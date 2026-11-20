"""
defender_agent.py  -  Person C  (EdgeShield) — dynamic response phase

Subscribes to SCORE_COMPUTED (Person B). Resolves attacker/victim IPs and dominant
attack_type from SQLite, applies proportional iptables tiers in the attacker
container (docker exec + OUTPUT/DNAT rules), honeypot DNAT on isolation,
false-positive guard, adaptive rollback, per-victim responses on multi-node chains,
and parallel chain handling.

Threads:
  1  EventBus listener (SCORE_COMPUTED)
  2  Rollback checker
  3  Polling fallback for missed scores

Each thread uses its own Redis EventBus connection.
"""

import json
import logging
import os
import re
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# Path setup for local Windows runs and Docker (/app)
_here = os.path.dirname(os.path.abspath(__file__))
for _p in (
    os.path.join(_here, "..", ".."),
    os.path.abspath("."),
    "/app",
):
    if _p and os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from shared.eventbus_client import EventBus
from shared import sqlite_util

try:
    from enforcer import (
        format_steps,
        get_container_stats,
        parse_steps,
        run_steps,
        socket_available,
    )
except ImportError:
    from src.enforcer import (
        format_steps,
        get_container_stats,
        parse_steps,
        run_steps,
        socket_available,
    )

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
SQLITE_PATH = os.environ.get("SQLITE_PATH", "/data/edgeshield.db")
HONEYPOT_IP = os.environ.get("HONEYPOT_IP", "172.28.0.200")
ATTACKER_CONTAINER = os.environ.get("ATTACKER_CONTAINER", "lab-traffic-source")
_RAW_ENFORCEMENT = os.environ.get("DEFENDER_ENFORCEMENT", "auto").strip().lower()


def _resolve_enforcement_mode() -> str:
    if _RAW_ENFORCEMENT == "auto":
        return "live" if socket_available() else "simulation"
    return _RAW_ENFORCEMENT


ENFORCEMENT_MODE = _resolve_enforcement_mode()

ROLLBACK_POLL_SEC = 30
TELEMETRY_POLL_SEC = 20
FALLBACK_POLL_SEC = 15
ROLLBACK_DELAY_SEC = 60
MAX_ROLLBACK_DELAY_SEC = 300
FP_MIN_ALERTS = 2
FP_MIN_GAP_SEC = 5.0
FALSE_ROLLBACK_WINDOW_SEC = 180
EXECUTOR_WORKERS = 20

ATTACK_SEVERITY = {
    "port_scan": 10,
    "brute_force": 20,
    "lateral_movement": 25,
    "ddos": 25,
    "arp_spoofing": 22,
    "dns_tunnelling": 18,
    "credential_stuff": 20,
    "http_flood": 22,
    "icmp_flood": 20,
}
DEFAULT_SEVERITY = 18

CRITICALITY_SCORE_DELTA = {
    "low": -5.0,
    "medium": 0.0,
    "high": 8.0,
    "critical": 15.0,
}
OFF_HOURS_DELTA = 3.0
HIGH_LOAD_CPU_DELTA = 5.0
HIGH_LOAD_CPU_THRESHOLD = 80.0

try:
    from shared.edge_devices import EDGE_DEVICES
except ImportError:
    EDGE_DEVICES = {
        "172.28.0.11": {"node_name": "edge-node-1", "criticality": "high", "device_class": "industrial_opc_gateway", "display_name": "Industrial OPC-UA Gateway", "description": "PLC gateway"},
        "172.28.0.12": {"node_name": "edge-node-2", "criticality": "medium", "device_class": "iot_sensor_hub", "display_name": "IoT Sensor Hub", "description": "IoT hub"},
        "172.28.0.13": {"node_name": "edge-node-3", "criticality": "critical", "device_class": "dns_utility_edge", "display_name": "DNS Utility Edge", "description": "DNS edge"},
    }

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("defender-agent")

TIERS = [
    {"min": 85, "max": 100, "action_type": "full_isolation", "label": "CRITICAL - full isolation"},
    {"min": 70, "max": 85, "action_type": "isolate_node", "label": "HIGH - node isolated"},
    {"min": 50, "max": 70, "action_type": "block_ip", "label": "MEDIUM-HIGH - source IP blocked"},
    {"min": 30, "max": 50, "action_type": "rate_limit", "label": "MEDIUM - rate limited"},
    {"min": 0, "max": 30, "action_type": "monitor", "label": "LOW - monitor only"},
]

_below_since: dict = {}
_active_tier_map: dict = {}
_rollback_delay_sec: dict = {}
_last_rollback_at: dict = {}
_state_lock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=EXECUTOR_WORKERS, thread_name_prefix="chain-eval")


def get_tier(score: float) -> dict:
    for tier in TIERS:
        if tier["min"] <= score <= tier["max"]:
            return tier
    return TIERS[-1]


def _conn() -> sqlite3.Connection:
    return sqlite_util.connect(SQLITE_PATH, check_same_thread=False)


EnforceStep = Tuple[str, str]


def _node_name_for_ip(ip: str) -> Optional[str]:
    try:
        conn = _conn()
        row = conn.execute(
            "SELECT device_name FROM device_registry WHERE ip_address = ?",
            (ip,),
        ).fetchone()
        conn.close()
        if row and row["device_name"]:
            return str(row["device_name"])
    except sqlite3.OperationalError:
        pass
    except Exception as exc:
        log.debug("[registry] device_name lookup failed for %s: %s", ip, exc)
    return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_device_registry():
    try:
        conn = _conn()
        for ip, meta in EDGE_DEVICES.items():
            name = meta["node_name"]
            crit = meta["criticality"]
            conn.execute(
                """INSERT OR IGNORE INTO device_registry
                   (ip_address, device_name, criticality, registered_at,
                    device_class, display_name, description)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    ip,
                    name,
                    crit,
                    _now(),
                    meta.get("device_class"),
                    meta.get("display_name"),
                    meta.get("description"),
                ),
            )
            conn.execute(
                """UPDATE device_registry
                   SET criticality=?, device_class=?, display_name=?, description=?
                   WHERE ip_address=?""",
                (crit, meta.get("device_class"), meta.get("display_name"), meta.get("description"), ip),
            )
            conn.execute(
                """INSERT OR IGNORE INTO node_health
                   (node_name, status, cpu_usage, memory_usage, last_updated)
                   VALUES (?, 'healthy', 0.0, 0.0, ?)""",
                (name, _now()),
            )
        conn.commit()
        conn.close()
        log.info("[startup] device_registry seeded (%d heterogeneous devices)", len(EDGE_DEVICES))
    except sqlite3.OperationalError:
        log.warning("[startup] device_registry table missing — extensions not applied?")
    except Exception as exc:
        log.warning("[startup] device_registry seed failed: %s", exc)


def _device_criticality(victim_ip: str) -> str:
    try:
        conn = _conn()
        row = conn.execute(
            "SELECT criticality FROM device_registry WHERE ip_address = ?",
            (victim_ip,),
        ).fetchone()
        conn.close()
        if row and row["criticality"]:
            return str(row["criticality"]).lower()
    except sqlite3.OperationalError:
        pass
    except Exception as exc:
        log.debug("[policy] device_registry lookup failed: %s", exc)
    return "medium"


def _node_cpu_load(victim_ip: str) -> float:
    try:
        conn = _conn()
        row = conn.execute(
            """SELECT nh.cpu_usage FROM node_health nh
               JOIN device_registry dr ON dr.device_name = nh.node_name
               WHERE dr.ip_address = ?""",
            (victim_ip,),
        ).fetchone()
        conn.close()
        if row and row["cpu_usage"] is not None:
            return float(row["cpu_usage"])
    except Exception:
        pass
    return 0.0


def _policy_score(chain_id: str, raw_score: float) -> float:
    """Dynamic threshold: device criticality, off-hours, and node load."""
    victims = _get_chain_victims(chain_id)
    if not victims:
        return raw_score

    crit_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    dst = max(
        victims.keys(),
        key=lambda ip: crit_order.get(_device_criticality(ip), 1),
    )

    delta = CRITICALITY_SCORE_DELTA.get(_device_criticality(dst), 0.0)
    hour = datetime.now(timezone.utc).hour
    if hour >= 22 or hour < 6:
        delta += OFF_HOURS_DELTA
    if _node_cpu_load(dst) >= HIGH_LOAD_CPU_THRESHOLD:
        delta += HIGH_LOAD_CPU_DELTA

    adjusted = min(100.0, max(0.0, raw_score + delta))
    if abs(adjusted - raw_score) >= 0.01:
        log.info(
            "[policy] chain=%s score %.1f -> %.1f (delta=%+.1f victim=%s)",
            chain_id,
            raw_score,
            adjusted,
            delta,
            dst,
        )
    return adjusted


def _dominant_attack_type(types: list) -> str:
    if not types:
        return "unknown"
    return max(types, key=lambda t: ATTACK_SEVERITY.get(t, DEFAULT_SEVERITY))


def _get_chain_victims(chain_id: str) -> Dict[str, str]:
    """Map victim IP -> dominant attack_type for alerts on that target."""
    victims: Dict[str, List[str]] = {}
    try:
        conn = _conn()
        chain = conn.execute(
            "SELECT alert_ids FROM attack_chains WHERE chain_id = ?",
            (chain_id,),
        ).fetchone()
        if not chain:
            conn.close()
            return {}
        alert_ids = json.loads(chain["alert_ids"])
        if not alert_ids:
            conn.close()
            return {}
        placeholders = ",".join("?" * len(alert_ids))
        rows = conn.execute(
            f"""SELECT source_ip, target_ip, attack_type FROM alerts
                WHERE id IN ({placeholders})""",
            [int(i) for i in alert_ids],
        ).fetchall()
        conn.close()
        for row in rows:
            dst = row["target_ip"]
            if not dst:
                continue
            victims.setdefault(dst, [])
            if row["attack_type"]:
                victims[dst].append(row["attack_type"])
        return {ip: _dominant_attack_type(types) for ip, types in victims.items()}
    except Exception as exc:
        log.warning("Could not derive victims for %s: %s", chain_id, exc)
        return {}


def _get_chain_context(chain_id: str) -> Tuple[str, str, str]:
    """Returns (source_ip attacker, primary target_ip, dominant attack_type overall)."""
    try:
        conn = _conn()
        chain = conn.execute(
            "SELECT alert_ids FROM attack_chains WHERE chain_id = ?",
            (chain_id,),
        ).fetchone()
        if not chain:
            conn.close()
            return "unknown", "unknown", "unknown"
        alert_ids = json.loads(chain["alert_ids"])
        if not alert_ids:
            conn.close()
            return "unknown", "unknown", "unknown"
        placeholders = ",".join("?" * len(alert_ids))
        rows = conn.execute(
            f"""SELECT source_ip, target_ip, attack_type FROM alerts
                WHERE id IN ({placeholders})""",
            [int(i) for i in alert_ids],
        ).fetchall()
        conn.close()
        if not rows:
            return "unknown", "unknown", "unknown"
        src_ips = {r["source_ip"] for r in rows if r["source_ip"]}
        src = next(iter(src_ips)) if len(src_ips) == 1 else (rows[0]["source_ip"] or "unknown")
        victims = _get_chain_victims(chain_id)
        if not victims:
            return src, "unknown", "unknown"
        dst = next(iter(victims.keys()))
        types = [r["attack_type"] for r in rows if r["attack_type"]]
        return src, dst, _dominant_attack_type(types)
    except Exception as exc:
        log.warning("Could not derive chain context for %s: %s", chain_id, exc)
        return "unknown", "unknown", "unknown"


def _is_corroborated(chain_id: str) -> bool:
    try:
        conn = _conn()
        chain = conn.execute(
            "SELECT alert_ids FROM attack_chains WHERE chain_id = ?",
            (chain_id,),
        ).fetchone()
        if not chain:
            conn.close()
            return False
        alert_ids = json.loads(chain["alert_ids"])
        if len(alert_ids) < FP_MIN_ALERTS:
            log.info(
                "[fp_guard] chain %s has %d alert(s) - need %d",
                chain_id,
                len(alert_ids),
                FP_MIN_ALERTS,
            )
            conn.close()
            return False
        placeholders = ",".join("?" * len(alert_ids))
        rows = conn.execute(
            f"SELECT timestamp FROM alerts WHERE id IN ({placeholders}) ORDER BY timestamp ASC",
            [int(i) for i in alert_ids],
        ).fetchall()
        conn.close()
        if len(rows) < FP_MIN_ALERTS:
            return False
        try:
            first = datetime.fromisoformat(rows[0]["timestamp"].replace("Z", "+00:00"))
            last = datetime.fromisoformat(rows[-1]["timestamp"].replace("Z", "+00:00"))
            gap = (last - first).total_seconds()
        except Exception:
            return True
        if gap < FP_MIN_GAP_SEC:
            log.info(
                "[fp_guard] chain %s: span=%.1fs < %.1fs - burst",
                chain_id,
                gap,
                FP_MIN_GAP_SEC,
            )
            return False
        log.info(
            "[fp_guard] chain %s corroborated: %d alerts over %.1fs",
            chain_id,
            len(rows),
            gap,
        )
        return True
    except Exception as exc:
        log.error("[fp_guard] error for chain %s: %s", chain_id, exc)
        return False


def _ns() -> str:
    return ATTACKER_CONTAINER


def _rate_limit_steps(attack_type: str, dst: str) -> Tuple[List[EnforceStep], List[EnforceStep]]:
    ns = _ns()
    drop = f"iptables -A OUTPUT -d {dst} -j DROP"
    if attack_type == "brute_force":
        accept = (
            f"iptables -I OUTPUT -d {dst} -p tcp --dport 22 "
            f"-m limit --limit 6/min --limit-burst 3 -j ACCEPT"
        )
        return [(ns, accept), (ns, drop)], [
            (ns, f"iptables -D OUTPUT -d {dst} -j DROP"),
            (ns, f"iptables -D OUTPUT -d {dst} -p tcp --dport 22 -m limit --limit 6/min --limit-burst 3 -j ACCEPT"),
        ]
    if attack_type in ("ddos", "http_flood", "icmp_flood"):
        accept = f"iptables -I OUTPUT -d {dst} -m limit --limit 30/sec --limit-burst 50 -j ACCEPT"
        return [(ns, accept), (ns, drop)], [
            (ns, f"iptables -D OUTPUT -d {dst} -j DROP"),
            (ns, f"iptables -D OUTPUT -d {dst} -m limit --limit 30/sec --limit-burst 50 -j ACCEPT"),
        ]
    if attack_type == "port_scan":
        accept = (
            f"iptables -I OUTPUT -d {dst} -p tcp --tcp-flags SYN,RST,ACK,FIN SYN "
            f"-m limit --limit 15/min --limit-burst 10 -j ACCEPT"
        )
        return [(ns, accept), (ns, drop)], [
            (ns, f"iptables -D OUTPUT -d {dst} -j DROP"),
            (ns, f"iptables -D OUTPUT -d {dst} -p tcp --tcp-flags SYN,RST,ACK,FIN SYN -m limit --limit 15/min --limit-burst 10 -j ACCEPT"),
        ]
    accept = f"iptables -I OUTPUT -d {dst} -m limit --limit 10/min --limit-burst 5 -j ACCEPT"
    return [(ns, accept), (ns, drop)], [
        (ns, f"iptables -D OUTPUT -d {dst} -j DROP"),
        (ns, f"iptables -D OUTPUT -d {dst} -m limit --limit 10/min --limit-burst 5 -j ACCEPT"),
    ]


def _block_ip_steps(attack_type: str, dst: str) -> Tuple[List[EnforceStep], List[EnforceStep]]:
    ns = _ns()
    if attack_type in ("ddos", "icmp_flood"):
        cmd = f"iptables -I OUTPUT -d {dst} -p icmp -j DROP"
    elif attack_type in ("brute_force", "credential_stuff"):
        cmd = f"iptables -I OUTPUT -d {dst} -p tcp --dport 22 -j DROP"
    elif attack_type == "http_flood":
        cmd = f"iptables -I OUTPUT -d {dst} -p tcp --dport 80 -j DROP"
    elif attack_type == "dns_tunnelling":
        cmd = f"iptables -I OUTPUT -d {dst} -p udp --dport 53 -j DROP"
    else:
        cmd = f"iptables -I OUTPUT -d {dst} -j DROP"
    rb = cmd.replace("-I", "-D", 1)
    return [(ns, cmd)], [(ns, rb)]


def _isolate_steps(dst: str) -> Tuple[List[EnforceStep], List[EnforceStep]]:
    ns = _ns()
    apply_cmd = f"iptables -t nat -A OUTPUT -d {dst} -j DNAT --to-destination {HONEYPOT_IP}"
    rb = f"iptables -t nat -D OUTPUT -d {dst} -j DNAT --to-destination {HONEYPOT_IP}"
    return [(ns, apply_cmd)], [(ns, rb)]


def _full_isolation_steps(dst: str) -> Tuple[List[EnforceStep], List[EnforceStep]]:
    ns = _ns()
    cmd = f"iptables -I OUTPUT -d {dst} -j DROP"
    return [(ns, cmd)], [(ns, cmd.replace("-I", "-D", 1))]


def _steps_for_tier(
    action_type: str, attack_type: str, src: str, dst: str
) -> Tuple[List[EnforceStep], List[EnforceStep]]:
    del src
    if action_type == "monitor":
        return [], []
    if action_type == "rate_limit":
        return _rate_limit_steps(attack_type, dst)
    if action_type == "block_ip":
        return _block_ip_steps(attack_type, dst)
    if action_type == "isolate_node":
        return _isolate_steps(dst)
    if action_type == "full_isolation":
        return _full_isolation_steps(dst)
    return [], []


def _enforce_steps(apply_steps: List[EnforceStep]) -> bool:
    if ENFORCEMENT_MODE == "live":
        ok = run_steps(apply_steps)
        if ok:
            log.info("[policy] LIVE enforcement applied (%d steps)", len(apply_steps))
        return ok
    log.info(
        "[policy] SIMULATED enforcement (%d steps) — set DEFENDER_ENFORCEMENT=live for iptables",
        len(apply_steps),
    )
    return True


def _live_rollback(rollback_cmd: Optional[str], label: str) -> bool:
    if not rollback_cmd:
        return True
    if ENFORCEMENT_MODE == "live":
        return run_steps(parse_steps(rollback_cmd))
    log.info("[rollback] SIMULATED %s", label)
    return True


def _write_response(
    chain_id, action_type, target, rollback_cmd, policy_reason: str = ""
) -> int:
    mode = "live" if ENFORCEMENT_MODE == "live" else "simulated"
    conn = _conn()
    cur = conn.execute(
        """INSERT INTO responses
           (chain_id, timestamp, action_type, target, rollback_command, status,
            enforcement_mode, policy_reason)
           VALUES (?, ?, ?, ?, ?, 'active', ?, ?)""",
        (chain_id, _now(), action_type, target, rollback_cmd, mode, policy_reason),
    )
    rowid = cur.lastrowid
    conn.commit()
    conn.close()
    return rowid


def _mark_rolled_back(response_id: int):
    conn = _conn()
    conn.execute(
        "UPDATE responses SET status='rolled_back', rolled_back_at=? WHERE id=?",
        (_now(), response_id),
    )
    conn.commit()
    conn.close()


def _get_active_response(chain_id: str):
    conn = _conn()
    row = conn.execute(
        """SELECT id, action_type, target, rollback_command
             FROM responses WHERE chain_id=? AND status='active'
             ORDER BY timestamp DESC LIMIT 1""",
        (chain_id,),
    ).fetchone()
    conn.close()
    return row


def _rollback_active_for_chain(chain_id: str):
    """Remove prior tier rules before escalating to a new tier on the same chain."""
    conn = _conn()
    rows = conn.execute(
        """SELECT id, rollback_command FROM responses
             WHERE chain_id=? AND status='active'""",
        (chain_id,),
    ).fetchall()
    conn.close()
    for row in rows:
        _live_rollback(row["rollback_command"], f"pre-escalation id={row['id']}")
        _mark_rolled_back(row["id"])


def _get_latest_score(chain_id: str):
    conn = _conn()
    row = conn.execute(
        "SELECT score FROM threat_scores WHERE chain_id=? ORDER BY timestamp DESC LIMIT 1",
        (chain_id,),
    ).fetchone()
    conn.close()
    return float(row["score"]) if row else None


def _update_node_health(victim_ip: str, status: str):
    """Update node_health using device_registry name (never attacker IP)."""
    node_name = _node_name_for_ip(victim_ip)
    if not node_name:
        log.debug("[node_health] skip unregistered IP %s", victim_ip)
        return
    try:
        conn = _conn()
        conn.execute(
            """INSERT INTO node_health (node_name, status, cpu_usage, memory_usage, last_updated)
               VALUES (?, ?, 0.0, 0.0, ?)
               ON CONFLICT(node_name) DO UPDATE
               SET status=excluded.status,
                   last_updated=excluded.last_updated""",
            (node_name, status, _now()),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        log.warning("[node_health] update failed: %s", exc)


def _cpu_percent_from_stats(stats: dict) -> float:
    try:
        cpu_stats = stats.get("cpu_stats") or {}
        precpu = stats.get("precpu_stats") or {}
        usage_delta = (
            cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
            - precpu.get("cpu_usage", {}).get("total_usage", 0)
        )
        system_delta = (
            cpu_stats.get("system_cpu_usage", 0) - precpu.get("system_cpu_usage", 0)
        )
        if system_delta <= 0:
            return 0.0
        online = cpu_stats.get("online_cpus") or 1
        return min(100.0, (usage_delta / system_delta) * online * 100.0)
    except Exception:
        return 0.0


def _memory_percent_from_stats(stats: dict) -> float:
    try:
        mem = stats.get("memory_stats") or {}
        usage = float(mem.get("usage", 0))
        limit = float(mem.get("limit") or 1)
        return min(100.0, (usage / limit) * 100.0)
    except Exception:
        return 0.0


def _publish_edge_telemetry():
    """Poll Docker stats for edge-node containers → node_health (Person C)."""
    if not socket_available():
        return
    try:
        conn = _conn()
        for meta in EDGE_DEVICES.values():
            node_name = meta["node_name"]
            stats = get_container_stats(node_name)
            if not stats:
                continue
            cpu = _cpu_percent_from_stats(stats)
            mem = _memory_percent_from_stats(stats)
            row = conn.execute(
                "SELECT status FROM node_health WHERE node_name=?",
                (node_name,),
            ).fetchone()
            status = row["status"] if row else "healthy"
            conn.execute(
                """INSERT INTO node_health (node_name, status, cpu_usage, memory_usage, last_updated)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(node_name) DO UPDATE SET
                       cpu_usage=excluded.cpu_usage,
                       memory_usage=excluded.memory_usage,
                       last_updated=excluded.last_updated""",
                (node_name, status, cpu, mem, _now()),
            )
        conn.commit()
        conn.close()
    except Exception as exc:
        log.debug("[telemetry] edge stats update failed: %s", exc)


def _finalize_rollback(
    resp: dict,
    bus: EventBus,
    reason: str,
    latest_score: Optional[float] = None,
):
    chain_id = resp["chain_id"]
    response_id = resp["id"]
    action_type = resp["action_type"]
    target = resp["target"]
    rollback_cmd = resp["rollback_command"]

    _live_rollback(rollback_cmd, f"rollback id={response_id} reason={reason}")
    _mark_rolled_back(response_id)
    _log_optional_rollback_history(chain_id, response_id, reason)
    victim_ip = _victim_ip_from_rollback(rollback_cmd)
    if victim_ip:
        _update_node_health(victim_ip, "healthy")
    elif action_type in ("isolate_node", "full_isolation") and target:
        _update_node_health(target, "healthy")
    now = datetime.now(timezone.utc)
    with _state_lock:
        active_left = False
        try:
            conn = _conn()
            left = conn.execute(
                "SELECT COUNT(*) AS c FROM responses WHERE chain_id=? AND status='active'",
                (chain_id,),
            ).fetchone()
            conn.close()
            active_left = bool(left and left["c"] > 0)
        except Exception:
            active_left = False
        if not active_left:
            _active_tier_map.pop(chain_id, None)
            _below_since.pop(chain_id, None)
            _last_rollback_at[chain_id] = now
    bus.publish(
        EventBus.RESPONSE_EXECUTED,
        {
            "response_id": response_id,
            "chain_id": chain_id,
            "action_type": "rollback",
            "target": target,
            "score": latest_score,
            "severity": f"rollback - {reason}",
            "enforcement_mode": "live" if ENFORCEMENT_MODE == "live" else "simulated",
            "timestamp": _now(),
        },
    )


def _log_optional_honeypot(chain_id: str, src: str):
    try:
        conn = _conn()
        conn.execute(
            """INSERT INTO honeypot_sessions (chain_id, attacker_ip, honeypot_ip, started_at)
               VALUES (?, ?, ?, ?)""",
            (chain_id, src, HONEYPOT_IP, _now()),
        )
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        pass
    except Exception as exc:
        log.debug("[honeypot] session log skipped: %s", exc)


def _log_optional_rollback_history(chain_id: str, response_id: int, reason: str):
    try:
        conn = _conn()
        conn.execute(
            """INSERT INTO rollback_history (chain_id, response_id, reason, timestamp)
               VALUES (?, ?, ?, ?)""",
            (chain_id, response_id, reason, _now()),
        )
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        pass
    except Exception as exc:
        log.debug("[rollback_history] log skipped: %s", exc)


def _rollback_delay_for(chain_id: str) -> float:
    with _state_lock:
        return _rollback_delay_sec.get(chain_id, ROLLBACK_DELAY_SEC)


def _victim_ip_from_rollback(rollback_cmd: Optional[str]) -> Optional[str]:
    if not rollback_cmd:
        return None
    for _ns, cmd in parse_steps(rollback_cmd):
        match = re.search(r"-d\s+(\d{1,3}(?:\.\d{1,3}){3})", cmd)
        if match:
            return match.group(1)
    match = re.search(r"-d\s+(\d{1,3}(?:\.\d{1,3}){3})", rollback_cmd)
    return match.group(1) if match else None


def _note_false_rollback(chain_id: str):
    with _state_lock:
        current = _rollback_delay_sec.get(chain_id, ROLLBACK_DELAY_SEC)
        new_delay = min(current * 2, MAX_ROLLBACK_DELAY_SEC)
        _rollback_delay_sec[chain_id] = new_delay
        log.warning(
            "[rollback] false rollback detected chain=%s — delay now %.0fs",
            chain_id,
            new_delay,
        )


def _apply_response(chain_id: str, score: float, bus: EventBus):
    score = _policy_score(chain_id, score)
    tier = get_tier(score)

    if tier["action_type"] == "monitor":
        log.info("[policy] chain=%s score=%.1f -> MONITOR only", chain_id, score)
        return

    if not _is_corroborated(chain_id):
        log.warning(
            "[policy] FP guard BLOCKED chain=%s tier=%s",
            chain_id,
            tier["action_type"],
        )
        return

    with _state_lock:
        current = _active_tier_map.get(chain_id)
        last_rb = _last_rollback_at.get(chain_id)
    if last_rb is not None:
        elapsed = (datetime.now(timezone.utc) - last_rb).total_seconds()
        if elapsed <= FALSE_ROLLBACK_WINDOW_SEC and current is None:
            _note_false_rollback(chain_id)

    if current == tier["action_type"]:
        log.info("[policy] chain=%s already at tier=%s - skip", chain_id, tier["action_type"])
        return

    if current is not None and current != tier["action_type"]:
        log.info(
            "[policy] chain=%s escalating %s -> %s — rolling back prior rules",
            chain_id,
            current,
            tier["action_type"],
        )
        _rollback_active_for_chain(chain_id)

    victims = _get_chain_victims(chain_id)
    src, _, _ = _get_chain_context(chain_id)
    if src == "unknown" or not victims:
        log.warning("[policy] cannot derive src/victims for chain=%s - skip", chain_id)
        return

    applied_any = False
    for dst, attack_type in victims.items():
        apply_steps, rollback_steps = _steps_for_tier(
            tier["action_type"], attack_type, src, dst
        )
        display_target = dst if tier["action_type"] in ("isolate_node", "full_isolation") else src
        rollback_stored = format_steps(rollback_steps)
        reason = f"score={score:.1f} tier={tier['action_type']} attack={attack_type}"

        response_id = _write_response(
            chain_id,
            tier["action_type"],
            display_target,
            rollback_stored,
            policy_reason=reason,
        )
        success = _enforce_steps(apply_steps) if apply_steps else True

        if success:
            applied_any = True
            log.info(
                "[policy] APPLIED chain=%s score=%.1f tier=%s attack=%s src=%s dst=%s id=%d",
                chain_id,
                score,
                tier["action_type"],
                attack_type,
                src,
                dst,
                response_id,
            )
            if tier["action_type"] == "isolate_node":
                _log_optional_honeypot(chain_id, src)
            _update_node_health(dst, tier["action_type"])
            bus.publish(
                EventBus.RESPONSE_EXECUTED,
                {
                    "response_id": response_id,
                    "chain_id": chain_id,
                    "action_type": tier["action_type"],
                    "target": display_target,
                    "victim_ip": dst,
                    "source_ip": src,
                    "attack_type": attack_type,
                    "score": score,
                    "severity": tier["label"],
                    "enforcement_mode": (
                        "live" if ENFORCEMENT_MODE == "live" else "simulated"
                    ),
                    "timestamp": _now(),
                },
            )
        else:
            log.error(
                "[policy] command FAILED chain=%s tier=%s dst=%s",
                chain_id,
                tier["action_type"],
                dst,
            )

    if applied_any:
        with _state_lock:
            _active_tier_map[chain_id] = tier["action_type"]
            _below_since.pop(chain_id, None)


def _listener_thread(bus: EventBus):
    log.info("[thread-1] EventBus listener started")
    for event_type, payload in bus.listen():
        if event_type != EventBus.SCORE_COMPUTED:
            continue
        try:
            chain_id = payload.get("chain_id")
            score = float(payload.get("score", 0))
            if not chain_id:
                continue
            log.info("[thread-1] SCORE_COMPUTED chain=%s score=%.1f", chain_id, score)
            _executor.submit(_apply_response, chain_id, score, bus)
        except Exception as exc:
            log.error("[thread-1] error: %s", exc)


def _rollback_thread(bus: EventBus):
    log.info("[thread-2] Rollback checker started - interval=%ds", ROLLBACK_POLL_SEC)
    while True:
        try:
            conn = _conn()
            resolved_active = conn.execute(
                """SELECT r.id, r.chain_id, r.action_type, r.target, r.rollback_command
                     FROM responses r
                     JOIN attack_chains ac ON ac.chain_id = r.chain_id
                    WHERE r.status='active' AND ac.status='resolved'"""
            ).fetchall()
            active = conn.execute(
                """SELECT id, chain_id, action_type, target, rollback_command
                     FROM responses WHERE status='active'"""
            ).fetchall()
            conn.close()

            for resp in resolved_active:
                log.info(
                    "[thread-2] chain=%s resolved — rolling back response id=%s",
                    resp["chain_id"],
                    resp["id"],
                )
                _finalize_rollback(dict(resp), bus, "chain_resolved_attack_stopped")

            for resp in active:
                if any(resp["id"] == r["id"] for r in resolved_active):
                    continue
                chain_id = resp["chain_id"]
                response_id = resp["id"]
                action_type = resp["action_type"]
                target = resp["target"]
                rollback_cmd = resp["rollback_command"]

                raw_score = _get_latest_score(chain_id)
                if raw_score is None:
                    continue
                latest_score = _policy_score(chain_id, raw_score)

                tier_min = next(
                    (t["min"] for t in TIERS if t["action_type"] == action_type), 0
                )
                now = datetime.now(timezone.utc)
                delay_needed = _rollback_delay_for(chain_id)

                if latest_score < tier_min:
                    with _state_lock:
                        if chain_id not in _below_since:
                            _below_since[chain_id] = now
                            log.info(
                                "[thread-2] chain=%s score=%.1f below tier_min=%d - timer started (delay=%.0fs)",
                                chain_id,
                                latest_score,
                                tier_min,
                                delay_needed,
                            )
                        elapsed = (now - _below_since[chain_id]).total_seconds()

                    if elapsed >= delay_needed:
                        log.info(
                            "[thread-2] ROLLBACK chain=%s elapsed=%.0fs action=%s target=%s",
                            chain_id,
                            elapsed,
                            action_type,
                            target,
                        )
                        _finalize_rollback(
                            dict(resp),
                            bus,
                            "score_below_tier",
                            latest_score=latest_score,
                        )
                else:
                    with _state_lock:
                        if chain_id in _below_since:
                            log.info(
                                "[thread-2] chain=%s score recovered to %.1f - reset timer",
                                chain_id,
                                latest_score,
                            )
                            _below_since.pop(chain_id, None)

        except Exception as exc:
            log.error("[thread-2] error: %s", exc)
        time.sleep(ROLLBACK_POLL_SEC)


def _fallback_thread(bus: EventBus):
    log.info("[thread-3] Polling fallback started - interval=%ds", FALLBACK_POLL_SEC)
    while True:
        try:
            conn = _conn()
            rows = conn.execute(
                """SELECT ac.chain_id, ts.score
                     FROM attack_chains ac
                     JOIN threat_scores ts ON ts.chain_id = ac.chain_id
                    WHERE ac.status = 'active'
                    GROUP BY ac.chain_id
                    HAVING ts.id = MAX(ts.id)"""
            ).fetchall()
            conn.close()

            for row in rows:
                chain_id = row["chain_id"]
                score = _policy_score(chain_id, float(row["score"]))
                existing = _get_active_response(chain_id)
                if existing:
                    continue
                with _state_lock:
                    current = _active_tier_map.get(chain_id)
                tier = get_tier(score)
                if current == tier["action_type"]:
                    continue
                log.info("[thread-3] fallback triggered chain=%s score=%.1f", chain_id, score)
                _executor.submit(_apply_response, chain_id, score, bus)

        except Exception as exc:
            log.error("[thread-3] error: %s", exc)
        time.sleep(FALLBACK_POLL_SEC)


def _telemetry_thread():
    log.info(
        "[thread-4] Edge telemetry started - interval=%ds (docker stats → node_health)",
        TELEMETRY_POLL_SEC,
    )
    while True:
        try:
            _publish_edge_telemetry()
        except Exception as exc:
            log.error("[thread-4] error: %s", exc)
        time.sleep(TELEMETRY_POLL_SEC)


def _wait_for_redis() -> EventBus:
    import redis as rlib

    for attempt in range(1, 31):
        try:
            r = rlib.Redis(host=REDIS_HOST, port=REDIS_PORT)
            r.ping()
            r.close()
            log.info("[startup] Redis ready at %s:%d", REDIS_HOST, REDIS_PORT)
            return EventBus(host=REDIS_HOST, port=REDIS_PORT)
        except Exception as exc:
            log.warning("[startup] Redis not ready (%d/30): %s", attempt, exc)
            time.sleep(3)
    log.critical("[startup] Redis unavailable - exiting")
    sys.exit(1)


def _wait_for_sqlite():
    import pathlib

    for attempt in range(1, 16):
        try:
            pathlib.Path(SQLITE_PATH).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(SQLITE_PATH, timeout=5)
            conn.execute("SELECT 1")
            conn.close()
            log.info("[startup] SQLite ready at %s", SQLITE_PATH)
            return
        except Exception as exc:
            log.warning("[startup] SQLite not ready (%d/15): %s", attempt, exc)
            time.sleep(2)
    log.critical("[startup] SQLite unavailable - exiting")
    sys.exit(1)


def _init_schema():
    scripts = []
    for path in (
        os.path.join(_here, "..", "..", "shared", "schema.sql"),
        "/app/shared/schema.sql",
        "shared/schema.sql",
    ):
        if os.path.exists(path) and path not in scripts:
            scripts.append(path)
    for path in (
        os.path.join(_here, "..", "schema_extensions.sql"),
        "/app/schema_extensions.sql",
    ):
        if os.path.exists(path) and path not in scripts:
            scripts.append(path)

    if not scripts:
        log.warning("[startup] no schema scripts found - tables may already exist")
        return

    conn = _conn()
    for path in scripts:
        with open(path, encoding="utf-8") as f:
            conn.executescript(f.read())
        log.info("[startup] Schema applied: %s", path)
    conn.commit()
    conn.close()
    _seed_device_registry()


def main():
    log.info("=" * 55)
    log.info("EdgeShield Defender Agent  (Person C) — dynamic")
    log.info("  REDIS_HOST   = %s:%s", REDIS_HOST, REDIS_PORT)
    log.info("  SQLITE_PATH  = %s", SQLITE_PATH)
    log.info("  HONEYPOT_IP  = %s", HONEYPOT_IP)
    log.info("  WORKERS      = %d", EXECUTOR_WORKERS)
    log.info("  ENFORCEMENT  = %s (requested=%s)", ENFORCEMENT_MODE, _RAW_ENFORCEMENT)
    log.info("=" * 55)

    _wait_for_sqlite()
    _init_schema()
    if socket_available():
        log.info(
            "[startup] Enforcing iptables in container %s via Docker socket / enforcer",
            ATTACKER_CONTAINER,
        )
    else:
        log.warning(
            "[startup] Docker socket unavailable — rules will run in defender namespace only"
        )
    _publish_edge_telemetry()
    bus = _wait_for_redis()

    bus.subscribe([EventBus.SCORE_COMPUTED])

    bus2 = EventBus(host=REDIS_HOST, port=REDIS_PORT)
    bus3 = EventBus(host=REDIS_HOST, port=REDIS_PORT)

    t1 = threading.Thread(
        target=_listener_thread, args=(bus,), daemon=True, name="eventbus-listener"
    )
    t2 = threading.Thread(
        target=_rollback_thread, args=(bus2,), daemon=True, name="rollback-checker"
    )
    t3 = threading.Thread(
        target=_fallback_thread, args=(bus3,), daemon=True, name="polling-fallback"
    )
    t4 = threading.Thread(
        target=_telemetry_thread, daemon=True, name="edge-telemetry"
    )

    t1.start()
    t2.start()
    t3.start()
    t4.start()

    log.info("[startup] Defender threads running (listener, rollback, fallback, telemetry)")

    while True:
        time.sleep(60)
        with _state_lock:
            log.info(
                "[heartbeat] active_tiers=%s delays=%s",
                list(_active_tier_map.keys()),
                {k: _rollback_delay_sec.get(k, ROLLBACK_DELAY_SEC) for k in _active_tier_map},
            )


if __name__ == "__main__":
    main()
