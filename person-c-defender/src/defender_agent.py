"""
defender_agent.py  -  Person C  (EdgeShield) — dynamic response phase

Subscribes to SCORE_COMPUTED (Person B). Resolves attacker/victim IPs and dominant
attack_type from SQLite, applies proportional iptables tiers, honeypot DNAT on
isolation, false-positive guard, adaptive rollback, and parallel chain handling.

Threads:
  1  EventBus listener (SCORE_COMPUTED)
  2  Rollback checker
  3  Polling fallback for missed scores

Each thread uses its own Redis EventBus connection.
"""

import json
import logging
import os
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import List, Optional, Tuple

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

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
SQLITE_PATH = os.environ.get("SQLITE_PATH", "/data/edgeshield.db")
HONEYPOT_IP = os.environ.get("HONEYPOT_IP", "172.28.0.200")
ATTACKER_CONTAINER = os.environ.get("ATTACKER_CONTAINER", "attacker")
DEFENDER_ENFORCEMENT = os.environ.get("DEFENDER_ENFORCEMENT", "simulation").strip().lower()

ROLLBACK_POLL_SEC = 30
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

DEFAULT_DEVICES = (
    ("172.28.0.11", "edge-node-1", "high"),
    ("172.28.0.12", "edge-node-2", "medium"),
    ("172.28.0.13", "edge-node-3", "critical"),
)

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
    c = sqlite3.connect(SQLITE_PATH, timeout=10, check_same_thread=False)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=10000")
    except sqlite3.Error:
        pass
    return c


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _enable_ip_forward():
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as exc:
        log.debug("[net] ip_forward not set: %s", exc)


def _seed_device_registry():
    try:
        conn = _conn()
        for ip, name, crit in DEFAULT_DEVICES:
            conn.execute(
                """INSERT OR IGNORE INTO device_registry
                   (ip_address, device_name, criticality, registered_at)
                   VALUES (?, ?, ?, ?)""",
                (ip, name, crit, _now()),
            )
        conn.commit()
        conn.close()
        log.info("[startup] device_registry seeded (%d devices)", len(DEFAULT_DEVICES))
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


def _policy_score_for_victim(raw_score: float, victim_ip: str) -> float:
    if victim_ip == "unknown":
        return raw_score
    delta = CRITICALITY_SCORE_DELTA.get(_device_criticality(victim_ip), 0.0)
    hour = datetime.now(timezone.utc).hour
    if hour >= 22 or hour < 6:
        delta += OFF_HOURS_DELTA
    if _node_cpu_load(victim_ip) >= HIGH_LOAD_CPU_THRESHOLD:
        delta += HIGH_LOAD_CPU_DELTA
    return min(100.0, max(0.0, raw_score + delta))


def _policy_score(chain_id: str, raw_score: float) -> float:
    """Dynamic threshold: worst-case adjustment across all victims on the chain."""
    _, victims, _ = _get_chain_victims(chain_id)
    if not victims:
        return raw_score
    adjusted = max(_policy_score_for_victim(raw_score, vip) for vip, _ in victims)
    if abs(adjusted - raw_score) >= 0.01:
        log.info(
            "[policy] chain=%s score %.1f -> %.1f (multi-victim policy)",
            chain_id,
            raw_score,
            adjusted,
        )
    return adjusted


def _dominant_attack_type(types: list) -> str:
    if not types:
        return "unknown"
    return max(types, key=lambda t: ATTACK_SEVERITY.get(t, DEFAULT_SEVERITY))


def _victim_node_name(victim_ip: str, target_node: Optional[str] = None) -> str:
    if target_node:
        return target_node
    try:
        conn = _conn()
        row = conn.execute(
            "SELECT device_name FROM device_registry WHERE ip_address = ?",
            (victim_ip,),
        ).fetchone()
        conn.close()
        if row and row["device_name"]:
            return str(row["device_name"])
    except Exception:
        pass
    return victim_ip


def _get_chain_context(chain_id: str) -> Tuple[str, str, str]:
    """Returns (source_ip attacker, primary target_ip victim, dominant attack_type)."""
    src, victims, attack_type = _get_chain_victims(chain_id)
    if not victims:
        return "unknown", "unknown", attack_type
    return src, victims[0][0], attack_type


def _get_chain_victims(chain_id: str) -> Tuple[str, List[Tuple[str, str]], str]:
    """Returns (attacker_ip, [(victim_ip, target_node), ...], dominant attack_type)."""
    try:
        conn = _conn()
        chain = conn.execute(
            "SELECT alert_ids FROM attack_chains WHERE chain_id = ?",
            (chain_id,),
        ).fetchone()
        if not chain:
            conn.close()
            return "unknown", [], "unknown"
        alert_ids = json.loads(chain["alert_ids"])
        if not alert_ids:
            conn.close()
            return "unknown", [], "unknown"
        placeholders = ",".join("?" * len(alert_ids))
        rows = conn.execute(
            f"""SELECT source_ip, target_ip, target_node, attack_type FROM alerts
                WHERE id IN ({placeholders})""",
            [int(i) for i in alert_ids],
        ).fetchall()
        conn.close()
        if not rows:
            return "unknown", [], "unknown"
        src = rows[0]["source_ip"] or "unknown"
        types = [r["attack_type"] for r in rows if r["attack_type"]]
        seen: set = set()
        victims: List[Tuple[str, str]] = []
        for row in rows:
            vip = row["target_ip"] or "unknown"
            if vip == "unknown" or vip in seen:
                continue
            seen.add(vip)
            node = row["target_node"] or _victim_node_name(vip)
            victims.append((vip, node))
        return src, victims, _dominant_attack_type(types)
    except Exception as exc:
        log.warning("Could not derive chain context for %s: %s", chain_id, exc)
        return "unknown", [], "unknown"


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


def _rate_limit_cmd(attack_type: str, src: str) -> Tuple[str, str]:
    base_drop = f"iptables -A INPUT -s {src} -j DROP"
    if attack_type == "brute_force":
        accept = (
            f"iptables -I INPUT -s {src} -p tcp --dport 22 "
            f"-m limit --limit 6/min --limit-burst 3 -j ACCEPT"
        )
        rollback = (
            f"iptables -D INPUT -s {src} -p tcp --dport 22 "
            f"-m limit --limit 6/min --limit-burst 3 -j ACCEPT ; "
            f"iptables -D INPUT -s {src} -j DROP"
        )
        return f"{accept} && {base_drop}", rollback
    if attack_type in ("ddos", "http_flood", "icmp_flood"):
        accept = (
            f"iptables -I INPUT -s {src} -m limit --limit 30/sec --limit-burst 50 -j ACCEPT"
        )
        rollback = (
            f"iptables -D INPUT -s {src} -m limit --limit 30/sec --limit-burst 50 -j ACCEPT ; "
            f"iptables -D INPUT -s {src} -j DROP"
        )
        return f"{accept} && {base_drop}", rollback
    if attack_type == "port_scan":
        accept = (
            f"iptables -I INPUT -s {src} -p tcp --tcp-flags SYN,RST,ACK,FIN SYN "
            f"-m limit --limit 15/min --limit-burst 10 -j ACCEPT"
        )
        rollback = (
            f"iptables -D INPUT -s {src} -p tcp --tcp-flags SYN,RST,ACK,FIN SYN "
            f"-m limit --limit 15/min --limit-burst 10 -j ACCEPT ; "
            f"iptables -D INPUT -s {src} -j DROP"
        )
        return f"{accept} && {base_drop}", rollback
    accept = (
        f"iptables -I INPUT -s {src} -m limit --limit 10/min --limit-burst 5 -j ACCEPT"
    )
    rollback = (
        f"iptables -D INPUT -s {src} -m limit --limit 10/min --limit-burst 5 -j ACCEPT ; "
        f"iptables -D INPUT -s {src} -j DROP"
    )
    return f"{accept} && {base_drop}", rollback


def _block_ip_cmd(attack_type: str, src: str) -> Tuple[str, str]:
    if attack_type in ("ddos", "icmp_flood"):
        cmd = f"iptables -I INPUT -s {src} -p icmp -j DROP"
        rb = f"iptables -D INPUT -s {src} -p icmp -j DROP"
    elif attack_type in ("brute_force", "credential_stuff"):
        cmd = f"iptables -I INPUT -s {src} -p tcp --dport 22 -j DROP"
        rb = f"iptables -D INPUT -s {src} -p tcp --dport 22 -j DROP"
    elif attack_type == "http_flood":
        cmd = f"iptables -I INPUT -s {src} -p tcp --dport 80 -j DROP"
        rb = f"iptables -D INPUT -s {src} -p tcp --dport 80 -j DROP"
    elif attack_type == "dns_tunnelling":
        cmd = f"iptables -I INPUT -s {src} -p udp --dport 53 -j DROP"
        rb = f"iptables -D INPUT -s {src} -p udp --dport 53 -j DROP"
    else:
        cmd = f"iptables -I INPUT -s {src} -j DROP"
        rb = f"iptables -D INPUT -s {src} -j DROP"
    return cmd, rb


def _isolate_cmd(src: str, dst: str) -> Tuple[str, str]:
    apply_cmds = (
        f"iptables -t nat -I PREROUTING -s {src} -d {dst} "
        f"-j DNAT --to-destination {HONEYPOT_IP} && "
        f"iptables -I FORWARD -s {src} -d {dst} -j DROP"
    )
    rollback = (
        f"iptables -t nat -D PREROUTING -s {src} -d {dst} "
        f"-j DNAT --to-destination {HONEYPOT_IP} ; "
        f"iptables -D FORWARD -s {src} -d {dst} -j DROP"
    )
    return apply_cmds, rollback


def _full_isolation_cmd(src: str, dst: str) -> Tuple[str, str]:
    apply_cmds = (
        f"iptables -I INPUT -s {src} -j DROP && "
        f"iptables -I FORWARD -d {dst} -j DROP"
    )
    rollback = (
        f"iptables -D INPUT -s {src} -j DROP ; "
        f"iptables -D FORWARD -d {dst} -j DROP"
    )
    return apply_cmds, rollback


def _commands_for_tier(
    action_type: str, attack_type: str, src: str, dst: str
) -> Tuple[Optional[str], Optional[str]]:
    if action_type == "monitor":
        return None, None
    if action_type == "rate_limit":
        return _rate_limit_cmd(attack_type, src)
    if action_type == "block_ip":
        return _block_ip_cmd(attack_type, src)
    if action_type == "isolate_node":
        return _isolate_cmd(src, dst)
    if action_type == "full_isolation":
        return _full_isolation_cmd(src, dst)
    return None, None


def _live_iptables_cmd(cmd: str) -> str:
    """Apply rules in the lab attacker namespace (OUTPUT toward victims), not defender INPUT."""
    parts = []
    for segment in cmd.split(" ; "):
        segment = segment.strip()
        if not segment:
            continue
        segment = (
            segment.replace("iptables -A INPUT", "iptables -A OUTPUT")
            .replace("iptables -I INPUT", "iptables -I OUTPUT")
            .replace("iptables -D INPUT", "iptables -D OUTPUT")
            .replace("-s ", "-d ", 1)
            if " INPUT " in f" {segment} " or segment.startswith("iptables -")
            and "INPUT" in segment
            else segment
        )
        if "PREROUTING" in segment:
            segment = segment.replace("PREROUTING", "OUTPUT")
        if "FORWARD" in segment:
            segment = segment.replace("FORWARD", "OUTPUT")
        parts.append(segment)
    inner = " ; ".join(parts)
    escaped = inner.replace("'", "'\"'\"'")
    return f"docker exec {ATTACKER_CONTAINER} sh -c '{escaped}'"


def _run_shell(cmd: str) -> bool:
    if not cmd:
        return True
    if DEFENDER_ENFORCEMENT == "simulation":
        log.info("[iptables] SIMULATED: %s", cmd)
        return True
    run_cmd = _live_iptables_cmd(cmd) if DEFENDER_ENFORCEMENT == "live" else cmd
    log.info("[iptables] RUN (%s): %s", DEFENDER_ENFORCEMENT, run_cmd)
    try:
        result = subprocess.run(
            run_cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            log.warning(
                "[iptables] exit=%d stderr=%s",
                result.returncode,
                (result.stderr or "").strip(),
            )
            return DEFENDER_ENFORCEMENT != "live"
        return True
    except subprocess.TimeoutExpired:
        log.error("[iptables] TIMEOUT: %s", run_cmd)
        return False
    except Exception as exc:
        log.error("[iptables] ERROR: %s - %s", run_cmd, exc)
        return False


def _write_response(chain_id, action_type, target, rollback_cmd) -> int:
    conn = _conn()
    cur = conn.execute(
        """INSERT INTO responses
           (chain_id, timestamp, action_type, target, rollback_command, status)
           VALUES (?, ?, ?, ?, ?, 'active')""",
        (chain_id, _now(), action_type, target, rollback_cmd),
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


def _get_latest_score(chain_id: str):
    conn = _conn()
    row = conn.execute(
        "SELECT score FROM threat_scores WHERE chain_id=? ORDER BY timestamp DESC LIMIT 1",
        (chain_id,),
    ).fetchone()
    conn.close()
    return float(row["score"]) if row else None


def _update_node_health(node_name: str, status: str):
    try:
        conn = _conn()
        conn.execute(
            """INSERT INTO node_health (node_name, status, last_updated)
               VALUES (?, ?, ?)
               ON CONFLICT(node_name) DO UPDATE
               SET status=excluded.status,
                   last_updated=excluded.last_updated""",
            (node_name, status, _now()),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        log.warning("[node_health] update failed: %s", exc)


def _node_name_from_target(target: str) -> str:
    if not target or target == "unknown":
        return target
    if target.count(".") == 3 and target.replace(".", "").isdigit():
        return _victim_node_name(target)
    return target


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

    src, victims, attack_type = _get_chain_victims(chain_id)
    if src == "unknown" or not victims:
        log.warning("[policy] cannot derive src/victims for chain=%s - skip", chain_id)
        return

    # One enforcement action per distinct victim IP (Person B multi-victim chains).
    applied_any = False
    for dst, node_name in victims:
        command, rollback_cmd = _commands_for_tier(
            tier["action_type"], attack_type, src, dst
        )
        display_target = dst if tier["action_type"] in ("isolate_node", "full_isolation") else src

        response_id = _write_response(
            chain_id, tier["action_type"], display_target, rollback_cmd
        )
        success = _run_shell(command) if command else True

        if not success:
            log.error(
                "[policy] command FAILED chain=%s tier=%s victim=%s",
                chain_id,
                tier["action_type"],
                dst,
            )
            continue

        applied_any = True
        log.info(
            "[policy] APPLIED chain=%s score=%.1f tier=%s attack=%s src=%s dst=%s node=%s id=%d",
            chain_id,
            score,
            tier["action_type"],
            attack_type,
            src,
            dst,
            node_name,
            response_id,
        )
        if tier["action_type"] == "isolate_node":
            _log_optional_honeypot(chain_id, src)
        _update_node_health(node_name, tier["action_type"])
        bus.publish(
            EventBus.RESPONSE_EXECUTED,
            {
                "response_id": response_id,
                "chain_id": chain_id,
                "action_type": tier["action_type"],
                "target": display_target,
                "source_ip": src,
                "attack_type": attack_type,
                "score": score,
                "severity": tier["label"],
                "timestamp": _now(),
            },
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
            active = conn.execute(
                """SELECT id, chain_id, action_type, target, rollback_command
                     FROM responses WHERE status='active'"""
            ).fetchall()
            conn.close()

            for resp in active:
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
                        if rollback_cmd:
                            _run_shell(rollback_cmd)
                        _mark_rolled_back(response_id)
                        _log_optional_rollback_history(
                            chain_id, response_id, "score_below_tier"
                        )
                        _update_node_health(_node_name_from_target(target), "healthy")
                        with _state_lock:
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
                                "severity": "rollback - score dropped",
                                "timestamp": _now(),
                            },
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
    log.info("  ENFORCEMENT  = %s", DEFENDER_ENFORCEMENT)
    log.info("  ATTACKER_NS  = %s", ATTACKER_CONTAINER)
    log.info("  WORKERS      = %d", EXECUTOR_WORKERS)
    log.info("=" * 55)

    _wait_for_sqlite()
    _init_schema()
    _enable_ip_forward()
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

    t1.start()
    t2.start()
    t3.start()

    log.info("[startup] All three threads running - Defender Agent is LIVE")

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
