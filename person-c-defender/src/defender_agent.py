"""
defender_agent.py  -  Person C  (EdgeShield)

Reads SCORE_COMPUTED events from Redis (published by Person B).
For each score, looks up the target IP from the chain's alerts in SQLite,
evaluates the response policy, runs the false-positive guard, executes
the network command, logs to the responses table, and fires RESPONSE_EXECUTED.

Three threads run concurrently:
  Thread 1  EventBus listener   - reacts to SCORE_COMPUTED in real time
  Thread 2  Rollback checker    - every 30s, rolls back responses whose score dropped
  Thread 3  Polling fallback    - every 15s, catches any missed Redis events

Startup: waits for Redis and SQLite before launching threads.
"""

import json
import logging
import os
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.abspath("."))

from shared.eventbus_client import EventBus

REDIS_HOST  = os.environ.get("REDIS_HOST",  "redis")
REDIS_PORT  = int(os.environ.get("REDIS_PORT", "6379"))
SQLITE_PATH = os.environ.get("SQLITE_PATH", "/data/edgeshield.db")

ROLLBACK_POLL_SEC   = 30
FALLBACK_POLL_SEC   = 15
ROLLBACK_DELAY_SEC  = 60
FP_MIN_ALERTS       = 2
FP_MIN_GAP_SEC      = 5.0

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("defender-agent")

TIERS = [
    {
        "min": 85, "max": 100,
        "action_type": "full_isolation",
        "command":      "iptables -I INPUT -s {target} -j DROP && iptables -I FORWARD -d {target} -j DROP",
        "rollback_cmd": "iptables -D INPUT -s {target} -j DROP ; iptables -D FORWARD -d {target} -j DROP",
        "label": "CRITICAL - full isolation",
    },
    {
        "min": 70, "max": 85,
        "action_type": "isolate_node",
        "command":      "iptables -I FORWARD -d {target} -j DROP",
        "rollback_cmd": "iptables -D FORWARD -d {target} -j DROP",
        "label": "HIGH - node isolated",
    },
    {
        "min": 50, "max": 70,
        "action_type": "block_ip",
        "command":      "iptables -I INPUT -s {target} -j DROP",
        "rollback_cmd": "iptables -D INPUT -s {target} -j DROP",
        "label": "MEDIUM-HIGH - source IP blocked",
    },
    {
        "min": 30, "max": 50,
        "action_type": "rate_limit",
        "command":      "iptables -I INPUT -s {target} -m limit --limit 10/min --limit-burst 5 -j ACCEPT && iptables -A INPUT -s {target} -j DROP",
        "rollback_cmd": "iptables -D INPUT -s {target} -m limit --limit 10/min --limit-burst 5 -j ACCEPT ; iptables -D INPUT -s {target} -j DROP",
        "label": "MEDIUM - rate limited",
    },
    {
        "min": 0, "max": 30,
        "action_type": "monitor",
        "command":      None,
        "rollback_cmd": None,
        "label": "LOW - monitor only",
    },
]


def get_tier(score: float) -> dict:
    for tier in TIERS:
        if tier["min"] <= score <= tier["max"]:
            return tier
    return TIERS[-1]


_below_since: dict = {}
_active_tier_map: dict = {}
_state_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(SQLITE_PATH, timeout=10, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_target_ip(chain_id: str) -> str:
    try:
        conn = _conn()
        chain = conn.execute(
            "SELECT alert_ids FROM attack_chains WHERE chain_id = ?",
            (chain_id,)
        ).fetchone()
        if not chain:
            conn.close()
            return "unknown"
        alert_ids = json.loads(chain["alert_ids"])
        if not alert_ids:
            conn.close()
            return "unknown"
        placeholders = ",".join("?" * len(alert_ids))
        row = conn.execute(
            f"SELECT target_ip, source_ip FROM alerts WHERE id IN ({placeholders}) LIMIT 1",
            [int(i) for i in alert_ids],
        ).fetchone()
        conn.close()
        if row:
            return row["target_ip"] or row["source_ip"] or "unknown"
        return "unknown"
    except Exception as exc:
        log.warning("Could not derive target_ip for chain %s: %s", chain_id, exc)
        return "unknown"


def _is_corroborated(chain_id: str) -> bool:
    try:
        conn = _conn()
        chain = conn.execute(
            "SELECT alert_ids FROM attack_chains WHERE chain_id = ?",
            (chain_id,)
        ).fetchone()
        if not chain:
            conn.close()
            return False
        alert_ids = json.loads(chain["alert_ids"])
        if len(alert_ids) < FP_MIN_ALERTS:
            log.info("[fp_guard] chain %s has %d alert(s) - need %d", chain_id, len(alert_ids), FP_MIN_ALERTS)
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
            last  = datetime.fromisoformat(rows[-1]["timestamp"].replace("Z", "+00:00"))
            gap   = (last - first).total_seconds()
        except Exception:
            return True
        if gap < FP_MIN_GAP_SEC:
            log.info("[fp_guard] chain %s: span=%.1fs < %.1fs - looks like burst", chain_id, gap, FP_MIN_GAP_SEC)
            return False
        log.info("[fp_guard] chain %s corroborated: %d alerts over %.1fs", chain_id, len(rows), gap)
        return True
    except Exception as exc:
        log.error("[fp_guard] error for chain %s: %s", chain_id, exc)
        return False


def _run_command(cmd_template: str, target: str) -> bool:
    if not cmd_template:
        return True
    cmd = cmd_template.replace("{target}", target)
    log.info("[iptables] RUN: %s", cmd)
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            log.warning("[iptables] exit=%d stderr=%s", result.returncode, result.stderr.strip())
        return True
    except subprocess.TimeoutExpired:
        log.error("[iptables] TIMEOUT: %s", cmd)
        return False
    except Exception as exc:
        log.error("[iptables] ERROR: %s - %s", cmd, exc)
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


def _update_node_health(target: str, status: str):
    try:
        conn = _conn()
        conn.execute(
            """INSERT INTO node_health (node_name, status, last_updated)
               VALUES (?, ?, ?)
               ON CONFLICT(node_name) DO UPDATE
               SET status=excluded.status,
                   last_updated=excluded.last_updated""",
            (target, status, _now()),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        log.warning("[node_health] update failed: %s", exc)


def _apply_response(chain_id: str, score: float, bus: EventBus):
    tier = get_tier(score)

    if tier["action_type"] == "monitor":
        log.info("[policy] chain=%s score=%.1f -> MONITOR only", chain_id, score)
        return

    if not _is_corroborated(chain_id):
        log.warning("[policy] FP guard BLOCKED chain=%s tier=%s", chain_id, tier["action_type"])
        return

    with _state_lock:
        current = _active_tier_map.get(chain_id)
    if current == tier["action_type"]:
        log.info("[policy] chain=%s already at tier=%s - skip", chain_id, tier["action_type"])
        return

    target = _get_target_ip(chain_id)
    if target == "unknown":
        log.warning("[policy] cannot derive target for chain=%s - skip", chain_id)
        return

    rollback_cmd = tier["rollback_cmd"].replace("{target}", target) if tier["rollback_cmd"] else None
    response_id = _write_response(chain_id, tier["action_type"], target, rollback_cmd)
    success = _run_command(tier["command"], target)

    if success:
        log.info(
            "[policy] APPLIED chain=%s score=%.1f tier=%s target=%s id=%d",
            chain_id, score, tier["action_type"], target, response_id,
        )
        with _state_lock:
            _active_tier_map[chain_id] = tier["action_type"]
            _below_since.pop(chain_id, None)
        _update_node_health(target, tier["action_type"])
        bus.publish(EventBus.RESPONSE_EXECUTED, {
            "response_id":  response_id,
            "chain_id":     chain_id,
            "action_type":  tier["action_type"],
            "target":       target,
            "score":        score,
            "severity":     tier["label"],
            "timestamp":    _now(),
        })
    else:
        log.error("[policy] command FAILED chain=%s tier=%s", chain_id, tier["action_type"])


def _listener_thread(bus: EventBus):
    log.info("[thread-1] EventBus listener started")
    for event_type, payload in bus.listen():
        if event_type != EventBus.SCORE_COMPUTED:
            continue
        try:
            chain_id = payload.get("chain_id")
            score    = float(payload.get("score", 0))
            if not chain_id:
                continue
            log.info("[thread-1] SCORE_COMPUTED chain=%s score=%.1f", chain_id, score)
            _apply_response(chain_id, score, bus)
        except Exception as exc:
            log.error("[thread-1] error: %s", exc)


def _rollback_thread(bus: EventBus):
    log.info("[thread-2] Rollback checker started - interval=%ds", ROLLBACK_POLL_SEC)
    while True:
        try:
            conn = _conn()
            active = conn.execute(
                "SELECT id, chain_id, action_type, target, rollback_command FROM responses WHERE status='active'"
            ).fetchall()
            conn.close()

            for resp in active:
                chain_id     = resp["chain_id"]
                response_id  = resp["id"]
                action_type  = resp["action_type"]
                target       = resp["target"]
                rollback_cmd = resp["rollback_command"]

                latest_score = _get_latest_score(chain_id)
                if latest_score is None:
                    continue

                tier_min = next(
                    (t["min"] for t in TIERS if t["action_type"] == action_type), 0
                )
                now = datetime.now(timezone.utc)

                if latest_score < tier_min:
                    with _state_lock:
                        if chain_id not in _below_since:
                            _below_since[chain_id] = now
                            log.info(
                                "[thread-2] chain=%s score=%.1f below tier_min=%d - timer started",
                                chain_id, latest_score, tier_min,
                            )
                        elapsed = (now - _below_since[chain_id]).total_seconds()

                    if elapsed >= ROLLBACK_DELAY_SEC:
                        log.info(
                            "[thread-2] ROLLBACK chain=%s elapsed=%.0fs action=%s target=%s",
                            chain_id, elapsed, action_type, target,
                        )
                        if rollback_cmd:
                            _run_command(rollback_cmd, target)
                        _mark_rolled_back(response_id)
                        _update_node_health(target, "healthy")
                        with _state_lock:
                            _active_tier_map.pop(chain_id, None)
                            _below_since.pop(chain_id, None)
                        bus.publish(EventBus.RESPONSE_EXECUTED, {
                            "response_id": response_id,
                            "chain_id":    chain_id,
                            "action_type": "rollback",
                            "target":      target,
                            "score":       latest_score,
                            "severity":    "rollback - score dropped",
                            "timestamp":   _now(),
                        })
                else:
                    with _state_lock:
                        if chain_id in _below_since:
                            log.info("[thread-2] chain=%s score recovered to %.1f - reset timer", chain_id, latest_score)
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
                score    = float(row["score"])
                existing = _get_active_response(chain_id)
                if existing:
                    continue
                with _state_lock:
                    current = _active_tier_map.get(chain_id)
                tier = get_tier(score)
                if current == tier["action_type"]:
                    continue
                log.info("[thread-3] fallback triggered chain=%s score=%.1f", chain_id, score)
                _apply_response(chain_id, score, bus)

        except Exception as exc:
            log.error("[thread-3] error: %s", exc)
        time.sleep(FALLBACK_POLL_SEC)


def _wait_for_redis() -> EventBus:
    import redis as rlib
    for attempt in range(1, 21):
        try:
            r = rlib.Redis(host=REDIS_HOST, port=REDIS_PORT)
            r.ping()
            r.close()
            log.info("[startup] Redis ready at %s:%d", REDIS_HOST, REDIS_PORT)
            return EventBus(host=REDIS_HOST, port=REDIS_PORT)
        except Exception as exc:
            log.warning("[startup] Redis not ready (%d/20): %s", attempt, exc)
            time.sleep(3)
    log.critical("[startup] Redis unavailable - exiting")
    sys.exit(1)


def _wait_for_sqlite():
    import pathlib
    for attempt in range(1, 11):
        try:
            pathlib.Path(SQLITE_PATH).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(SQLITE_PATH, timeout=5)
            conn.execute("SELECT 1")
            conn.close()
            log.info("[startup] SQLite ready at %s", SQLITE_PATH)
            return
        except Exception as exc:
            log.warning("[startup] SQLite not ready (%d/10): %s", attempt, exc)
            time.sleep(2)
    log.critical("[startup] SQLite unavailable - exiting")
    sys.exit(1)


def _init_schema():
    for path in [
        os.path.join(os.path.dirname(__file__), "..", "shared", "schema.sql"),
        "shared/schema.sql",
    ]:
        if os.path.exists(path):
            conn = _conn()
            with open(path) as f:
                conn.executescript(f.read())
            conn.commit()
            conn.close()
            log.info("[startup] Schema initialised from %s", path)
            return
    log.warning("[startup] schema.sql not found - tables may already exist")


def main():
    log.info("=" * 55)
    log.info("EdgeShield Defender Agent  (Person C)")
    log.info("  REDIS_HOST  = %s:%s", REDIS_HOST, REDIS_PORT)
    log.info("  SQLITE_PATH = %s", SQLITE_PATH)
    log.info("=" * 55)

    _wait_for_sqlite()
    _init_schema()
    bus = _wait_for_redis()

    bus.subscribe([EventBus.SCORE_COMPUTED])

    bus2 = EventBus(host=REDIS_HOST, port=REDIS_PORT)
    bus3 = EventBus(host=REDIS_HOST, port=REDIS_PORT)

    t1 = threading.Thread(target=_listener_thread, args=(bus,),  daemon=True, name="eventbus-listener")
    t2 = threading.Thread(target=_rollback_thread, args=(bus2,), daemon=True, name="rollback-checker")
    t3 = threading.Thread(target=_fallback_thread, args=(bus3,), daemon=True, name="polling-fallback")

    t1.start()
    t2.start()
    t3.start()

    log.info("[startup] All three threads running - Defender Agent is LIVE")

    while True:
        time.sleep(60)
        with _state_lock:
            log.info(
                "[heartbeat] active_tiers=%s",
                list(_active_tier_map.keys()),
            )


if __name__ == "__main__":
    main()