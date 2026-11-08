"""
Seed SQLite + publish SCORE_COMPUTED events for a Person C-only demo.

Run from repo root (Redis on localhost:6379, DB at data/edgeshield.db):

    python person-c-defender/scripts/seed_person_c_demo.py

With Docker Redis:

    set REDIS_HOST=localhost
    python person-c-defender/scripts/seed_person_c_demo.py
"""

import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

CHAIN_ID = "person-c-demo-001"
SCORES = [28, 42, 58, 76, 88]


def _load_schema(conn: sqlite3.Connection):
    for rel in ("shared/schema.sql", "person-c-defender/schema_extensions.sql"):
        path = os.path.join(ROOT, rel)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                conn.executescript(fh.read())


def main():
    db_path = os.environ.get("SQLITE_PATH", os.path.join(ROOT, "data", "edgeshield.db"))
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    _load_schema(conn)

    now = datetime.now(timezone.utc)
    t0 = now - timedelta(seconds=30)
    t1 = now - timedelta(seconds=20)

    conn.execute("DELETE FROM alerts WHERE source_ip = '172.28.0.10' AND target_ip = '172.28.0.11'")
    conn.execute("DELETE FROM threat_scores WHERE chain_id = ?", (CHAIN_ID,))
    conn.execute("DELETE FROM responses WHERE chain_id = ?", (CHAIN_ID,))
    conn.execute("DELETE FROM attack_chains WHERE chain_id = ?", (CHAIN_ID,))

    conn.execute(
        """INSERT INTO alerts
           (timestamp, source_ip, target_ip, target_node, attack_type,
            detection_source, mitre_tactic, raw_details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            t0.isoformat(),
            "172.28.0.10",
            "172.28.0.11",
            "edge-node-1",
            "port_scan",
            "scapy",
            "TA0043",
            "person-c demo alert 1",
        ),
    )
    conn.execute(
        """INSERT INTO alerts
           (timestamp, source_ip, target_ip, target_node, attack_type,
            detection_source, mitre_tactic, raw_details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            t1.isoformat(),
            "172.28.0.10",
            "172.28.0.11",
            "edge-node-1",
            "brute_force",
            "suricata",
            "TA0006",
            "person-c demo alert 2",
        ),
    )
    alert_ids = [r[0] for r in conn.execute("SELECT id FROM alerts ORDER BY id DESC LIMIT 2").fetchall()]
    alert_ids.reverse()

    conn.execute(
        """INSERT INTO attack_chains
           (chain_id, alert_ids, mitre_sequence, start_time, last_updated, status)
           VALUES (?, ?, ?, ?, ?, 'active')""",
        (
            CHAIN_ID,
            json.dumps(alert_ids),
            "TA0043 -> TA0006",
            t0.isoformat(),
            now.isoformat(),
        ),
    )

    for i, score in enumerate(SCORES):
        ts = now + timedelta(seconds=i * 2)
        label = (
            "Low"
            if score < 30
            else "Medium"
            if score < 50
            else "High"
            if score < 85
            else "Critical"
        )
        conn.execute(
            """INSERT INTO threat_scores
               (chain_id, timestamp, score, severity_label, factors_json)
               VALUES (?, ?, ?, ?, ?)""",
            (CHAIN_ID, ts.isoformat(), score, label, json.dumps({"demo": True})),
        )

    conn.commit()
    conn.close()
    print(f"Seeded chain {CHAIN_ID} with alerts {alert_ids} and scores {SCORES} -> {db_path}")

    try:
        import redis

        host = os.environ.get("REDIS_HOST", "localhost")
        port = int(os.environ.get("REDIS_PORT", "6379"))
        r = redis.Redis(host=host, port=port, decode_responses=True)
        r.ping()
        for score in SCORES:
            payload = {
                "chain_id": CHAIN_ID,
                "score": float(score),
                "severity_label": "demo",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            r.publish("SCORE_COMPUTED", json.dumps(payload))
            print(f"Published SCORE_COMPUTED score={score}")
        print("Done. Check defender logs and responses table.")
    except Exception as exc:
        print(f"Redis publish skipped ({exc}). Start defender and re-run, or publish manually.")


if __name__ == "__main__":
    main()
