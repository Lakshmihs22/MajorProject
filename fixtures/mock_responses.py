"""
Day-1 fixture: inserts a handful of response actions so Person D can build
the Response Audit Log panel and the Evaluation Module without waiting on
Person C's real Defender Agent.

Run:
    python fixtures/mock_responses.py /path/to/edgeshield.db
"""

import sqlite3
import sys
import json
from datetime import datetime, timedelta

MOCK_RESPONSES = [
    ("mock-chain-001", "rate_limit", "172.28.0.10", "iptables -D INPUT -s 172.28.0.10 -j DROP", "active"),
    ("mock-chain-001", "block_ip", "172.28.0.10", "iptables -D INPUT -s 172.28.0.10 -j DROP", "active"),
    ("mock-chain-001", "isolate_node", "edge-node-2", "iptables -D FORWARD -d 172.28.0.12 -j DROP", "rolled_back"),
]


def main(db_path: str):
    conn = sqlite3.connect(db_path)
    with open("shared/schema.sql") as f:
        conn.executescript(f.read())

    now = datetime.utcnow()
    for i, (chain_id, action_type, target, rollback_cmd, status) in enumerate(MOCK_RESPONSES):
        t = now + timedelta(seconds=i * 15)
        rolled_back_at = (t + timedelta(seconds=60)).isoformat() if status == "rolled_back" else None
        conn.execute(
            """INSERT INTO responses
               (chain_id, timestamp, action_type, target, rollback_command, status, rolled_back_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (chain_id, t.isoformat(), action_type, target, rollback_cmd, status, rolled_back_at),
        )

    conn.commit()
    conn.close()
    print(f"Inserted {len(MOCK_RESPONSES)} mock responses into {db_path}")


if __name__ == "__main__":
    db_path = sys.argv[1] if len(sys.argv) > 1 else "data/edgeshield.db"
    main(db_path)
