"""
Day-1 fixture: inserts one attack chain and a rising sequence of threat
scores so Person C can test every tier of the Response Policy Engine
without waiting on Person B's real Analysis Agent.

Run:
    python fixtures/mock_chains_scores.py /path/to/edgeshield.db
"""

import sqlite3
import sys
import json
from datetime import datetime, timedelta

RISING_SCORES = [10, 25, 32, 48, 55, 68, 74, 86, 91]  # crosses every response tier


def main(db_path: str):
    conn = sqlite3.connect(db_path)
    with open("shared/schema.sql") as f:
        conn.executescript(f.read())

    chain_id = "mock-chain-001"
    now = datetime.utcnow()

    conn.execute(
        """INSERT OR IGNORE INTO attack_chains
           (chain_id, alert_ids, mitre_sequence, start_time, last_updated, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (chain_id, json.dumps([1, 2, 3]), "TA0043 -> TA0006 -> TA0008", now.isoformat(), now.isoformat(), "active"),
    )

    for i, score in enumerate(RISING_SCORES):
        t = now + timedelta(seconds=i * 10)
        label = "Low" if score < 30 else "Medium" if score < 50 else "High" if score < 85 else "Critical"
        conn.execute(
            """INSERT INTO threat_scores
               (chain_id, timestamp, score, severity_label, factors_json)
               VALUES (?, ?, ?, ?, ?)""",
            (chain_id, t.isoformat(), score, label, json.dumps({"mock": True})),
        )

    conn.commit()
    conn.close()
    print(f"Inserted mock chain '{chain_id}' with {len(RISING_SCORES)} rising scores into {db_path}")


if __name__ == "__main__":
    db_path = sys.argv[1] if len(sys.argv) > 1 else "data/edgeshield.db"
    main(db_path)
