"""
Day-1 fixture: populates `alerts` with 50 realistic fake rows so Person B
can build the Correlation Engine, Tactic Mapper, and Threat Scorer without
waiting on Person A's real Sensor Agent.

Run from inside a container with access to /data, or locally against a
local sqlite file for quick iteration:

    python fixtures/mock_alerts.py /path/to/edgeshield.db
"""

import sqlite3
import sys
import random
from datetime import datetime, timedelta

ATTACK_TYPES = ["port_scan", "brute_force", "lateral_movement", "ddos"]
NODES = ["edge-node-1", "edge-node-2", "edge-node-3"]


def main(db_path: str):
    conn = sqlite3.connect(db_path)
    with open("shared/schema.sql") as f:
        conn.executescript(f.read())

    base_time = datetime.utcnow()
    rows = []
    t = base_time
    for i in range(50):
        node = random.choice(NODES)
        attack_type = ATTACK_TYPES[min(i // 13, 3)]  # roughly stages through the kill chain
        t += timedelta(seconds=random.randint(5, 40))
        rows.append((
            t.isoformat(),
            "172.28.0.10",       # attacker
            f"172.28.0.1{NODES.index(node)+1}",
            node,
            attack_type,
            random.choice(["scapy", "suricata", "both"]),
            None,
            f"mock alert #{i}",
        ))

    conn.executemany(
        """INSERT INTO alerts
           (timestamp, source_ip, target_ip, target_node, attack_type,
            detection_source, mitre_tactic, raw_details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    conn.commit()
    conn.close()
    print(f"Inserted {len(rows)} mock alerts into {db_path}")


if __name__ == "__main__":
    db_path = sys.argv[1] if len(sys.argv) > 1 else "data/edgeshield.db"
    main(db_path)
