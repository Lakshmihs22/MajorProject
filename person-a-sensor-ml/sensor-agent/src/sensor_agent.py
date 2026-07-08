"""
Sensor Agent (Person A)

Runs two parallel detection mechanisms:
    1. A Scapy packet sniffer with threshold-based classifiers per attack type
    2. A Suricata alert reader tailing the Suricata log file

Both are normalized into one unified alert format, deduplicated, written to
the `alerts` table, and published as a NEW_ALERT event on the EventBus.

Also loads the trained Random Forest model and classifies each traffic
window, writing to `ml_predictions` and publishing ML_PREDICTION.

This is a placeholder so `docker compose build` succeeds. Real logic comes
in the next build step.
"""

import os
import sys
import time
import sqlite3

sys.path.append("/app/shared")  # shared/ is mounted or copied in at build time
SQLITE_PATH = os.environ.get("SQLITE_PATH", "/data/edgeshield.db")


def init_db():
    conn = sqlite3.connect(SQLITE_PATH)
    with open("/app/shared/schema.sql") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


def main():
    print("[sensor-agent] placeholder running -- replace with Scapy + Suricata + ML logic")
    while True:
        time.sleep(30)


if __name__ == "__main__":
    main()
