"""
Attack Agent (Person A)

Runs a multi-stage kill chain against the edge nodes:
    port_scan -> brute_force -> lateral_movement -> ddos

Every action must be appended to the ground truth file with an exact
timestamp -- this file is what Person D's Evaluation Module scores against,
so accuracy here matters more than anywhere else in the project.

This is a placeholder so `docker compose build` succeeds. Real logic comes
in the next build step.
"""

import time
import json
from datetime import datetime, timezone

GROUND_TRUTH_PATH = "/data/ground_truth.jsonl"


def log_ground_truth(stage: str, target: str, detail: str = ""):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "target": target,
        "detail": detail,
    }
    with open(GROUND_TRUTH_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[attack-agent] {entry}")


def main():
    print("[attack-agent] placeholder running -- replace with real kill chain logic")
    while True:
        time.sleep(30)


if __name__ == "__main__":
    main()
