"""
Defender Agent (Person C)

Subscribes to SCORE_COMPUTED. On each new score:
    1. Checks the response policy table (score -> action tier)
    2. Applies a false-positive guard (>=2 corroborating alerts before
       anything above rate-limiting)
    3. Executes the network action (iptables etc.), logs it to `responses`
       with its rollback command, fires RESPONSE_EXECUTED
A background thread every 30s checks whether any active response should be
rolled back because its score has since dropped.

Day-1 independence: run fixtures/mock_chains_scores.py first to get a rising
sequence of scores to react to, instead of waiting on Person B.

This is a placeholder so `docker compose build` succeeds. Real logic comes later.
"""

import time


def main():
    print("[defender-agent] placeholder running -- replace with policy engine + response logic")
    while True:
        time.sleep(30)


if __name__ == "__main__":
    main()
