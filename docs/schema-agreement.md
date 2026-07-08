# Day 1 Schema Agreement

This is the one meeting where all four people must be in the same room
(or call) before anyone writes real code, because every agent reads and
writes these same SQLite tables and EventBus event names. Changing them
later means changing everyone's code.

## Checklist for the meeting

- [ ] Walk through `shared/schema.sql` table by table. Everyone confirms
      the columns they need are present.
- [ ] Walk through `shared/eventbus_client.py` event names
      (`NEW_ALERT`, `ML_PREDICTION`, `CHAIN_DETECTED`, `SCORE_COMPUTED`,
      `RESPONSE_EXECUTED`). Confirm payload shape for each (suggest: agree
      a JSON example for every event type and paste it below).
- [ ] Confirm fixed IPs on the `edgeshield-net` bridge network match what's
      in `docker-compose.yml` (attacker .10, edge-nodes .11-.13, sensor .20,
      redis .30, analysis .31, defender .32, backend .40, frontend .41).
- [ ] Confirm the ground truth file format Person A will write to
      (`/data/ground_truth.jsonl`), since Person D's Evaluation Module
      depends on it exactly.
- [ ] Agree on timestamp format everywhere: ISO 8601 UTC, e.g.
      `2026-07-08T10:15:32.123456+00:00` (Python's
      `datetime.now(timezone.utc).isoformat()`).

## Example event payloads (fill in during the meeting)

```json
// NEW_ALERT
{
  "alert_id": 123,
  "timestamp": "...",
  "source_ip": "172.28.0.10",
  "target_ip": "172.28.0.11",
  "target_node": "edge-node-1",
  "attack_type": "port_scan"
}
```

```json
// SCORE_COMPUTED
{
  "chain_id": "chain-abc123",
  "score": 74,
  "severity_label": "High",
  "timestamp": "..."
}
```

## Integration checkpoints after Day 1

- **End of Week 2**: Person B switches from `fixtures/mock_alerts.py` to
  Person A's real, live alerts.
- **End of Week 5**: Full system integration test -- all four modules
  connected, complete loop, attacker -> sensor -> analysis -> defender ->
  dashboard.
