# EdgeShield implementation checklist (main branch)

This file tracks the lab checklist against **main** only. All paths are under
`MajorProject-main/`.

## Architecture merge policy

| Area | Source | Notes |
|------|--------|-------|
| Person A, C, D | **Main** | Real lab traffic source, sensors, defender, dashboard |
| Person B | **person-b branch + main open correlator** | Branch: `parse_ts`, schema path resolution, Redis reconnect, ingest `detection_source`. Main: source-IP campaigns, decay, unknown types, synthetic exclusion |

## Data separation (not a static undifferentiated demo)

- **Live:** `provenance = sensor_live` (default) — real packets/alerts from the lab.
- **Benign:** health-probe → `packet_observations` with `observation_kind = benign_health_check`.
- **Synthetic:** dashboard button → `provenance = synthetic_scenario` (excluded from live correlation).
- **Defender:** `DEFENDER_ENFORCEMENT=simulation` by default (audit-only). Set `DEFENDER_ENFORCEMENT=live` only after lab approval.

## Validation order

See user checklist Phases 1–7. Docker must be running locally before E2E proof.

## Demo day (final — main branch)

| Document | Purpose |
|----------|---------|
| `docs/DEMO_IN_2_HOURS.txt` | Countdown + one decision (simulation vs live) |
| `docs/FINAL_RUN_AND_DEMO.txt` | Full build/run/demo + troubleshooting |
| `docs/FINAL_PHASE_DEMO.md` | Short panel narrative |
| `docs/FINAL_VERIFICATION_STATUS.md` | Blocker → resolved mapping |

**Default run:** `docker compose build && docker compose up`  
**Optional live enforcement:** add `-f docker-compose.final-demo.yml`

Code on disk is treated as **final** for evaluation; E2E proof = your Docker run.