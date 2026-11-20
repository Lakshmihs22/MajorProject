# Final project verification — main branch status

Static review against the **EdgeShield Final Project Verification Report** themes
(live pipeline close, heterogeneous lab, honest enforcement labeling). **Runtime E2E**
must be confirmed on the demo laptop with `docker compose up`.

## Verdict

**Demo-ready on code** — use `docs/DEMO_IN_2_HOURS.txt` + `docs/FINAL_RUN_AND_DEMO.txt`
for the evaluation machine. **Pick simulation (default) or live overlay before you present.**

## Items resolved (former blockers)

| Former issue | Status | Where |
|--------------|--------|--------|
| Defender crashes (`Optional`) | Resolved | `defender_agent.py` |
| Firewall rules on defender container | Resolved | `enforcer.py` → `lab-traffic-source` namespace |
| Docker socket not mounted at root compose | Resolved | `docker-compose.yml` defender volume |
| Closed 3-stage / 4-type correlator | Resolved | `analysis_agent.py` open campaigns + decay |
| Single static kill chain | Resolved | `attack_agent.py` `run_device_aware_campaign()` |
| Fixture-only narrative risk | Mitigated | Live `sensor_live`; synthetic labeled + excluded |
| Multi-victim defender actions | Resolved | Per-victim loop in defender |
| SQLite contention | Mitigated | `shared/sqlite_util.py` WAL + busy timeout |
| Dashboard lifecycle / fleet story | Resolved | Device fleet, packet telemetry, scenario control |
| Unknown attack types | Resolved | `DEFAULT_MITRE` ingest path (Person B) |

## Objectives 1–12 (checklist)

| # | Objective | Demo evidence |
|---|-----------|----------------|
| 1 | Multi-container lab | `docker compose ps` — edge nodes + sensors + agents |
| 2 | Real attack traffic | `docker logs lab-traffic-source` |
| 3 | Passive sensors | Three sensors in edge network namespaces |
| 4 | Cross-node correlation | One `chain_id`, multiple victims on dashboard |
| 5 | MITRE mapping | Chain / alert detail in DB |
| 6 | Explainable scores + decay | Score chart after idle period |
| 7 | Proportional response | Response log tiers |
| 8 | Honeypot on isolate (live) | `docker-compose.final-demo.yml` + defender logs |
| 9 | Rollback | Defender thread-2 / logs (`simulation` or `live`) |
| 10 | Node health | Node health panel |
| 11 | Dashboard | http://localhost:3000 |
| 12 | Unknown attack types | Ingest defaults in analysis agent |

## What to say (honest limits)

- **Devices** are Docker containers modeling OPC gateway, IoT hub, DNS edge — not physical hardware.
- **Enforcement** is **simulated by default**; live iptables proof requires the final-demo compose overlay.
- **ML** is auxiliary to rule-based scoring; model optional until `train_model.py` is run post-campaign.

## One command smoke test (after ~3 min uptime)

```powershell
docker compose ps
curl http://localhost:8000/health
curl http://localhost:8000/devices
```