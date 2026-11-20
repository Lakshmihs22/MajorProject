# Final phase evaluation demo (major project)

## What to tell the panel

EdgeShield is **not** a single hardcoded attack script against one victim. It is a **Docker lab that stands in for heterogeneous edge devices** (different classes, IPs, criticality). A **real lab traffic source** (`lab-traffic-source` at `172.28.0.10`) runs **live packets** (Nmap, Hydra, Paramiko, Scapy) against:

| IP | Device role |
|----|-------------|
| 172.28.0.11 | Industrial OPC-UA / PLC gateway |
| 172.28.0.12 | Building IoT sensor hub |
| 172.28.0.13 | DNS / utility edge relay |

Each edge container has its **own passive sensor** sharing that container’s network namespace — as close as we can get to “different real devices” without physical hardware cost.

**One adversary IP → one correlated campaign** across multiple victims and attack types (port scan, brute force, lateral movement, credential stuffing, HTTP flood, DNS tunnelling, ARP recon, DDoS impact).

Synthetic fixtures exist **only** for optional labeled pipeline tests on the dashboard — **not** the primary final demo story.

## Run (standard — policy simulation + real traffic)

```bash
docker compose build
docker compose up
```

- Dashboard: http://localhost:3000  
- API: http://localhost:8000  

Default: `DEFENDER_ENFORCEMENT=simulation` (real decisions, full audit, **no** host firewall claims).

## Run (optional final wow — live lab enforcement)

```bash
docker compose -f docker-compose.yml -f docker-compose.final-demo.yml up --build
```

Prove block only inside the lab:

```bash
docker exec lab-traffic-source ping -c 2 172.28.0.11
```

## Demo script (15–20 min)

1. **Fleet** — Dashboard **Edge device fleet**: three device classes, three IPs.  
2. **Benign** — **Packet telemetry**: health-probe `172.28.0.9` → `benign_health_check` (not an attack).  
3. **Live attack** — `docker logs -f lab-traffic-source` — multi-device campaign narrative.  
4. **Detection** — Alerts with `provenance: sensor_live` on **different target_node** values.  
5. **Analysis** — One **chain_id**, multiple victims in score factors / chain graph.  
6. **Defense** — Response log with tier + `enforcement_mode` (simulated or live).  
7. **Criticality** — DNS utility edge (critical) influences policy score on defender.  
8. **Evaluation** — Metrics scoped to live alerts vs `ground_truth.jsonl`.  
9. **Synthetic** (30 s) — Only to show labeled test data; state it is excluded from live correlation.

## Requirements alignment

See project objectives 1–12: real containers, real traffic, passive sensors, cross-node correlation, MITRE mapping, explainable scores + decay, proportional response, honeypot on isolate (live mode), rollback, node health, dashboard lifecycle, unknown attack types via defaults.