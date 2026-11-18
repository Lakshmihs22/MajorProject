# EdgeShield — Person C (Defender Agent)

**Owner:** Palguni V Kumar (1SI23CS124)  
**Component:** Autonomous response policy engine, iptables enforcement, honeypot redirection, adaptive rollback.

Person C sits after Person B’s threat scoring. It listens for `SCORE_COMPUTED` on Redis, loads attacker/victim context from SQLite, applies a **dynamic policy score**, chooses a **response tier**, runs **iptables** (and honeypot DNAT when isolating), logs to the database, and publishes `RESPONSE_EXECUTED` for the dashboard.

---

## What is implemented

| Feature | Description |
|--------|-------------|
| **Event-driven response** | Subscribes to `SCORE_COMPUTED`; publishes `RESPONSE_EXECUTED`. |
| **SQLite context lookup** | Person B does **not** send `target_ip` in the event. Defender reads `attack_chains` → `alerts` for `source_ip` (attacker), `target_ip` (victim), and dominant `attack_type`. |
| **Five response tiers** | `monitor`, `rate_limit`, `block_ip`, `isolate_node`, `full_isolation` (score bands 0–29 … 85–100). |
| **Attack-specific iptables** | Rules differ for e.g. `brute_force` (port 22), `ddos` / floods, `dns_tunnelling`, etc. Unknown types use `DEFAULT_SEVERITY=18` for type ranking. |
| **False-positive guard** | Needs ≥2 alerts on the chain and ≥5 seconds between first and last alert; DB errors → **no** response (fail-secure). |
| **Parallel chains** | `ThreadPoolExecutor` with 20 workers so many chains are handled at once. |
| **Adaptive rollback** | Default 60s below tier before rollback; delay **doubles** after a false rollback (max 300s). |
| **Honeypot** | On `isolate_node`: DNAT attacker traffic toward victim to `HONEYPOT_IP` (default `172.28.0.200`) + FORWARD drop to real victim. |
| **Device registry** | Seeds edge nodes with criticality (`high` / `medium` / `critical`). |
| **Dynamic policy score** | Adjusts Person B’s raw score using victim criticality, off-hours (UTC 22:00–06:00), and high CPU in `node_health` (+5 if CPU ≥ 80%). |
| **Three background threads** | (1) Redis listener, (2) rollback checker every 30s, (3) DB polling fallback every 15s. Each thread has its **own** Redis connection. |
| **DB extensions** | `device_registry`, `honeypot_sessions`, `rollback_history` (via `schema_extensions.sql` at startup). |
| **Honeypot HTTP service** | Flask catch-all on port 80; logs to `/data/honeypot_log.jsonl` on the shared volume. |
| **Docker Compose** | Root `docker-compose.yml` includes `honeypot` + `defender-agent` with `HONEYPOT_IP` and shared `edgeshield-data` volume. |

### Response tiers (after dynamic score adjustment)

| Score | `action_type` | Network effect |
|------|----------------|----------------|
| 0–29 | `monitor` | Log only |
| 30–49 | `rate_limit` | Attack-type-specific rate limit + drop |
| 50–69 | `block_ip` | Drop / restrict traffic from attacker IP |
| 70–84 | `isolate_node` | DNAT to honeypot + protect victim |
| 85–100 | `full_isolation` | Drop from attacker + drop forward to victim |

### Supported attack types (extensible)

`port_scan`, `brute_force`, `lateral_movement`, `ddos`, `arp_spoofing`, `dns_tunnelling`, `credential_stuff`, `http_flood`, `icmp_flood`, plus any unknown label (severity default 18).

---

## Repository layout (Person C)

```
person-c-defender/
├── README.md                 ← this file
├── Dockerfile                ← defender image (iptables, agent)
├── requirements.txt          ← redis
├── schema_extensions.sql     ← device_registry, honeypot_*, rollback_history
├── src/
│   └── defender_agent.py     ← main agent
├── honeypot/
│   ├── Dockerfile
│   └── honeypot_server.py
└── scripts/
    └── seed_person_c_demo.py ← local / CI demo without full attack stack
```

**Also required from repo root (not under `person-c-defender/`):**

- `shared/schema.sql`, `shared/eventbus_client.py`
- `docker-compose.yml` (honeypot + defender services)

---

## Prerequisites (other laptop)

1. **Docker Desktop** (or Docker Engine + Compose v2) — **Linux containers** (WSL2 backend on Windows is fine).
2. **Git** optional; you can unzip the project folder as-is.
3. **Python 3.10+** only if you run `scripts/seed_person_c_demo.py` on the **host** (not required if you use full stack + Person B).

Open a terminal in the **project root** (folder that contains `docker-compose.yml`).

---

## Environment variables

| Variable | Default | Used by |
|----------|---------|---------|
| `REDIS_HOST` | `redis` | Defender |
| `REDIS_PORT` | `6379` | Defender |
| `SQLITE_PATH` | `/data/edgeshield.db` | Defender (in container) |
| `HONEYPOT_IP` | `172.28.0.200` | Defender DNAT target |
| `HONEYPOT_LOG` | `/data/honeypot_log.jsonl` | Honeypot container |
| `DEFENDER_ENFORCEMENT` | `simulation` | `simulation` (DB + Redis only) or `live` (docker exec into attacker) |
| `ATTACKER_CONTAINER` | `attacker` | Container name for live iptables (matches root `docker-compose.yml`) |

Host-side demo script: set `REDIS_HOST=localhost` when Redis port `6379` is published.

---

## How to run

### 1) Person C only (fast smoke test)

```bash
docker compose up --build redis honeypot defender-agent
```

Wait for log line: `Defender Agent is LIVE`.

**If your friend “cannot see the defender at all”:**

1. Confirm the container is running: `docker ps --filter name=defender-agent` (not exited/restarting).
2. Check logs: `docker logs defender-agent` — a past bug used `Optional` without importing it and the process died immediately on startup; pull the latest `person-c-defender/src/defender_agent.py` if logs show `NameError: Optional`.
3. The dashboard has no separate “Defender” tile — responses appear under **Response Audit Log** on http://localhost:3000 (needs `defender-agent` + `analysis-agent` or the seed script).
4. Default enforcement is **simulation** (rows in SQLite + `RESPONSE_EXECUTED` on Redis); live blocking needs the overlay compose file below.

### 2) Full EdgeShield stack (demo with dashboard)

```bash
docker compose up --build
```

- Dashboard API: http://localhost:8000  
- Dashboard UI: http://localhost:3000  
- Redis on host: `localhost:6379` (for seed script)

### 3) Scripted Person C demo (no attacker / no Person B)

Start Redis + defender (and honeypot) as in step 1. On the **host**:

**Windows (cmd):**

```bat
set REDIS_HOST=localhost
set SQLITE_PATH=data\edgeshield.db
python person-c-defender\scripts\seed_person_c_demo.py
```

**Linux / macOS:**

```bash
export REDIS_HOST=localhost
export SQLITE_PATH=data/edgeshield.db
python3 person-c-defender/scripts/seed_person_c_demo.py
```

The script:

- Creates chain `person-c-demo-001` with two corroborated alerts (`172.28.0.10` → `172.28.0.11`).
- Inserts scores `28, 42, 58, 76, 88`.
- Publishes each score on `SCORE_COMPUTED`.

Because `edge-node-1` is **high** criticality (+8), effective scores are higher than raw — expect escalation through **rate_limit → block_ip → isolate_node** (and possibly higher) in defender logs.

---

## How to test and verify

### Defender logs

```bash
docker logs -f defender-agent
```

Look for:

- `[thread-1] SCORE_COMPUTED`
- `[policy] score X -> Y` (dynamic adjustment)
- `[fp_guard] ... corroborated`
- `[policy] APPLIED ... tier=...`
- `[iptables] RUN: ...`
- `[thread-2] ROLLBACK` (after score stays below tier long enough)

### Responses in SQLite

```bash
docker exec defender-agent python -c "import sqlite3; c=sqlite3.connect('/data/edgeshield.db'); print(*c.execute('SELECT id,chain_id,action_type,target,status FROM responses').fetchall(), sep='\n')"
```

### Honeypot log (after `isolate_node`)

```bash
docker exec honeypot cat /data/honeypot_log.jsonl
```

### Manual Redis publish (one shot)

With Redis on localhost:

```bash
python -c "import redis,json; r=redis.Redis(host='localhost',port=6379); r.publish('SCORE_COMPUTED',json.dumps({'chain_id':'person-c-demo-001','score':75.0,'severity_label':'High','timestamp':'2026-01-01T00:00:00+00:00'}))"
```

Chain must exist in DB with ≥2 alerts or FP guard will block.

### Integration test (real pipeline)

1. `docker compose up --build`
2. Let Person A generate alerts and Person B publish scores.
3. Confirm `responses` rows and dashboard **Response audit** updates.

---

## Troubleshooting

### Docker: “cannot connect to Docker API” / daemon not running

- Start **Docker Desktop** and wait until it is healthy.
- On Windows, ensure **WSL2** integration is enabled for your distro if you use WSL.

### `docker compose` vs `docker-compose`

Try both:

```bash
docker compose up --build
# or
docker-compose up --build
```

### Defender exits: Redis / SQLite not ready

- Defender retries Redis **30×** (3s apart) and SQLite **15×** (2s apart).
- Start **redis** first: `docker compose up redis` then add defender.
- Ensure volume mount exists: service uses `edgeshield-data:/data`.

### No responses / “FP guard BLOCKED”

- Chain needs **at least 2** alert IDs in `attack_chains.alert_ids`.
- Alerts must be **≥5 seconds** apart on timestamp.
- Fix: re-run `seed_person_c_demo.py` or insert proper alerts before scoring.

### “cannot derive src/dst” / target unknown

- `attack_chains` must reference valid `alerts.id` values with `source_ip` and `target_ip` populated.

### iptables warnings / exit code 1

- **Normal on duplicate rules** (iptables returns 1 if rule already exists). Agent logs a warning and continues.
- **On Windows host:** iptables is **not** used on the host; only inside the **defender** Linux container. Do not run `defender_agent.py` on Windows expecting real firewall changes unless you only test DB/logic.

### `ModuleNotFoundError: No module named 'shared'`

- Run via Docker (recommended) or from repo root with paths as in `defender_agent.py`.
- Local run from root:

```bash
set PYTHONPATH=.
set REDIS_HOST=localhost
set SQLITE_PATH=data\edgeshield.db
python person-c-defender\src\defender_agent.py
```

### Seed script: Redis publish skipped

- Start Redis with port published: `docker compose up redis defender-agent`
- Set `REDIS_HOST=localhost` on the host.

### Honeypot / DNAT not visible in traffic

- DNAT is applied in the **defender container’s network namespace**; full path visibility depends on bridge routing and who generates traffic. For the project demo, **DB responses + honeypot JSONL + dashboard** are the primary proof.
- Defender is `privileged: true` with `NET_ADMIN` and enables `net.ipv4.ip_forward=1` at startup.

### Dashboard shows no responses

- Confirm `dashboard-backend` shares the same `edgeshield-data` volume.
- Confirm defender published `RESPONSE_EXECUTED` (Redis) and rows exist in `responses`.

### Rebuild after code changes

```bash
docker compose build defender-agent honeypot
docker compose up -d redis honeypot defender-agent
```

### Clean slate (destructive — wipes shared DB volume)

```bash
docker compose down -v
docker compose up --build
```

---

## Event contract (team alignment)

| Event | Direction | Payload (minimal) |
|-------|-----------|-------------------|
| `SCORE_COMPUTED` | Person B → Person C | `chain_id`, `score`, `severity_label`, `timestamp` |
| `RESPONSE_EXECUTED` | Person C → Person D | `response_id`, `chain_id`, `action_type`, `target`, `score`, `timestamp`, … |

Person C **must** resolve IPs from SQLite; do not rely on `target_ip` in `SCORE_COMPUTED`.

---

## Research / viva talking points

1. **Proportional autonomous response** — five tiers mapped to continuous threat score, not a single block/deny.
2. **Attack-aware enforcement** — iptables templates per attack type (e.g. SSH brute force vs DDoS).
3. **Operational safety** — corroboration guard, audit-first DB write, non-fatal duplicate iptables, adaptive rollback to reduce false rollbacks.
4. **Deception** — honeypot DNAT on isolation to observe attacker while protecting the edge node.
5. **Context-aware policy** — device criticality and environmental factors adjust effective score before tier selection.

---

## Is everything done?

**Person C implementation:** yes — agent, honeypot service, schema extensions, compose wiring, and demo seed script are included in this zip.

**Your checklist on the new laptop:**

1. Install Docker Desktop.  
2. Unzip project → open terminal at repo root.  
3. `docker compose up --build redis honeypot defender-agent`  
4. Run `seed_person_c_demo.py` with `REDIS_HOST=localhost`.  
5. Check defender logs + `responses` table.  
6. Optional: full `docker compose up --build` with team for end-to-end attack → score → response → dashboard.

If anything fails, use the **Troubleshooting** section above and capture `docker logs defender-agent` for debugging.

---

## Quick reference commands

```bash
# Minimal Person C stack
docker compose up --build redis honeypot defender-agent

# Full system
docker compose up --build

# Follow defender
docker logs -f defender-agent

# List responses
docker exec defender-agent python -c "import sqlite3; c=sqlite3.connect('/data/edgeshield.db'); [print(r) for r in c.execute('SELECT * FROM responses')]"
```

**Team:** EdgeShield — SIT Tumakuru, AY 2026-27.
