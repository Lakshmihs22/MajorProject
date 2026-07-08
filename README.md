# EdgeShield

Multi-agent cooperative cyber defense system for edge computing networks.
Detects multi-stage attacks, correlates them into campaigns, scores threat
level continuously, and automatically responds -- all in Docker.

## Repo structure

```
edgeshield/
├── docker-compose.yml          # wires every container together
├── .env.example
├── shared/
│   ├── schema.sql              # the ONE shared SQLite schema -- agree changes as a team
│   └── eventbus_client.py      # Redis pub/sub wrapper used by every agent
├── docs/
│   └── schema-agreement.md     # Day-1 meeting checklist
├── fixtures/                   # mock data so everyone can build independently
│   ├── mock_alerts.py          # Person A's Day-1 fixture (for Person B)
│   ├── mock_chains_scores.py   # Person B's Day-1 fixture (for Person C)
│   └── mock_responses.py       # Person C's Day-1 fixture (for Person D)
├── person-a-sensor-ml/         # network sim + attack agent + sensor agent + ML classifier
│   ├── attacker/
│   ├── edge-node/               # reused x3 in docker-compose (edge-node-1/2/3)
│   └── sensor-agent/
├── person-b-analysis/          # correlation engine + MITRE mapper + threat scorer
├── person-c-defender/          # response policy engine + defender agent
├── person-d-dashboard/         # FastAPI backend + React frontend + evaluation module
│   ├── backend/
│   └── frontend/
└── data/                       # shared SQLite volume mount point (gitignored contents)
```

Ownership matches the four-way split: whoever owns a folder is the only
person who should be editing inside it day-to-day. `shared/` and
`docker-compose.yml` are the two files everyone touches, so changes to
those go through a quick heads-up in the group chat or a PR review.

## Why Redis is in here

The design calls for an EventBus that notifies instantly with no polling.
Since each agent is a separate container, they can't share an in-process
Python object, so `shared/eventbus_client.py` wraps Redis pub/sub instead --
same instant-notify behavior, works across containers. SQLite (on the
shared `edgeshield-data` volume) stays the source of truth for actual data;
Redis only carries the "something happened, go look" signal.

## First-time setup

```bash
# 1. Clone
git clone <your-repo-url> edgeshield
cd edgeshield

# 2. Copy env template
cp .env.example .env

# 3. Build everything
docker compose build

# 4. Bring the whole system up
docker compose up
```

The dashboard will be reachable at `http://localhost:3000` and the API at
`http://localhost:8000` once Person D's containers are running.

To work on just your own piece without starting the whole stack:

```bash
docker compose up sensor-agent redis        # Person A example
docker compose up analysis-agent redis      # Person B example
```

## Day-1 independence (no one waits on anyone)

Each fixture script writes directly into the shared SQLite file so you can
build and test your agent in isolation:

```bash
python fixtures/mock_alerts.py data/edgeshield.db          # for Person B
python fixtures/mock_chains_scores.py data/edgeshield.db   # for Person C
python fixtures/mock_responses.py data/edgeshield.db       # for Person D
```

See `docs/schema-agreement.md` for the Day-1 meeting checklist -- this is
the one meeting everyone needs to be at before writing real code.

## Git workflow

Simple branch-per-person model on one repo:

```bash
git checkout -b person-a-sensor-ml     # Person A
git checkout -b person-b-analysis      # Person B
git checkout -b person-c-defender      # Person C
git checkout -b person-d-dashboard     # Person D
```

Work inside your own folder, commit, push your branch, open a PR into
`main`. Since the data flow is one-directional (A -> B -> C -> D) and
everyone talks to SQLite/Redis rather than calling each other's code
directly, merge conflicts should mostly only come up in `shared/` or
`docker-compose.yml`.

```bash
git add .
git commit -m "person-a: initial sensor agent scaffold"
git push -u origin person-a-sensor-ml
```

Then open a pull request on GitHub into `main` and merge once someone else
has glanced at it.

## Integration checkpoints

1. **Day 1** -- schema agreement meeting (everyone).
2. **End of Week 2** -- Person B switches from `fixtures/mock_alerts.py` to
   Person A's real, live Sensor Agent output.
3. **End of Week 5** -- full system integration test, complete loop, all
   four modules connected for the first time.

## Tech stack

Python, Scapy, Suricata, scikit-learn, SQLite, Redis, FastAPI, React,
Docker, Docker Compose, iptables, UNSW-NB15 dataset.
