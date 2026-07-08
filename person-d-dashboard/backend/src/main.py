"""
Dashboard backend (Person D)

Pure read layer: exposes REST endpoints for alerts, chains, scores,
responses, node health, and evaluation metrics, plus a WebSocket that
pushes live events to the frontend every 2 seconds. No business logic
lives here -- it only reads SQLite and serves JSON.

This is a placeholder so `docker compose build` succeeds. Real endpoints
come after Persons A-C have real data flowing.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="EdgeShield Dashboard API")

# Without this, the browser blocks requests from the frontend (port 3000)
# to this API (port 8000) since they're different origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/alerts")
def get_alerts():
    return {"alerts": [], "note": "placeholder -- wire up to SQLite alerts table"}


@app.get("/chains")
def get_chains():
    return {"chains": [], "note": "placeholder -- wire up to SQLite attack_chains table"}


@app.get("/scores")
def get_scores():
    return {"scores": [], "note": "placeholder -- wire up to SQLite threat_scores table"}


@app.get("/responses")
def get_responses():
    return {"responses": [], "note": "placeholder -- wire up to SQLite responses table"}
