import os
import json
import sqlite3
import asyncio
from pathlib import Path

import redis

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# PATH CONFIGURATION
# ============================================================

# Project root:
# MajorProject/
#
# backend is:
# MajorProject/person-d-dashboard/backend/
#
# Database is expected at:
# MajorProject/data/edgeshield.db

PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_DATABASE_PATH = (
    PROJECT_ROOT / "data" / "edgeshield.db"
)


DATABASE_PATH = os.getenv(
    "SQLITE_PATH",
    str(DEFAULT_DATABASE_PATH)
)


# ============================================================
# REDIS CONFIGURATION
# ============================================================

REDIS_HOST = os.getenv(
    "REDIS_HOST",
    "localhost"
)

REDIS_PORT = int(
    os.getenv(
        "REDIS_PORT",
        "6379"
    )
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="EdgeShield Dashboard API",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(

    CORSMiddleware,

    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"]

)


# ============================================================
# DATABASE HELPER
# ============================================================

def get_db_connection():

    conn = sqlite3.connect(
        DATABASE_PATH
    )

    conn.row_factory = sqlite3.Row

    return conn


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "ok",
        "database": DATABASE_PATH
    }


# ============================================================
# ALERTS
# ============================================================

@app.get("/alerts")
def get_alerts():

    conn = get_db_connection()

    try:

        rows = conn.execute(
            """
            SELECT
                id,
                timestamp,
                source_ip,
                target_ip,
                target_node,
                attack_type,
                detection_source,
                mitre_tactic,
                raw_details
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT 50
            """
        ).fetchall()

        return {
            "alerts": [
                dict(row)
                for row in rows
            ]
        }

    finally:

        conn.close()


# ============================================================
# ATTACK CHAINS
# ============================================================

@app.get("/chains")
def get_chains():

    conn = get_db_connection()

    try:

        rows = conn.execute(
            """
            SELECT
                id,
                chain_id,
                alert_ids,
                mitre_sequence,
                start_time,
                last_updated,
                status
            FROM attack_chains
            ORDER BY last_updated DESC
            """
        ).fetchall()

        return {
            "chains": [
                dict(row)
                for row in rows
            ]
        }

    finally:

        conn.close()


# ============================================================
# THREAT SCORES
# ============================================================

@app.get("/scores")
def get_scores():

    conn = get_db_connection()

    try:

        rows = conn.execute(
            """
            SELECT
                id,
                chain_id,
                timestamp,
                score,
                severity_label,
                factors_json
            FROM threat_scores
            ORDER BY timestamp ASC
            """
        ).fetchall()

        return {
            "scores": [
                dict(row)
                for row in rows
            ]
        }

    finally:

        conn.close()


# ============================================================
# RESPONSES
# ============================================================

@app.get("/responses")
def get_responses():

    conn = get_db_connection()

    try:

        rows = conn.execute(
            """
            SELECT
                id,
                chain_id,
                timestamp,
                action_type,
                target,
                rollback_command,
                status,
                rolled_back_at
            FROM responses
            ORDER BY timestamp DESC
            """
        ).fetchall()

        return {
            "responses": [
                dict(row)
                for row in rows
            ]
        }

    finally:

        conn.close()


# ============================================================
# NODE HEALTH
# ============================================================

@app.get("/node-health")
def get_node_health():

    conn = get_db_connection()

    try:

        rows = conn.execute(
            """
            SELECT
                id,
                node_name,
                status,
                cpu_usage,
                memory_usage,
                last_updated
            FROM node_health
            ORDER BY node_name
            """
        ).fetchall()

        return {
            "nodes": [
                dict(row)
                for row in rows
            ]
        }

    finally:

        conn.close()


# ============================================================
# EVALUATION METRICS
# ============================================================

@app.get("/metrics")
def get_metrics():

    conn = get_db_connection()

    try:

        total_alerts = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM alerts
            """
        ).fetchone()["count"]


        total_chains = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM attack_chains
            """
        ).fetchone()["count"]


        total_responses = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM responses
            """
        ).fetchone()["count"]


        avg_confidence = conn.execute(
            """
            SELECT AVG(confidence) AS average
            FROM ml_predictions
            """
        ).fetchone()["average"]


        if avg_confidence is None:

            avg_confidence = 0


        return {

            "total_alerts":
                total_alerts,

            "total_chains":
                total_chains,

            "total_responses":
                total_responses,

            "average_ml_confidence":
                avg_confidence

        }

    finally:

        conn.close()


# ============================================================
# REDIS
# ============================================================

def create_redis_client():

    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True
    )


# ============================================================
# WEBSOCKET
# ============================================================

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket
):

    await websocket.accept()

    print(
        "[WebSocket] Frontend connected"
    )

    redis_client = None
    pubsub = None

    try:

        redis_client = create_redis_client()

        redis_client.ping()

        print(
            "[WebSocket] Redis connected"
        )


        pubsub = redis_client.pubsub()


        pubsub.subscribe(
            "NEW_ALERT",
            "ML_PREDICTION",
            "CHAIN_DETECTED",
            "SCORE_COMPUTED",
            "RESPONSE_EXECUTED"
        )


        print(
            "[WebSocket] "
            "Subscribed to Redis events"
        )


        while True:

            # Check Redis for a new event.

            message = await asyncio.to_thread(
                pubsub.get_message,
                ignore_subscribe_messages=True,
                timeout=1.0
            )


            if message:

                try:

                    event_type = (
                        message["channel"]
                    )

                    raw_data = (
                        message["data"]
                    )


                    try:

                        payload = json.loads(
                            raw_data
                        )

                    except (
                        json.JSONDecodeError,
                        TypeError
                    ):

                        payload = {
                            "raw": raw_data
                        }


                    event = {

                        "event_type":
                            event_type,

                        "payload":
                            payload

                    }


                    await websocket.send_json(
                        event
                    )


                    print(
                        "[WebSocket] "
                        f"Sent event: {event_type}"
                    )


                except Exception as error:

                    print(
                        "[WebSocket] "
                        f"Event error: {error}"
                    )


            await asyncio.sleep(0.1)


    except WebSocketDisconnect:

        print(
            "[WebSocket] "
            "Frontend disconnected"
        )


    except Exception as error:

        print(
            "[WebSocket] Error:",
            error
        )


        try:

            await websocket.close()

        except Exception:

            pass


    finally:

        if pubsub:

            try:

                pubsub.close()

            except Exception:

                pass


        if redis_client:

            try:

                redis_client.close()

            except Exception:

                pass