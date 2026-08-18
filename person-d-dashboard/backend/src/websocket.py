import asyncio
import json
import os

import redis
from fastapi import WebSocket


REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = 6379


EVENT_TYPES = [
    "NEW_ALERT",
    "ML_PREDICTION",
    "CHAIN_DETECTED",
    "SCORE_COMPUTED",
    "RESPONSE_EXECUTED",
]


async def redis_event_listener(websocket: WebSocket):

    """
    Listen to Redis events and forward them
    to the connected React dashboard.
    """

    client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True
    )

    pubsub = client.pubsub()

    pubsub.subscribe(*EVENT_TYPES)

    try:

        while True:

            message = pubsub.get_message(
                ignore_subscribe_messages=True
            )

            if message:

                event_type = message["channel"]
                payload = message["data"]

                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError:
                    payload = {
                        "message": payload
                    }

                await websocket.send_json({
                    "event_type": event_type,
                    "payload": payload
                })

            await asyncio.sleep(0.1)

    except Exception as e:

        print(
            f"[websocket] Redis listener stopped: {e}"
        )

    finally:

        pubsub.close()
        client.close()