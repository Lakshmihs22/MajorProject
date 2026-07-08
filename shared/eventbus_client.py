"""
Shared EventBus client for EdgeShield.

Because each agent runs in its own Docker container, we can't share an
in-process Python pub/sub object across them. This wraps Redis pub/sub
instead, which gives every agent the same "no polling, instant notify"
behavior described in the project design, just over the network.

Event types (keep these names identical across all four people's code):
    NEW_ALERT        - fired by Person A's Sensor Agent
    ML_PREDICTION    - fired by Person A's ML classifier
    CHAIN_DETECTED    - fired by Person B's Correlation Engine
    SCORE_COMPUTED   - fired by Person B's Threat Scorer
    RESPONSE_EXECUTED - fired by Person C's Defender Agent
"""

import json
import redis


class EventBus:
    NEW_ALERT = "NEW_ALERT"
    ML_PREDICTION = "ML_PREDICTION"
    CHAIN_DETECTED = "CHAIN_DETECTED"
    SCORE_COMPUTED = "SCORE_COMPUTED"
    RESPONSE_EXECUTED = "RESPONSE_EXECUTED"

    def __init__(self, host="redis", port=6379):
        self.client = redis.Redis(host=host, port=port, decode_responses=True)
        self.pubsub = self.client.pubsub()

    def publish(self, event_type: str, payload: dict):
        self.client.publish(event_type, json.dumps(payload))

    def subscribe(self, event_types: list):
        self.pubsub.subscribe(*event_types)
        return self.pubsub

    def listen(self):
        """Blocking generator: yields (event_type, payload_dict) forever."""
        for message in self.pubsub.listen():
            if message["type"] == "message":
                yield message["channel"], json.loads(message["data"])


if __name__ == "__main__":
    # Quick manual test: run this inside any container to confirm Redis is reachable.
    bus = EventBus()
    bus.publish(EventBus.NEW_ALERT, {"test": "hello from eventbus_client.py"})
    print("Published test event. Redis connection OK.")
