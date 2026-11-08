"""
Lightweight honeypot HTTP service for EdgeShield isolate_node DNAT targets.
Logs interactions to the shared volume for dashboard / forensics.
"""

import json
import os
from datetime import datetime, timezone

from flask import Flask, request

app = Flask(__name__)
LOG_PATH = os.environ.get("HONEYPOT_LOG", "/data/honeypot_log.jsonl")
BIND_HOST = os.environ.get("HONEYPOT_BIND", "0.0.0.0")
BIND_PORT = int(os.environ.get("HONEYPOT_PORT", "80"))


def _log_event(event: dict):
    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def catch_all(path):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "remote_addr": request.remote_addr,
        "method": request.method,
        "path": "/" + path,
        "headers": {k: v for k, v in request.headers.items()},
        "body_preview": (request.get_data(as_text=True) or "")[:512],
    }
    _log_event(event)
    return (
        json.dumps(
            {
                "service": "edge-node-api",
                "status": "ok",
                "node": "edge-sim",
                "message": "request accepted",
            }
        ),
        200,
        {"Content-Type": "application/json"},
    )


if __name__ == "__main__":
    app.run(host=BIND_HOST, port=BIND_PORT)
