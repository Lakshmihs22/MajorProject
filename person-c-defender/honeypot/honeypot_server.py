"""
Lightweight honeypot HTTP service for EdgeShield isolate_node DNAT targets.
Logs interactions to the shared volume for dashboard / forensics.
Request headers and bodies are redacted — no secrets or payloads stored verbatim.
"""

import json
import os
from datetime import datetime, timezone

from flask import Flask, request

app = Flask(__name__)
LOG_PATH = os.environ.get("HONEYPOT_LOG", "/data/honeypot_log.jsonl")
BIND_HOST = os.environ.get("HONEYPOT_BIND", "0.0.0.0")
BIND_PORT = int(os.environ.get("HONEYPOT_PORT", "80"))

_SENSITIVE_HEADER_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
        "x-csrf-token",
    }
)


def _redact_headers(headers) -> dict:
    redacted = {}
    for key, value in headers.items():
        if key.lower() in _SENSITIVE_HEADER_KEYS:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def _redact_body(raw: bytes) -> str:
    if not raw:
        return ""
    return f"[REDACTED bytes={len(raw)}]"


def _log_event(event: dict):
    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def catch_all(path):
    raw_body = request.get_data()
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "remote_addr": request.remote_addr,
        "method": request.method,
        "path": "/" + path,
        "headers": _redact_headers(request.headers),
        "body_preview": _redact_body(raw_body),
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