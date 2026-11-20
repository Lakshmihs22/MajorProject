"""
Run iptables inside lab-traffic-source (or other) container namespaces via Docker.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
from typing import List, Optional, Tuple

log = logging.getLogger("defender-enforcer")

Step = Tuple[str, str]  # (container_name, shell_command)

DOCKER_SOCK_PATH = "/var/run/docker.sock"
ENFORCER_IMAGE = os.environ.get("ENFORCER_IMAGE", "edgeshield-defender:latest")
ATTACKER_CONTAINER = os.environ.get("ATTACKER_CONTAINER", "lab-traffic-source")

_client = None
_socket_available: Optional[bool] = None


def socket_available() -> bool:
    global _socket_available
    if _socket_available is None:
        _socket_available = os.path.exists(DOCKER_SOCK_PATH)
    return bool(_socket_available)


def _docker_client():
    global _client
    if _client is not None:
        return _client
    if not socket_available():
        return None
    try:
        import docker

        _client = docker.from_env()
        _client.ping()
        log.info("[enforcer] Docker socket connected")
        return _client
    except Exception as exc:
        log.warning("[enforcer] Docker SDK unavailable: %s", exc)
        return None


def format_steps(steps: List[Step]) -> str:
    return json.dumps(steps)


def parse_steps(raw: Optional[str]) -> List[Step]:
    if not raw:
        return []
    raw = raw.strip()
    if raw.startswith("["):
        try:
            data = json.loads(raw)
            return [(str(ns), str(cmd)) for ns, cmd in data]
        except json.JSONDecodeError:
            log.warning("[enforcer] invalid JSON rollback steps")
            return []
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    return [(ATTACKER_CONTAINER, cmd) for cmd in parts]


def _run_via_container_exec(steps: List[Step]) -> bool:
    client = _docker_client()
    if client is None:
        return False
    ok = True
    for namespace, cmd in steps:
        log.info("[enforcer] exec ns=%s: %s", namespace, cmd)
        try:
            container = client.containers.get(namespace)
            exit_code, output = container.exec_run(["sh", "-c", cmd], privileged=True)
            if exit_code != 0:
                text = (output or b"").decode(errors="replace").strip()
                log.warning(
                    "[enforcer] exec exit=%s ns=%s stderr/stdout=%s",
                    exit_code,
                    namespace,
                    text[:500],
                )
                ok = False
        except Exception as exc:
            log.warning("[enforcer] exec failed ns=%s: %s", namespace, exc)
            ok = False
    return ok


def _run_via_sdk(steps: List[Step]) -> bool:
    client = _docker_client()
    if client is None:
        return False
    ok = True
    for namespace, cmd in steps:
        log.info("[enforcer] RUN ephemeral ns=%s: %s", namespace, cmd)
        try:
            client.containers.run(
                ENFORCER_IMAGE,
                command=["sh", "-c", cmd],
                network_mode=f"container:{namespace}",
                cap_add=["NET_ADMIN"],
                privileged=True,
                remove=True,
                detach=False,
            )
        except Exception as exc:
            log.warning("[enforcer] step failed ns=%s: %s", namespace, exc)
            ok = False
    return ok


def _run_via_cli(steps: List[Step]) -> bool:
    ok = True
    for namespace, cmd in steps:
        remote = f"docker exec {shlex.quote(namespace)} sh -c {shlex.quote(cmd)}"
        log.info("[enforcer] RUN (cli) ns=%s: %s", namespace, cmd)
        try:
            result = subprocess.run(
                remote,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                log.warning(
                    "[enforcer] exit=%d stderr=%s",
                    result.returncode,
                    (result.stderr or result.stdout or "").strip(),
                )
                ok = False
        except Exception as exc:
            log.error("[enforcer] cli error: %s", exc)
            ok = False
    return ok


def run_steps(steps: List[Step]) -> bool:
    if not steps:
        return True
    if socket_available():
        if _run_via_container_exec(steps):
            return True
        if _run_via_cli(steps):
            return True
        return _run_via_sdk(steps)
    log.warning(
        "[enforcer] Docker socket unavailable — rules run in local namespace (no live block)"
    )
    ok = True
    for _ns, cmd in steps:
        try:
            subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        except Exception as exc:
            log.error("[enforcer] local run failed: %s", exc)
            ok = False
    return ok


def get_container_stats(container_name: str) -> Optional[dict]:
    """Return Docker stats dict for edge telemetry (Person C → dashboard)."""
    client = _docker_client()
    if client is None:
        return None
    try:
        container = client.containers.get(container_name)
        return container.stats(stream=False)
    except Exception as exc:
        log.debug("[enforcer] stats failed for %s: %s", container_name, exc)
        return None