"""
Sensor Agent (Person A)

Each instance of this container shares the network namespace of ONE edge
node (see docker-compose.yml: network_mode: "service:edge-node-X"), so it
sees exactly the traffic in and out of that node -- three instances run,
one per node, giving full coverage.

Detects all 4 attack types using tuned thresholds against a sliding window
of recent packets per source IP:
    - port_scan:        many distinct destination ports touched
    - brute_force:       many SYN packets to port 22 (repeated attempts)
    - lateral_movement:  a small number of SYN packets to port 22 (one attempt)
    - ddos:              very high total packet volume from one source

Normalized alerts are written to the shared `alerts` table and published
as NEW_ALERT events on the Redis EventBus.
"""

import os
import time
import json
import socket
import sqlite3
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

import redis
from scapy.all import sniff, IP, TCP

SQLITE_PATH = os.environ.get("SQLITE_PATH", "/data/edgeshield.db")
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
SENSOR_LABEL = os.environ.get("SENSOR_LABEL", "unknown-node")
IFACE = os.environ.get("IFACE", "eth0")

WINDOW_SECONDS = 5
ANALYSIS_INTERVAL = 2
DEDUP_SECONDS = 8  # don't re-alert on the same ongoing burst every cycle

# Thresholds tuned against our own Attack Agent's known behavior:
#   port_scan: nmap hits ~1000 ports in well under a second   -> way above 10
#   brute_force: hydra fires 12 rapid attempts to port 22     -> way above 5
#   lateral_movement: paramiko makes exactly ONE attempt      -> below 5, above 0
#   ddos: raw-socket flood sends ~50 pkts/sec to this node    -> way above 100 in a 5s window
PORT_SCAN_PORT_THRESHOLD = 10
BRUTE_FORCE_SYN22_THRESHOLD = 2
DDOS_PACKET_THRESHOLD = 100

SYN_FLAG = 0x02

lock = threading.Lock()
packet_log = defaultdict(deque)  # src_ip -> deque of (timestamp, dst_port, flags)
recent_alerts = {}               # (src_ip, attack_type) -> last alert time
SELF_IP = None


def get_self_ip() -> str:
    """
    Figure out this node's own IP on the shared network. We don't send any
    real traffic here -- connect() on a UDP socket just asks the kernel's
    routing table which local interface/IP it would use, which is exactly
    what we want since this container shares its edge node's network.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def get_db() -> sqlite3.Connection:
    return sqlite3.connect(SQLITE_PATH, check_same_thread=False)


def init_db(conn: sqlite3.Connection):
    with open("/app/shared/schema.sql") as f:
        conn.executescript(f.read())
    conn.commit()


def should_alert(src_ip: str, attack_type: str) -> bool:
    key = (src_ip, attack_type)
    now = time.time()
    if now - recent_alerts.get(key, 0) >= DEDUP_SECONDS:
        recent_alerts[key] = now
        return True
    return False


def log_alert(conn: sqlite3.Connection, r: redis.Redis, attack_type: str,
              source_ip: str, detail: str = ""):
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """INSERT INTO alerts
           (timestamp, source_ip, target_ip, target_node, attack_type, detection_source, raw_details)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (now, source_ip, SELF_IP, SENSOR_LABEL, attack_type, "scapy", detail),
    )
    conn.commit()

    payload = {
        "alert_id": cur.lastrowid,
        "timestamp": now,
        "source_ip": source_ip,
        "target_ip": SELF_IP,
        "target_node": SENSOR_LABEL,
        "attack_type": attack_type,
    }
    r.publish("NEW_ALERT", json.dumps(payload))
    print(f"[sensor-agent:{SENSOR_LABEL}] ALERT attack_type={attack_type} "
          f"source_ip={source_ip} detail={detail}")


def packet_callback(pkt):
    if IP not in pkt or TCP not in pkt:
        return
    src_ip = pkt[IP].src
    if src_ip == SELF_IP:
        return  # ignore our own outgoing replies -- we only care about incoming traffic
    dst_port = pkt[TCP].dport
    flags = int(pkt[TCP].flags)
    with lock:
        packet_log[src_ip].append((time.time(), dst_port, flags))


def prune_old():
    cutoff = time.time() - WINDOW_SECONDS
    with lock:
        for src_ip in list(packet_log.keys()):
            dq = packet_log[src_ip]
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                del packet_log[src_ip]


def analyze_loop(conn: sqlite3.Connection, r: redis.Redis):
    while True:
        time.sleep(ANALYSIS_INTERVAL)
        prune_old()

        with lock:
            snapshot = {src: list(dq) for src, dq in packet_log.items()}

        for src_ip, records in snapshot.items():
            distinct_ports = {rec[1] for rec in records}
            syn22_count = sum(1 for rec in records if rec[1] == 22 and (rec[2] & SYN_FLAG))
            total_count = len(records)

            # Check port diversity FIRST -- a real port scan is high-volume too,
            # so checking raw packet count before port spread misclassifies a
            # fast scan as a DDoS.
            if len(distinct_ports) >= PORT_SCAN_PORT_THRESHOLD:
                if should_alert(src_ip, "port_scan"):
                    log_alert(conn, r, "port_scan", src_ip, detail=f"distinct_ports={len(distinct_ports)}")
            elif total_count >= DDOS_PACKET_THRESHOLD:
                if should_alert(src_ip, "ddos"):
                    log_alert(conn, r, "ddos", src_ip, detail=f"packets_in_window={total_count}")
            elif syn22_count >= BRUTE_FORCE_SYN22_THRESHOLD:
                if should_alert(src_ip, "brute_force"):
                    log_alert(conn, r, "brute_force", src_ip, detail=f"syn22_in_window={syn22_count}")
            elif syn22_count >= 1:
                if should_alert(src_ip, "lateral_movement"):
                    log_alert(conn, r, "lateral_movement", src_ip, detail=f"syn22_in_window={syn22_count}")

def main():
    global SELF_IP
    print(f"[sensor-agent:{SENSOR_LABEL}] starting up, watching interface {IFACE}")

    conn = get_db()
    init_db(conn)
    r = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

    SELF_IP = get_self_ip()
    print(f"[sensor-agent:{SENSOR_LABEL}] own IP detected as {SELF_IP}")

    sniff_thread = threading.Thread(
        target=lambda: sniff(iface=IFACE, prn=packet_callback, store=False, filter="tcp"),
        daemon=True,
    )
    sniff_thread.start()

    analyze_loop(conn, r)


if __name__ == "__main__":
    main()