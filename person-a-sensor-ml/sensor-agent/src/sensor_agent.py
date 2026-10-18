"""
Sensor Agent (Person A)

Two parallel detection mechanisms, as required:
    1. Scapy packet sniffer with threshold-based classifiers
    2. Suricata alert reader (tails eve.json, custom rules tuned to our
       4 attack types)

Both are normalized into one unified alert format in the shared `alerts`
table. If both sources detect the same event, the row is merged into one
with detection_source='both' instead of creating two separate alerts.

Also runs the ML classifier (Random Forest, trained offline -- see
train_model.py) on every traffic window and logs predictions separately.
"""

import os
import csv
import json
import time
import socket
import sqlite3
import statistics
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

import redis
import joblib
from scapy.all import sniff, IP, TCP

SQLITE_PATH = os.environ.get("SQLITE_PATH", "/data/edgeshield.db")
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
SENSOR_LABEL = os.environ.get("SENSOR_LABEL", "unknown-node")
IFACE = os.environ.get("IFACE", "eth0")
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.joblib")
TRAINING_DATA_PATH = "/data/training_data.csv"
SURICATA_EVE_PATH = "/var/log/suricata/eve.json"

WINDOW_SECONDS = 5
ANALYSIS_INTERVAL = 2
DEDUP_SECONDS = 8

PORT_SCAN_PORT_THRESHOLD = 10
BRUTE_FORCE_SYN22_THRESHOLD = 2
DDOS_PACKET_THRESHOLD = 100

SYN_FLAG = 0x02

FEATURE_COLUMNS = [
    "total_packets", "packet_rate", "distinct_dst_ports", "syn_count",
    "syn_ratio", "total_bytes", "avg_byte_size", "mean_inter_arrival",
    "std_inter_arrival", "min_inter_arrival", "max_inter_arrival", "mean_ttl",
]

# Maps our custom Suricata rule SIDs (local.rules) to our 4 attack types.
SURICATA_SID_MAP = {
    1000001: "port_scan",
    1000002: "brute_force",
    1000003: "lateral_movement",
    1000004: "ddos",
}

# Used to resolve conflicts when multiple signatures fire for the same
# source close together -- keep only the highest-precedence classification,
# same ordering logic as the Scapy classifier's if/elif chain.
PRECEDENCE = {"port_scan": 4, "ddos": 3, "brute_force": 2, "lateral_movement": 1}

lock = threading.Lock()
packet_log = defaultdict(deque)  # src_ip -> deque of (timestamp, dst_port, flags, length, ttl)
recent_alerts = {}               # (src_ip, attack_type) -> last alert time
db_lock = threading.Lock()       # guards the merge-check-then-write sequence across threads
SELF_IP = None
REDIS_IP = None
MODEL = None


def get_self_ip() -> str:
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


def should_alert(src_ip: str, attack_type: str, detection_source: str) -> bool:
    key = (src_ip, attack_type, detection_source)
    now = time.time()
    if now - recent_alerts.get(key, 0) >= DEDUP_SECONDS:
        recent_alerts[key] = now
        return True
    return False


def higher_precedence_recently_alerted(src_ip: str, attack_type: str) -> bool:
    now = time.time()
    my_rank = PRECEDENCE.get(attack_type, 0)
    for (src, atype, _source), ts in recent_alerts.items():
        if src == src_ip and now - ts < DEDUP_SECONDS and PRECEDENCE.get(atype, 0) >= my_rank and atype != attack_type:
            return True
    return False


def record_alert(conn: sqlite3.Connection, r: redis.Redis, attack_type: str,
                  source_ip: str, detection_source: str, detail: str = ""):
    """
    Writes one alert, merging with an existing recent row from the OTHER
    detection source instead of creating a duplicate. This is the shared
    path both the Scapy classifier and the Suricata reader call into.
    """
    now = datetime.now(timezone.utc).isoformat()
    cutoff = (datetime.now(timezone.utc).timestamp() - DEDUP_SECONDS)

    with db_lock:
        row = conn.execute(
            """SELECT id, detection_source FROM alerts
               WHERE source_ip = ? AND target_node = ? AND attack_type = ?
               ORDER BY id DESC LIMIT 1""",
            (source_ip, SENSOR_LABEL, attack_type),
        ).fetchone()

        if row:
            alert_id, existing_source = row
            # Only merge if the existing row is recent enough and from the OTHER source.
            ts_row = conn.execute("SELECT timestamp FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            row_epoch = datetime.fromisoformat(ts_row[0]).timestamp()
            if row_epoch >= cutoff and existing_source != detection_source and existing_source != "both":
                conn.execute("UPDATE alerts SET detection_source = 'both' WHERE id = ?", (alert_id,))
                conn.commit()
                print(f"[sensor-agent:{SENSOR_LABEL}] MERGED alert id={alert_id} "
                      f"attack_type={attack_type} source_ip={source_ip} -> detection_source=both")
                return
            if row_epoch >= cutoff:
                return  # already recorded recently by this same source or already 'both'

        cur = conn.execute(
            """INSERT INTO alerts
               (timestamp, source_ip, target_ip, target_node, attack_type, detection_source, raw_details)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (now, source_ip, SELF_IP, SENSOR_LABEL, attack_type, detection_source, detail),
        )
        conn.commit()
        alert_id = cur.lastrowid

    payload = {
        "alert_id": alert_id, "timestamp": now, "source_ip": source_ip,
        "target_ip": SELF_IP, "target_node": SENSOR_LABEL, "attack_type": attack_type,
    }
    r.publish("NEW_ALERT", json.dumps(payload))
    print(f"[sensor-agent:{SENSOR_LABEL}] ALERT({detection_source}) attack_type={attack_type} "
          f"source_ip={source_ip} detail={detail}")


def log_ml_prediction(conn, r, source_ip, predicted_class, confidence, features):
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """INSERT INTO ml_predictions
           (timestamp, window_start, window_end, target_node, predicted_class, confidence, features_json)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (now, None, now, SENSOR_LABEL, predicted_class, confidence, json.dumps(features)),
    )
    conn.commit()
    payload = {
        "prediction_id": cur.lastrowid, "timestamp": now, "target_node": SENSOR_LABEL,
        "source_ip": source_ip, "predicted_class": predicted_class, "confidence": confidence,
    }
    r.publish("ML_PREDICTION", json.dumps(payload))
    print(f"[sensor-agent:{SENSOR_LABEL}] ML_PREDICTION class={predicted_class} "
          f"confidence={confidence:.2f} src={source_ip}")


def log_training_row(window_end_ts, src_ip, features):
    with open(TRAINING_DATA_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([window_end_ts, src_ip, SENSOR_LABEL] + [features[c] for c in FEATURE_COLUMNS])


# ---------------------------------------------------------------------------
# Detection mechanism 1: Scapy sniffer
# ---------------------------------------------------------------------------

def packet_callback(pkt):
    if IP not in pkt or TCP not in pkt:
        return
    src_ip = pkt[IP].src
    if src_ip == SELF_IP or src_ip == REDIS_IP:
        return
    dst_port = pkt[TCP].dport
    flags = int(pkt[TCP].flags)
    length = len(pkt)
    ttl = pkt[IP].ttl
    with lock:
        packet_log[src_ip].append((time.time(), dst_port, flags, length, ttl))


def prune_old():
    cutoff = time.time() - WINDOW_SECONDS
    with lock:
        for src_ip in list(packet_log.keys()):
            dq = packet_log[src_ip]
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                del packet_log[src_ip]

def current_distinct_ports(src_ip: str) -> int:
    """Cross-check against the Scapy sniffer's own live window for this
    source -- used to catch cases where Suricata's single-packet rules
    (brute_force, lateral_movement) fire on a packet that's actually just
    one part of a broader port scan already visible to Scapy."""
    with lock:
        records = packet_log.get(src_ip, [])
        return len({rec[1] for rec in records})


def compute_features(records):
    timestamps = [rec[0] for rec in records]
    ports = [rec[1] for rec in records]
    flags_list = [rec[2] for rec in records]
    lengths = [rec[3] for rec in records]
    ttls = [rec[4] for rec in records]

    total_packets = len(records)
    span = max(timestamps) - min(timestamps)
    span = span if span > 0 else 0.001
    packet_rate = total_packets / span
    distinct_dst_ports = len(set(ports))
    syn_count = sum(1 for f in flags_list if f & SYN_FLAG)
    syn_ratio = syn_count / total_packets
    total_bytes = sum(lengths)
    avg_byte_size = total_bytes / total_packets

    sorted_ts = sorted(timestamps)
    inter_arrivals = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]
    if inter_arrivals:
        mean_ia = statistics.mean(inter_arrivals)
        std_ia = statistics.pstdev(inter_arrivals) if len(inter_arrivals) > 1 else 0.0
        min_ia = min(inter_arrivals)
        max_ia = max(inter_arrivals)
    else:
        mean_ia = std_ia = min_ia = max_ia = 0.0

    mean_ttl = statistics.mean(ttls) if ttls else 0.0

    return {
        "total_packets": total_packets, "packet_rate": packet_rate,
        "distinct_dst_ports": distinct_dst_ports, "syn_count": syn_count,
        "syn_ratio": syn_ratio, "total_bytes": total_bytes,
        "avg_byte_size": avg_byte_size, "mean_inter_arrival": mean_ia,
        "std_inter_arrival": std_ia, "min_inter_arrival": min_ia,
        "max_inter_arrival": max_ia, "mean_ttl": mean_ttl,
    }


def analyze_loop(conn, r):
    while True:
        time.sleep(ANALYSIS_INTERVAL)
        prune_old()

        with lock:
            snapshot = {src: list(dq) for src, dq in packet_log.items()}

        for src_ip, records in snapshot.items():
            if not records:
                continue

            features = compute_features(records)
            log_training_row(time.time(), src_ip, features)

            distinct_ports = features["distinct_dst_ports"]
            syn22_count = sum(1 for rec in records if rec[1] == 22 and (rec[2] & SYN_FLAG))
            syn_total_count = features["syn_count"]

            if distinct_ports >= PORT_SCAN_PORT_THRESHOLD:
                if not higher_precedence_recently_alerted(src_ip, "port_scan") and should_alert(src_ip, "port_scan", "scapy"):
                    record_alert(conn, r, "port_scan", src_ip, "scapy", detail=f"distinct_ports={distinct_ports}")
            elif syn_total_count >= DDOS_PACKET_THRESHOLD:
                if not higher_precedence_recently_alerted(src_ip, "ddos") and should_alert(src_ip, "ddos", "scapy"):
                    record_alert(conn, r, "ddos", src_ip, "scapy", detail=f"syn_packets_in_window={syn_total_count}")
            elif syn22_count >= BRUTE_FORCE_SYN22_THRESHOLD:
                if not higher_precedence_recently_alerted(src_ip, "brute_force") and should_alert(src_ip, "brute_force", "scapy"):
                    record_alert(conn, r, "brute_force", src_ip, "scapy", detail=f"syn22_in_window={syn22_count}")
            elif syn22_count >= 1:
                if not higher_precedence_recently_alerted(src_ip, "lateral_movement") and should_alert(src_ip, "lateral_movement", "scapy"):
                    record_alert(conn, r, "lateral_movement", src_ip, "scapy", detail=f"syn22_in_window={syn22_count}")

            if MODEL is not None:
                vector = [features[c] for c in FEATURE_COLUMNS]
                proba = MODEL.predict_proba([vector])[0]
                classes = MODEL.classes_
                best_idx = max(range(len(proba)), key=lambda i: proba[i])
                log_ml_prediction(conn, r, src_ip, classes[best_idx], float(proba[best_idx]), features)


# ---------------------------------------------------------------------------
# Detection mechanism 2: Suricata alert reader
# ---------------------------------------------------------------------------

def tail_suricata_log(r: redis.Redis):
    """
    Runs in its own thread with its own DB connection (SQLite connections
    shouldn't be shared across threads). Waits for Suricata's eve.json to
    exist, then tails it like `tail -f`, parsing each new alert line.
    """
    conn = get_db()

    while not os.path.isfile(SURICATA_EVE_PATH):
        time.sleep(1)

    print(f"[sensor-agent:{SENSOR_LABEL}] Suricata log reader started, watching {SURICATA_EVE_PATH}")

    with open(SURICATA_EVE_PATH, "r") as f:
        f.seek(0, os.SEEK_END)  # only read NEW lines from here on
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            sid = event.get("alert", {}).get("signature_id")
            attack_type = SURICATA_SID_MAP.get(sid)
            if attack_type is None:
                continue

            src_ip = event.get("src_ip")
            if not src_ip or src_ip == SELF_IP:
                continue

            reclassified_note = ""
            if attack_type in ("brute_force", "lateral_movement"):
                if current_distinct_ports(src_ip) >= PORT_SCAN_PORT_THRESHOLD:
                    reclassified_note = f" (reclassified from {attack_type})"
                    attack_type = "port_scan"

            if higher_precedence_recently_alerted(src_ip, attack_type):
                continue
            if not should_alert(src_ip, attack_type, "suricata"):
                continue

            record_alert(conn, r, attack_type, src_ip, "suricata",
                         detail=f"sid={sid} signature={event.get('alert', {}).get('signature')}{reclassified_note}")


def main():
    global SELF_IP, MODEL, REDIS_IP
    print(f"[sensor-agent:{SENSOR_LABEL}] starting up, watching interface {IFACE}")

    conn = get_db()
    init_db(conn)
    r = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

    SELF_IP = get_self_ip()
    REDIS_IP = socket.gethostbyname(REDIS_HOST)
    print(f"[sensor-agent:{SENSOR_LABEL}] own IP detected as {SELF_IP}, excluding redis at {REDIS_IP}")

    if os.path.isfile(MODEL_PATH):
        MODEL = joblib.load(MODEL_PATH)
        print(f"[sensor-agent:{SENSOR_LABEL}] loaded ML model from {MODEL_PATH}")
    else:
        print(f"[sensor-agent:{SENSOR_LABEL}] no ML model found yet at {MODEL_PATH} -- "
              f"skipping ML predictions until trained (see train_model.py)")

    sniff_thread = threading.Thread(
        target=lambda: sniff(iface=IFACE, prn=packet_callback, store=False, filter="tcp"),
        daemon=True,
    )
    sniff_thread.start()

    suricata_thread = threading.Thread(target=tail_suricata_log, args=(r,), daemon=True)
    suricata_thread.start()

    analyze_loop(conn, r)


if __name__ == "__main__":
    main()