"""
Offline training script for the ML classifier (Person A).

Run this AFTER collecting data: cross-references every feature window the
Sensor Agent logged (training_data.csv) against the Attack Agent's ground
truth log to assign the correct label, then trains and saves a Random
Forest on the same 12 features the Sensor Agent computes live -- this is
what makes the live predictions actually meaningful.

Usage (from inside a container that has access to /data, e.g.):
    docker compose exec sensor-agent-1 python src/train_model.py
"""

import csv
import json
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

TRAINING_DATA_PATH = "/data/training_data.csv"
GROUND_TRUTH_PATH = "/data/ground_truth.jsonl"
MODEL_OUTPUT_PATH = "/app/src/model.joblib"
LABEL_TOLERANCE_SECONDS = 8  # matches sensor window + a small buffer

FEATURE_COLUMNS = [
    "total_packets", "packet_rate", "distinct_dst_ports", "syn_count",
    "syn_ratio", "total_bytes", "avg_byte_size", "mean_inter_arrival",
    "std_inter_arrival", "min_inter_arrival", "max_inter_arrival", "mean_ttl",
]


def load_ground_truth():
    events = []
    with open(GROUND_TRUTH_PATH) as f:
        for line in f:
            entry = json.loads(line)
            epoch = datetime.fromisoformat(entry["timestamp"]).timestamp()
            events.append({"epoch": epoch, "stage": entry["stage"], "target": entry["target"]})
    return events


def label_row(window_end_ts, target_node, events):
    best_match = None
    best_diff = LABEL_TOLERANCE_SECONDS
    for ev in events:
        if ev["target"] != target_node:
            continue
        diff = abs(window_end_ts - ev["epoch"])
        if diff <= best_diff:
            best_diff = diff
            best_match = ev["stage"]
    return best_match if best_match else "normal"


def main():
    events = load_ground_truth()
    print(f"Loaded {len(events)} ground truth events")

    X, y = [], []
    skipped = 0
    with open(TRAINING_DATA_PATH) as f:
        reader = csv.reader(f)
        for row in reader:
            try:
                window_end_ts = float(row[0])
                target_node = row[2]
                feature_values = [float(v) for v in row[3:3 + len(FEATURE_COLUMNS)]]
            except (ValueError, IndexError):
                skipped += 1
                continue
            label = label_row(window_end_ts, target_node, events)
            X.append(feature_values)
            y.append(label)

    print(f"Loaded {len(X)} feature rows (skipped {skipped} malformed/header rows)")
    label_counts = {label: y.count(label) for label in set(y)}
    print(f"Label distribution: {label_counts}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"Test accuracy: {accuracy_score(y_test, y_pred):.3f}")
    print(classification_report(y_test, y_pred, zero_division=0))

    joblib.dump(model, MODEL_OUTPUT_PATH)
    print(f"Model saved to {MODEL_OUTPUT_PATH}")


if __name__ == "__main__":
    main()