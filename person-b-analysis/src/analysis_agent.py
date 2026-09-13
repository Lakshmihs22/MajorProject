"""
Person B: Analysis Agent

Responsibilities:
    1. MITRE Tactic Mapper
    2. Correlation Engine
    3. Threat Scorer

This file runs independent of Person A. It can process the Day-1 fixture rows
from the shared SQLite database and also subscribe to NEW_ALERT events from the
shared Redis EventBus when Person A later publishes them.
"""

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from shared.eventbus_client import EventBus


logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("analysis-agent")


ATTACK_TO_MITRE = {
    "port_scan": "TA0043",
    "brute_force": "TA0006",
    "lateral_movement": "TA0008",
    "ddos": "TA0040",
}

ATTACK_WEIGHTS = {
    "port_scan": 10,
    "brute_force": 20,
    "lateral_movement": 25,
    "ddos": 25,
}

PREREQUISITE = ["port_scan", "brute_force", "lateral_movement"]


class AnalysisAgent:
    def __init__(self):
        # Match the project convention: SQLite path is environment-driven.
        self.database_path = os.getenv("SQLITE_PATH", "/data/edgeshield.db")
        # Local quick-development fallback documented in README and fixtures.
        if not os.path.exists(self.database_path):
            self.database_path = os.getenv("SQLITE_PATH", "data/edgeshield.db")

        # Match docker-compose service environment variables.
        self.redis_host = os.getenv("REDIS_HOST", "redis")
        self.redis_port = int(os.getenv("REDIS_PORT", "6379"))

        # Shared directory path for the container context is copied in the Dockerfile.
        # On the local host, the repository root is used.
        parent = Path(self.database_path).parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # Make sure the SQLite schema is available before we begin.
        self.ensure_schema()

        # Shared event bus object.
        self.bus = EventBus(host=self.redis_host, port=self.redis_port)

        # De-duplicate event handling, so NEW_ALERT duplicates do not create duplicate alerts.
        self.alert_seen_keys = set()

    def ensure_schema(self):
        try:
            conn = sqlite3.connect(self.database_path)
            with open("shared/schema.sql", "r", encoding="utf-8") as f:
                conn.executescript(f.read())
            conn.commit()
            conn.close()
            logger.info("Schema ready at %s", self.database_path)
        except Exception as exc:
            logger.warning("Schema preparation warning: %s", exc)

    def connect(self):
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        return conn

    def now_iso(self):
        return datetime.now(timezone.utc).isoformat()

    def parse_ts(self, value):
        try:
            if isinstance(value, str):
                if value.endswith("Z"):
                    value = value.replace("Z", "+00:00")
                return datetime.fromisoformat(value)
            return value
        except Exception:
            return datetime.utcnow()

    def normalize_timestamp(self, value):
        try:
            dt = self.parse_ts(value)
            # Ensure ISO 8601 UTC string with +00:00
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            return self.now_iso()

    def map_mitre_tactics(self):
        """Backfill MITRE tactic assignments for any attack_type already known in the repo."""
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT id, attack_type, mitre_tactic FROM alerts ORDER BY timestamp ASC"
            ).fetchall()
            updated = 0
            for row in rows:
                attack_type = row["attack_type"]
                mapped = ATTACK_TO_MITRE.get(attack_type)
                if mapped and row["mitre_tactic"] != mapped:
                    conn.execute(
                        "UPDATE alerts SET mitre_tactic = ? WHERE id = ?",
                        (mapped, row["id"]),
                    )
                    updated += 1
                    logger.info("Mapped alert %s attack_type %s -> %s", row["id"], attack_type, mapped)
                elif mapped:
                    logger.debug("Alert %s already mapped to %s", row["id"], mapped)
                else:
                    logger.warning("Unknown attack_type %s for alert %s", attack_type, row["id"])
            conn.commit()
            logger.info("MITRE mapping pass finished; updated %s alerts", updated)
        except Exception as exc:
            conn.rollback()
            logger.exception("MITRE mapping failed: %s", exc)
        finally:
            conn.close()

    def correlate_chains(self):
        """
        Person B correlation engine.

        Reads the shared SQLite alerts table, groups by the agreed context tuple
        (source_ip, target_ip, target_node), and searches a 15-minute sliding window
        for the prerequisite -> consequence sequence:
            port_scan -> brute_force -> lateral_movement

        A ddos event may be retained as a final impact stage if it occurs after the
        laterally moving event in the same correlation window. The function stores
        the alert IDs as a JSON array in `attack_chains.alert_ids`, stores the MITRE
        string in `attack_chains.mitre_sequence`, and emits CHAIN_DETECTED only when
        a new chain record is created or an existing chain record changes meaningfully.
        """
        conn = self.connect()
        try:
            rows = conn.execute(
                """
                SELECT id, timestamp, source_ip, target_ip, target_node, attack_type, mitre_tactic
                FROM alerts
                WHERE attack_type IN ('port_scan','brute_force','lateral_movement','ddos')
                ORDER BY timestamp ASC
                """
            ).fetchall()

            # Group alerts by the context every attack chain must share.
            groups = {}
            for row in rows:
                key = (row["source_ip"], row["target_ip"], row["target_node"])
                groups.setdefault(key, []).append(dict(row))

            created_or_updated = 0
            for (source_ip, target_ip, target_node), events in groups.items():
                events.sort(key=lambda row: self.parse_ts(row["timestamp"]))

                # Inspect every event as the window beginning.
                for start_index, event in enumerate(events):
                    start_time = self.parse_ts(event["timestamp"])
                    window = []
                    for later in events[start_index:]:
                        later_time = self.parse_ts(later["timestamp"])
                        if later_time - start_time > timedelta(minutes=15):
                            break
                        # Keep only chronological rows inside the same 15-minute band.
                        window.append(later)

                    if len(window) < 3:
                        continue

                    # Walk the window in chronological order and enforce the required strategy.
                    attack_sequence = [row["attack_type"] for row in window]
                    # Require exactly the order port_scan -> brute_force -> lateral_movement.
                    required_seen = []
                    for attack_type in attack_sequence:
                        if attack_type in PREREQUISITE:
                            if attack_type == PREREQUISITE[len(required_seen)]:
                                required_seen.append(attack_type)
                                if len(required_seen) == len(PREREQUISITE):
                                    break
                    if required_seen != PREREQUISITE:
                        continue

                    # Accept ddos only as an optional impact event that appears
                    # after the required prerequisite chain has been observed in
                    # the same source/target/target_node context.
                    ddos_event = None
                    lateral_time = None
                    for row in window:
                        if row["attack_type"] == "lateral_movement":
                            lateral_time = self.parse_ts(row["timestamp"])
                            break

                    if lateral_time:
                        # Restrict the ddos candidate to the same 15-minute window
                        # slice that already carries the prerequisite events, and
                        # only consider a ddos event that arrives after the
                        # lateral_movement stage in that same ordered context.
                        ddos_candidates = [
                            row for row in window
                            if row["attack_type"] == "ddos"
                            and self.parse_ts(row["timestamp"]) >= lateral_time
                        ]
                        if ddos_candidates:
                            ddos_event = ddos_candidates[0]

                    # Alert ids must be in the chronological chain order.
                    alert_ids = []
                    seen_alert_ids = set()
                    for attack_type in PREREQUISITE:
                        for row in window:
                            if row["attack_type"] == attack_type and row["id"] not in seen_alert_ids:
                                alert_ids.append(row["id"])
                                seen_alert_ids.add(row["id"])
                                break
                    if ddos_event:
                        if ddos_event["id"] not in seen_alert_ids:
                            alert_ids.append(ddos_event["id"])
                            seen_alert_ids.add(ddos_event["id"])

                    # Deterministic chain_id; independent of run order and consistent for same alert set.
                    seed_ids = sorted(alert_ids)
                    seed = "|".join(str(v) for v in seed_ids)
                    chain_id = "chain-" + hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]

                    # MITRE sequence string from the same known mapping.
                    mitre_sequence = " -> ".join([ATTACK_TO_MITRE[a] for a in PREREQUISITE])
                    if ddos_event:
                        mitre_sequence += " -> " + ATTACK_TO_MITRE["ddos"]

                    # Use UTC ISO 8601 timestamps everywhere.
                    start_timestamp = self.normalize_timestamp(window[0]["timestamp"])
                    last_updated = self.now_iso()

                    # Read existing chain row to decide if update is meaningful.
                    existing = conn.execute(
                        "SELECT alert_ids, mitre_sequence, start_time, last_updated FROM attack_chains WHERE chain_id = ?",
                        (chain_id,),
                    ).fetchone()

                    new_alert_ids_json = json.dumps(alert_ids)
                    new_payload = {
                        "chain_id": chain_id,
                        "alert_ids": alert_ids,
                        "mitre_sequence": mitre_sequence,
                        "start_time": start_timestamp,
                        "last_updated": last_updated,
                        "status": "active",
                    }

                    changed = True
                    if existing:
                        old_ids = json.loads(existing["alert_ids"])
                        old_sequence = existing["mitre_sequence"]
                        old_start = existing["start_time"]
                        if old_ids == alert_ids and old_sequence == mitre_sequence and old_start == start_timestamp:
                            changed = False

                    if existing and changed:
                        conn.execute(
                            """
                            UPDATE attack_chains
                            SET alert_ids = ?,
                                mitre_sequence = ?,
                                start_time = ?,
                                last_updated = ?,
                                status = 'active'
                            WHERE chain_id = ?
                            """,
                            (new_alert_ids_json, mitre_sequence, start_timestamp, last_updated, chain_id),
                        )
                        logger.info("Meaningfully updated chain %s with %s alerts", chain_id, len(alert_ids))
                    elif not existing:
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO attack_chains
                            (chain_id, alert_ids, mitre_sequence, start_time, last_updated, status)
                            VALUES (?, ?, ?, ?, ?, 'active')
                            """,
                            (chain_id, new_alert_ids_json, mitre_sequence, start_timestamp, last_updated),
                        )
                        logger.info("Created chain %s with %s alerts", chain_id, len(alert_ids))
                    else:
                        logger.info("Duplicate chain skipped for %s", chain_id)

                    # Publish only when chain is created or changed.
                    if not existing or changed:
                        try:
                            self.bus.publish(EventBus.CHAIN_DETECTED, new_payload)
                            logger.info("Published %s for %s", EventBus.CHAIN_DETECTED, chain_id)
                        except Exception as exc:
                            logger.warning("CHAIN_DETECTED publish failed for %s: %s", chain_id, exc)

                    created_or_updated += 1 if not existing or changed else 0
                    # Stop once a single valid window is found for a context; this keeps chains deterministic.
                    break

            conn.commit()
            logger.info("Correlation pass complete; created_or_updated %s chain records", created_or_updated)
        except Exception as exc:
            conn.rollback()
            logger.exception("Correlation engine failed: %s", exc)
        finally:
            conn.close()

    def severity_for_score(self, score):
        if score <= 29:
            return "Low"
        if score <= 49:
            return "Medium"
        if score <= 84:
            return "High"
        return "Critical"

    def score_chains(self):
        """Score every active chain deterministically, skipping unchanged score rows."""
        conn = self.connect()
        try:
            chains = conn.execute(
                """
                SELECT id, chain_id, alert_ids, start_time, last_updated
                FROM attack_chains
                WHERE status = 'active'
                ORDER BY last_updated DESC
                """
            ).fetchall()

            for chain in chains:
                try:
                    alert_ids = json.loads(chain["alert_ids"])
                except Exception:
                    alert_ids = []
                if not alert_ids:
                    continue

                placeholders = ",".join("?" for _ in alert_ids)
                sql = f"""
                    SELECT id, timestamp, attack_type, source_ip, target_ip, target_node
                    FROM alerts
                    WHERE id IN ({placeholders})
                    ORDER BY timestamp ASC
                """
                rows = conn.execute(sql, tuple(alert_ids)).fetchall()
                if not rows:
                    continue

                # Compute a deterministic score.
                score = 0
                factors = {
                    "attack_types": [],
                    "evidence_count": len(rows),
                    "source_ip": rows[0]["source_ip"] if rows else None,
                    "target_ip": rows[0]["target_ip"] if rows else None,
                    "target_node": rows[0]["target_node"] if rows else None,
                    "mitre_sequence": [ATTACK_TO_MITRE.get(r["attack_type"], "UNKNOWN") for r in rows],
                    "window_minutes": 15,
                }

                for row in rows:
                    attack_type = row["attack_type"]
                    factors["attack_types"].append(attack_type)
                    score += ATTACK_WEIGHTS.get(attack_type, 5)

                # Reward the requested prerequisite-to-consequence chain.
                if all(x in factors["attack_types"] for x in PREREQUISITE):
                    score += 20
                if "ddos" in factors["attack_types"]:
                    score += 15

                # Add a small size bonus for chain richness.
                if len(rows) >= 4:
                    score += 10

                # Deterministically clamp and map to severity.
                score = max(0, min(100, score))
                severity = self.severity_for_score(score)
                timestamp = self.now_iso()

                # Avoid duplicate score records for an unchanged chain.
                latest = conn.execute(
                    """
                    SELECT score, severity_label, factors_json
                    FROM threat_scores
                    WHERE chain_id = ?
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """,
                    (chain["chain_id"],),
                ).fetchone()

                new_factors = json.dumps(factors, sort_keys=True)
                if latest and float(latest["score"]) == float(score) and latest["severity_label"] == severity and latest["factors_json"] == new_factors:
                    logger.info("Skip duplicate unchanged score for chain %s", chain["chain_id"])
                    continue

                conn.execute(
                    """
                    INSERT INTO threat_scores
                    (chain_id, timestamp, score, severity_label, factors_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (chain["chain_id"], timestamp, score, severity, new_factors),
                )

                payload = {
                    "chain_id": chain["chain_id"],
                    "score": score,
                    "severity_label": severity,
                    "timestamp": timestamp,
                }
                self.bus.publish(EventBus.SCORE_COMPUTED, payload)
                logger.info(
                    "Published %s for %s with score %s (%s)",
                    EventBus.SCORE_COMPUTED,
                    chain["chain_id"],
                    score,
                    severity,
                )

            conn.commit()
            logger.info("Scorer pass complete")
        except Exception as exc:
            conn.rollback()
            logger.exception("Threat scoring failed: %s", exc)
        finally:
            conn.close()

    def insert_alert_from_event(self, payload):
        """Handle a NEW_ALERT Redis payload without depending on Person A being online."""
        try:
            if not isinstance(payload, dict):
                logger.warning("Malformed NEW_ALERT payload received: %s", payload)
                return

            # Accept event payloads from the documented example.
            event_ts = payload.get("timestamp") or self.now_iso()
            event_dtt = self.normalize_timestamp(event_ts)
            source_ip = payload.get("source_ip") or "unknown"
            target_ip = payload.get("target_ip") or "unknown"
            target_node = payload.get("target_node") or "unknown"
            attack_type = payload.get("attack_type")
            if attack_type not in ATTACK_TO_MITRE:
                logger.warning("Ignoring unsupported attack_type from NEW_ALERT event: %s", attack_type)
                return

            detection_source = "both"
            raw_details = json.dumps(payload, sort_keys=True)

            # De-duplicate by event shape and same timestamp.
            seen_key = f"{event_dtt}|{source_ip}|{target_ip}|{target_node}|{attack_type}|{detection_source}".lower()
            if seen_key in self.alert_seen_keys:
                logger.debug("Duplicate NEW_ALERT ignored: %s", seen_key)
                return
            self.alert_seen_keys.add(seen_key)

            conn = self.connect()
            try:
                existing = conn.execute(
                    """
                    SELECT id FROM alerts
                    WHERE timestamp = ? AND source_ip = ? AND target_ip = ? AND target_node = ? AND attack_type = ?
                    LIMIT 1
                    """,
                    (event_dtt, source_ip, target_ip, target_node, attack_type),
                ).fetchone()
                if existing:
                    logger.info("Duplicate alert row already exists for event: %s", seen_key)
                    conn.close()
                    return

                conn.execute(
                    """
                    INSERT INTO alerts
                    (timestamp, source_ip, target_ip, target_node, attack_type, detection_source, mitre_tactic, raw_details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (event_dtt, source_ip, target_ip, target_node, attack_type, detection_source, ATTACK_TO_MITRE[attack_type], raw_details),
                )
                conn.commit()
                logger.info("Inserted alert from NEW_ALERT event: %s", seen_key)
            except Exception as exc:
                conn.rollback()
                logger.exception("NEW_ALERT insertion failed: %s", exc)
            finally:
                conn.close()
        except Exception as exc:
            logger.exception("NEW_ALERT handler failed: %s", exc)

    def insert_ml_prediction_from_event(self, payload):
        """Safely store an ML_PREDICTION event if it is well-formed for the shared schema in shared/schema.sql."""
        try:
            if not isinstance(payload, dict):
                logger.warning("Malformed ML_PREDICTION payload ignored: %s", payload)
                return

            timestamp = payload.get("timestamp") or self.now_iso()
            timestamp = self.normalize_timestamp(timestamp)
            target_node = payload.get("target_node") or None
            predicted_class = payload.get("predicted_class") or "unknown"
            confidence = float(payload.get("confidence") or 0.0)
            window_start = payload.get("window_start") or timestamp
            window_end = payload.get("window_end") or timestamp
            features_json = json.dumps(payload.get("features_json") or payload, sort_keys=True)

            conn = self.connect()
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO ml_predictions
                    (timestamp, window_start, window_end, target_node, predicted_class, confidence, features_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (timestamp, window_start, window_end, target_node, predicted_class, confidence, features_json),
                )
                conn.commit()
                logger.info("Processed ML_PREDICTION event for %s", target_node or "unknown node")
            except Exception as exc:
                conn.rollback()
                logger.exception("ML_PREDICTION insertion failed: %s", exc)
            finally:
                conn.close()
        except Exception as exc:
            logger.exception("ML_PREDICTION handler failed: %s", exc)

    def start_event_listener(self):
        """Subscribe to both NEW_ALERT and ML_PREDICTION while allowing fixture/database mode to remain independent of Person A."""
        def worker():
            try:
                pubsub = self.bus.subscribe([EventBus.NEW_ALERT, EventBus.ML_PREDICTION])
                for channel, payload in self.bus.listen():
                    if channel == EventBus.NEW_ALERT:
                        logger.info("Received NEW_ALERT payload: %s", json.dumps(payload, sort_keys=True))
                        self.insert_alert_from_event(payload)
                    elif channel == EventBus.ML_PREDICTION:
                        logger.info("Received ML_PREDICTION payload: %s", json.dumps(payload, sort_keys=True))
                        self.insert_ml_prediction_from_event(payload)
            except Exception as exc:
                logger.warning("Redis listener stopped or Redis unavailable: %s", exc)

        thread = threading.Thread(target=worker, name="event-listener", daemon=True)
        thread.start()
        logger.info("Started Redis event subscription thread for NEW_ALERT and ML_PREDICTION")

    def run(self):
        logger.info("Person B analysis agent starting")
        logger.info("DB: %s", self.database_path)
        logger.info("Redis: %s:%s", self.redis_host, self.redis_port)

        self.start_event_listener()

        while True:
            try:
                self.map_mitre_tactics()
                self.correlate_chains()
                self.score_chains()
            except Exception as exc:
                logger.exception("Analysis agent loop raised an exception: %s", exc)

            logger.info("Person B analysis pass complete; waiting 10 seconds")
            time.sleep(10)


if __name__ == "__main__":
    agent = AnalysisAgent()
    agent.run()
