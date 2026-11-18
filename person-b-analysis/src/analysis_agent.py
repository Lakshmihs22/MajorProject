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
import importlib.util
import json
import logging
import math
import os
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from shared.eventbus_client import EventBus
except ImportError:
    module_path = REPO_ROOT / "shared" / "eventbus_client.py"
    spec = importlib.util.spec_from_file_location("shared.eventbus_client", str(module_path))
    module = importlib.util.module_from_spec(spec)
    if spec is not None and spec.loader is not None:
        spec.loader.exec_module(module)
    EventBus = module.EventBus


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
        parent.mkdir(parents=True, exist_ok=True)

        # Make sure the SQLite schema is available before we begin.
        self.ensure_schema()

        # Shared event bus object.
        self.bus = EventBus(host=self.redis_host, port=self.redis_port)

    def ensure_schema(self):
        schema_candidates = [
            Path(__file__).resolve().parents[2] / "shared" / "schema.sql",
            Path("shared") / "schema.sql",
            Path("/app/shared/schema.sql"),
        ]
        schema_path = next((p for p in schema_candidates if p.exists()), None)
        if schema_path is None:
            raise FileNotFoundError(
                f"Schema file not found; expected one of {schema_candidates}"
            )
        conn = self.connect()
        try:
            with conn:
                conn.executescript(schema_path.read_text(encoding="utf-8"))
            logger.info("Schema ready at %s using %s", self.database_path, schema_path)
        except Exception:
            logger.exception("Schema preparation failed at %s", self.database_path)
            raise
        finally:
            conn.close()

    def connect(self):
        conn = sqlite3.connect(self.database_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn

    def now_iso(self):
        return datetime.now(timezone.utc).isoformat()

    def parse_ts(self, value):
        """Return a timezone-aware UTC datetime for alert timestamps.

        Existing project fixtures and DB rows may contain ISO strings without an
        explicit offset (for example datetime.utcnow().isoformat() in fixtures), so
        we interpret naive timestamps as UTC to stay consistent with the repo's
        documented timestamp convention.
        """
        if value is None:
            return None

        try:
            if isinstance(value, datetime):
                dt = value
            elif isinstance(value, str):
                text = value.strip()
                if not text:
                    return None
                if text.endswith("Z"):
                    text = text[:-1] + "+00:00"
                dt = datetime.fromisoformat(text)
            else:
                return None
        except Exception:
            return None

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def normalize_timestamp(self, value):
        dt = self.parse_ts(value)
        if dt is None:
            raise ValueError(f"Invalid timestamp: {value!r}")
        return dt.isoformat()

    def map_mitre_tactics(self):
        """Backfill MITRE tactic assignments for any attack_type already known in the repo."""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
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

    def _campaign_id(self, row):
        """Return the optional campaign identifier preserved in an alert's raw payload."""
        try:
            details = json.loads(row["raw_details"] or "{}")
        except (TypeError, json.JSONDecodeError):
            return None

        if not isinstance(details, dict):
            return None
        campaign_id = details.get("campaign_id")
        if isinstance(campaign_id, (str, int)) and not isinstance(campaign_id, bool):
            campaign_id = str(campaign_id).strip()
            return campaign_id or None
        return None

    def correlate_chains(self):
        """Build ordered campaign chains across targets and edge nodes."""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """
                SELECT id, timestamp, source_ip, target_ip, target_node, attack_type,
                       mitre_tactic, raw_details
                FROM alerts
                WHERE attack_type IN ('port_scan','brute_force','lateral_movement','ddos')
                """
            ).fetchall()

            groups = {}
            for row in rows:
                details = dict(row)
                campaign_id = self._campaign_id(details)
                key = (
                    ("campaign", campaign_id)
                    if campaign_id
                    else ("source_ip", details["source_ip"])
                )
                groups.setdefault(key, []).append(details)

            created_or_updated = 0
            for (identity_type, identity_value), events in groups.items():
                campaign_id = identity_value if identity_type == "campaign" else None
                normalized_events = []
                for row in events:
                    parsed = self.parse_ts(row["timestamp"])
                    if parsed is None:
                        logger.warning(
                            "Skipping alert %s with invalid timestamp %r",
                            row["id"],
                            row["timestamp"],
                        )
                        continue
                    row["_dt"] = parsed
                    normalized_events.append(row)

                normalized_events.sort(key=lambda row: (row["_dt"], row["id"]))
                consumed_ids = set()

                for start_index, event in enumerate(normalized_events):
                    if event["id"] in consumed_ids or event["attack_type"] != "port_scan":
                        continue

                    start_time = event["_dt"]
                    window = []
                    for later in normalized_events[start_index:]:
                        if later["_dt"] - start_time > timedelta(minutes=15):
                            break
                        if later["id"] not in consumed_ids:
                            window.append(later)

                    stage_rows = {}
                    for row in window:
                        attack = row["attack_type"]
                        if attack == "port_scan" and "port_scan" not in stage_rows:
                            stage_rows["port_scan"] = row
                        elif (
                            attack == "brute_force"
                            and "port_scan" in stage_rows
                            and "brute_force" not in stage_rows
                        ):
                            stage_rows["brute_force"] = row
                        elif (
                            attack == "lateral_movement"
                            and "brute_force" in stage_rows
                            and "lateral_movement" not in stage_rows
                        ):
                            stage_rows["lateral_movement"] = row
                        elif (
                            attack == "ddos"
                            and "lateral_movement" in stage_rows
                            and "ddos" not in stage_rows
                        ):
                            stage_rows["ddos"] = row

                    if not all(name in stage_rows for name in PREREQUISITE):
                        continue

                    ordered_alert_ids = [stage_rows[name]["id"] for name in PREREQUISITE]
                    if "ddos" in stage_rows:
                        ordered_alert_ids.append(stage_rows["ddos"]["id"])

                    start_timestamp = self.normalize_timestamp(
                        stage_rows["port_scan"]["timestamp"]
                    )
                    last_updated = self.now_iso()
                    mitre_sequence = " -> ".join(
                        ATTACK_TO_MITRE[attack] for attack in PREREQUISITE
                    )
                    if "ddos" in stage_rows:
                        mitre_sequence += " -> " + ATTACK_TO_MITRE["ddos"]

                    identity = (
                        f"{stage_rows['port_scan']['source_ip']}|{campaign_id or ''}|"
                        f"{stage_rows['port_scan']['id']}"
                    )
                    chain_id = "chain-" + hashlib.sha1(
                        identity.encode("utf-8")
                    ).hexdigest()[:12]

                    existing = conn.execute(
                        """
                        SELECT chain_id, alert_ids, mitre_sequence, start_time
                        FROM attack_chains WHERE chain_id = ?
                        """,
                        (chain_id,),
                    ).fetchone()

                    if not existing:
                        # Reuse a chain created by the previous ID scheme so new
                        # evidence updates it instead of leaving a stale duplicate.
                        for candidate in conn.execute(
                            """
                            SELECT chain_id, alert_ids, mitre_sequence, start_time
                            FROM attack_chains
                            """
                        ).fetchall():
                            try:
                                old_ids = json.loads(candidate["alert_ids"])
                            except (TypeError, json.JSONDecodeError):
                                continue
                            if old_ids and old_ids[0] == stage_rows["port_scan"]["id"]:
                                existing = candidate
                                chain_id = candidate["chain_id"]
                                break

                    changed = True
                    if existing:
                        try:
                            old_ids = json.loads(existing["alert_ids"])
                        except (TypeError, json.JSONDecodeError):
                            old_ids = []
                        changed = not (
                            old_ids == ordered_alert_ids
                            and existing["mitre_sequence"] == mitre_sequence
                            and existing["start_time"] == start_timestamp
                        )

                    if existing and changed:
                        conn.execute(
                            """
                            UPDATE attack_chains
                            SET alert_ids = ?, mitre_sequence = ?, start_time = ?,
                                last_updated = ?, status = 'active'
                            WHERE chain_id = ?
                            """,
                            (
                                json.dumps(ordered_alert_ids),
                                mitre_sequence,
                                start_timestamp,
                                last_updated,
                                chain_id,
                            ),
                        )
                        logger.info(
                            "Meaningfully updated chain %s with %s alerts",
                            chain_id,
                            len(ordered_alert_ids),
                        )
                    elif not existing:
                        conn.execute(
                            """
                            INSERT INTO attack_chains
                            (chain_id, alert_ids, mitre_sequence, start_time, last_updated, status)
                            VALUES (?, ?, ?, ?, ?, 'active')
                            """,
                            (
                                chain_id,
                                json.dumps(ordered_alert_ids),
                                mitre_sequence,
                                start_timestamp,
                                last_updated,
                            ),
                        )
                        logger.info(
                            "Created chain %s with %s alerts",
                            chain_id,
                            len(ordered_alert_ids),
                        )
                    else:
                        logger.info("Duplicate chain skipped for %s", chain_id)

                    if not existing or changed:
                        conn.commit()
                        payload = {
                            "chain_id": chain_id,
                            "alert_ids": ordered_alert_ids,
                            "mitre_sequence": mitre_sequence,
                            "start_time": start_timestamp,
                            "last_updated": last_updated,
                            "status": "active",
                        }
                        try:
                            self.bus.publish(EventBus.CHAIN_DETECTED, payload)
                            logger.info(
                                "Published %s for %s",
                                EventBus.CHAIN_DETECTED,
                                chain_id,
                            )
                        except Exception:
                            logger.exception(
                                "CHAIN_DETECTED publish failed for %s",
                                chain_id,
                            )

                    created_or_updated += 1 if not existing or changed else 0
                    consumed_ids.update(ordered_alert_ids)

            conn.commit()
            logger.info(
                "Correlation pass complete; created_or_updated %s chain records",
                created_or_updated,
            )
        except Exception:
            conn.rollback()
            logger.exception("Correlation engine failed")
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
        """Score every active chain deterministically, deduplicating repeated evidence."""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
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
                    if not isinstance(alert_ids, list) or any(
                        isinstance(alert_id, bool) or not isinstance(alert_id, int)
                        for alert_id in alert_ids
                    ):
                        raise ValueError("alert_ids must be a JSON array of integer IDs")
                    alert_ids = list(dict.fromkeys(alert_ids))
                except (TypeError, json.JSONDecodeError, ValueError):
                    logger.warning(
                        "Skipping chain %s with malformed alert_ids",
                        chain["chain_id"],
                    )
                    continue
                if not alert_ids:
                    continue

                placeholders = ",".join("?" for _ in alert_ids)
                sql = f"""
                    SELECT id, timestamp, attack_type, source_ip, target_ip, target_node
                    FROM alerts
                    WHERE id IN ({placeholders})
                """
                fetched_rows = conn.execute(sql, tuple(alert_ids)).fetchall()
                rows_by_id = {row["id"]: dict(row) for row in fetched_rows}
                alert_ids = [alert_id for alert_id in alert_ids if alert_id in rows_by_id]
                rows = [rows_by_id[alert_id] for alert_id in alert_ids if alert_id in rows_by_id]
                if not rows:
                    continue

                selected = []
                seen_attack_types = set()
                for row in rows:
                    attack_type = row["attack_type"]
                    if attack_type in ("port_scan", "brute_force", "lateral_movement", "ddos") and attack_type not in seen_attack_types:
                        selected.append(row)
                        seen_attack_types.add(attack_type)

                if not selected:
                    continue

                score = sum(ATTACK_WEIGHTS.get(row["attack_type"], 5) for row in selected)
                if set(PREREQUISITE).issubset(set(row["attack_type"] for row in selected)):
                    score += 20
                if "ddos" in {row["attack_type"] for row in selected}:
                    score += 15
                if len(selected) >= 4:
                    score += 10

                score = max(0, min(100, score))
                severity = self.severity_for_score(score)
                timestamp = self.now_iso()
                factors = {
                    "attack_types": [row["attack_type"] for row in selected],
                    "attack_types_ordered": [row["attack_type"] for row in selected],
                    "evidence_count": len(selected),
                    "source_ip": rows[0]["source_ip"] if rows else None,
                    "target_ips": sorted({row["target_ip"] for row in rows if row["target_ip"]}),
                    "target_nodes": sorted({row["target_node"] for row in rows if row["target_node"]}),
                    "mitre_sequence": [ATTACK_TO_MITRE.get(r["attack_type"], "UNKNOWN") for r in selected],
                    "window_minutes": 15,
                    "alert_ids": alert_ids,
                    "chain_start_time": chain["start_time"],
                    "chain_last_updated": chain["last_updated"],
                }

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
                conn.commit()

                payload = {
                    "chain_id": chain["chain_id"],
                    "score": score,
                    "severity_label": severity,
                    "timestamp": timestamp,
                    "alert_ids": alert_ids,
                    "evidence_count": len(alert_ids),
                    "factors": factors,
                }
                try:
                    self.bus.publish(EventBus.SCORE_COMPUTED, payload)
                    logger.info(
                        "Published %s for %s with score %s (%s)",
                        EventBus.SCORE_COMPUTED,
                        chain["chain_id"],
                        score,
                        severity,
                    )
                except Exception:
                    logger.exception(
                        "SCORE_COMPUTED publish failed for %s",
                        chain["chain_id"],
                    )

            logger.info("Scorer pass complete")
        except Exception as exc:
            conn.rollback()
            logger.exception("Threat scoring failed: %s", exc)
        finally:
            conn.close()

    def insert_alert_from_event(self, payload):
        """Handle a NEW_ALERT Redis payload without depending on Person A being online."""
        if not isinstance(payload, dict):
            logger.warning("Malformed NEW_ALERT payload received: %s", payload)
            return

        try:
            event_dtt = self.normalize_timestamp(payload.get("timestamp"))
            source_ip = payload.get("source_ip")
            target_ip = payload.get("target_ip")
            target_node = payload.get("target_node")
            attack_type = payload.get("attack_type")
            detection_source = payload.get("detection_source")

            if not isinstance(source_ip, str) or not source_ip.strip():
                raise ValueError("source_ip is required")
            if not isinstance(target_ip, str) or not target_ip.strip():
                raise ValueError("target_ip is required")
            if not isinstance(attack_type, str) or attack_type.strip().lower() not in ATTACK_TO_MITRE:
                raise ValueError(f"unsupported attack_type: {attack_type!r}")
            if not isinstance(detection_source, str) or not detection_source.strip():
                raise ValueError("detection_source is required")
            if target_node is not None and not isinstance(target_node, str):
                raise ValueError("target_node must be a string or null")

            source_ip = source_ip.strip()
            target_ip = target_ip.strip()
            if target_node is not None:
                target_node = target_node.strip() or None
            attack_type = attack_type.strip().lower()
            detection_source = detection_source.strip()
            event_time = self.parse_ts(event_dtt)
            raw_details = json.dumps(payload, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            logger.warning("Malformed NEW_ALERT payload ignored: %s", exc)
            return

        seen_key = (
            f"{event_dtt}|{source_ip}|{target_ip}|{target_node or ''}|"
            f"{attack_type}|{detection_source}"
        )
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            candidates = conn.execute(
                """
                SELECT timestamp FROM alerts
                WHERE source_ip = ? AND target_ip = ? AND target_node IS ? AND attack_type = ?
                """,
                (source_ip, target_ip, target_node, attack_type),
            ).fetchall()
            if any(self.parse_ts(row["timestamp"]) == event_time for row in candidates):
                logger.info("Duplicate alert row already exists for event: %s", seen_key)
                return

            conn.execute(
                """
                INSERT INTO alerts
                (timestamp, source_ip, target_ip, target_node, attack_type, detection_source, mitre_tactic, raw_details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_dtt,
                    source_ip,
                    target_ip,
                    target_node,
                    attack_type,
                    detection_source,
                    ATTACK_TO_MITRE[attack_type],
                    raw_details,
                ),
            )
            conn.commit()
            logger.info("Inserted alert from NEW_ALERT event: %s", seen_key)
        except Exception:
            conn.rollback()
            logger.exception("NEW_ALERT insertion failed")
            return
        finally:
            conn.close()

        self.map_mitre_tactics()
        self.correlate_chains()
        self.score_chains()

    def insert_ml_prediction_from_event(self, payload):
        """Safely store an ML_PREDICTION event if it is well-formed for the shared schema in shared/schema.sql."""
        if not isinstance(payload, dict):
            logger.warning("Malformed ML_PREDICTION payload ignored: %s", payload)
            return

        try:
            timestamp = self.normalize_timestamp(payload.get("timestamp"))
            target_node = payload.get("target_node")
            predicted_class = payload.get("predicted_class")
            confidence_value = payload.get("confidence")
            if target_node is not None and not isinstance(target_node, str):
                raise ValueError("target_node must be a string or null")
            if not isinstance(predicted_class, str) or not predicted_class.strip():
                raise ValueError("predicted_class is required")
            if isinstance(confidence_value, bool):
                raise ValueError("confidence must be a number between 0 and 1")
            confidence = float(confidence_value)
            if not math.isfinite(confidence) or not 0 <= confidence <= 1:
                raise ValueError("confidence must be a finite number between 0 and 1")

            window_start = self.normalize_timestamp(
                payload.get("window_start") or timestamp
            )
            window_end = self.normalize_timestamp(payload.get("window_end") or timestamp)
            features = payload.get("features_json", {})
            features_json = json.dumps(features, sort_keys=True, allow_nan=False)
            if target_node is not None:
                target_node = target_node.strip() or None
            predicted_class = predicted_class.strip()
        except (TypeError, ValueError) as exc:
            logger.warning("Malformed ML_PREDICTION payload ignored: %s", exc)
            return

        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """
                SELECT id FROM ml_predictions
                WHERE timestamp = ? AND window_start = ? AND window_end = ?
                  AND target_node IS ? AND predicted_class = ? AND confidence = ?
                  AND features_json = ?
                LIMIT 1
                """,
                (
                    timestamp,
                    window_start,
                    window_end,
                    target_node,
                    predicted_class,
                    confidence,
                    features_json,
                ),
            ).fetchone()
            if existing:
                logger.info(
                    "Duplicate ML_PREDICTION ignored for %s",
                    target_node or "unknown node",
                )
                return

            conn.execute(
                """
                INSERT INTO ml_predictions
                (timestamp, window_start, window_end, target_node, predicted_class, confidence, features_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    window_start,
                    window_end,
                    target_node,
                    predicted_class,
                    confidence,
                    features_json,
                ),
            )
            conn.commit()
            logger.info(
                "Processed ML_PREDICTION event for %s",
                target_node or "unknown node",
            )
        except Exception:
            conn.rollback()
            logger.exception("ML_PREDICTION insertion failed")
        finally:
            conn.close()

    def start_event_listener(self):
        """Subscribe to both NEW_ALERT and ML_PREDICTION while allowing fixture/database mode to remain independent of Person A."""
        def worker():
            while True:
                try:
                    self.bus.subscribe([EventBus.NEW_ALERT, EventBus.ML_PREDICTION])
                    for channel, payload in self.bus.listen():
                        if channel == EventBus.NEW_ALERT:
                            logger.info("Received NEW_ALERT payload: %s", json.dumps(payload, sort_keys=True))
                            self.insert_alert_from_event(payload)
                        elif channel == EventBus.ML_PREDICTION:
                            logger.info("Received ML_PREDICTION payload: %s", json.dumps(payload, sort_keys=True))
                            self.insert_ml_prediction_from_event(payload)
                except Exception as exc:
                    logger.warning("Redis listener stopped or Redis unavailable: %s", exc)
                logger.info("Redis listener reconnecting in 5 seconds")
                time.sleep(5)

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
