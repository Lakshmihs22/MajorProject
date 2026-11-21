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
import ipaddress
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
SYNTHETIC_ALERT_DETAILS_PREFIX = "mock alert #"
SYNTHETIC_ALERT_FLAG = "is_synthetic"

SCORE_DECAY_GRACE_SECONDS = int(os.getenv("SCORE_DECAY_GRACE_SECONDS", "300"))
SCORE_DECAY_INTERVAL_SECONDS = int(os.getenv("SCORE_DECAY_INTERVAL_SECONDS", "300"))
SCORE_DECAY_POINTS_PER_INTERVAL = int(
    os.getenv("SCORE_DECAY_POINTS_PER_INTERVAL", "5")
)
CHAIN_RESOLUTION_LOW_MEDIUM_SECONDS = int(
    os.getenv("CHAIN_RESOLUTION_LOW_MEDIUM_SECONDS", "1800")
)
CHAIN_RESOLUTION_HIGH_SECONDS = int(
    os.getenv("CHAIN_RESOLUTION_HIGH_SECONDS", "3600")
)
CHAIN_RESOLUTION_CRITICAL_SECONDS = int(
    os.getenv("CHAIN_RESOLUTION_CRITICAL_SECONDS", "7200")
)
# Confidence can refine a rule-based score, but never promote its severity band.
ML_CONFIDENCE_MAX_BONUS_POINTS = int(
    os.getenv("ML_CONFIDENCE_MAX_BONUS_POINTS", "5")
)
ML_CONFIDENCE_MATCH_WINDOW_SECONDS = int(
    os.getenv("ML_CONFIDENCE_MATCH_WINDOW_SECONDS", "900")
)

if (
    SCORE_DECAY_GRACE_SECONDS < 0
    or SCORE_DECAY_INTERVAL_SECONDS <= 0
    or SCORE_DECAY_POINTS_PER_INTERVAL <= 0
    or CHAIN_RESOLUTION_LOW_MEDIUM_SECONDS <= 0
    or CHAIN_RESOLUTION_HIGH_SECONDS <= 0
    or CHAIN_RESOLUTION_CRITICAL_SECONDS <= 0
    or ML_CONFIDENCE_MAX_BONUS_POINTS < 0
    or ML_CONFIDENCE_MATCH_WINDOW_SECONDS <= 0
):
    raise ValueError("Score decay and chain resolution settings are invalid")


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
            self._migrate_last_activity(conn)
            conn.commit()
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

    def _migrate_last_activity(self, conn):
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(attack_chains)")
        }
        if "last_activity_at" not in columns:
            conn.execute("ALTER TABLE attack_chains ADD COLUMN last_activity_at TEXT")

        chains = conn.execute(
            """
            SELECT id, chain_id, alert_ids, last_updated, start_time, last_activity_at
            FROM attack_chains
            WHERE last_activity_at IS NULL OR TRIM(last_activity_at) = ''
            """
        ).fetchall()
        for chain in chains:
            activity_at = self._latest_chain_alert_timestamp(
                conn, chain["alert_ids"]
            )
            if activity_at is None:
                activity_at = self.parse_ts(chain["last_updated"])
            if activity_at is None:
                activity_at = self.parse_ts(chain["start_time"])
            if activity_at is None:
                logger.warning(
                    "Chain %s has no valid activity timestamp; decay is deferred",
                    chain["chain_id"],
                )
                continue
            conn.execute(
                "UPDATE attack_chains SET last_activity_at = ? WHERE id = ?",
                (activity_at.isoformat(), chain["id"]),
            )

    def _latest_chain_alert_timestamp(self, conn, alert_ids_json):
        try:
            alert_ids = json.loads(alert_ids_json)
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(alert_ids, list):
            return None

        valid_ids = [
            alert_id for alert_id in alert_ids
            if isinstance(alert_id, int) and not isinstance(alert_id, bool)
        ]
        if not valid_ids:
            return None

        placeholders = ",".join("?" for _ in valid_ids)
        rows = conn.execute(
            f"SELECT timestamp FROM alerts WHERE id IN ({placeholders})",
            tuple(valid_ids),
        ).fetchall()
        timestamps = []
        for row in rows:
            parsed = self.parse_ts(row["timestamp"])
            if parsed is not None:
                timestamps.append(parsed)
        return max(timestamps) if timestamps else None

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
        """Backfill known MITRE tactics and clear mappings for unknown attack types."""
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
                    if row["mitre_tactic"] is not None:
                        conn.execute(
                            "UPDATE alerts SET mitre_tactic = NULL WHERE id = ?",
                            (row["id"],),
                        )
                        updated += 1
                    logger.warning("Unknown attack type for alert id=%s", row["id"])
            conn.commit()
            logger.info("MITRE mapping pass finished; updated %s alerts", updated)
        except Exception as exc:
            conn.rollback()
            logger.error("MITRE mapping failed (%s)", type(exc).__name__)
        finally:
            conn.close()

    def _validated_ip(self, value, field_name):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty IP address")
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            raise ValueError(f"{field_name} must be a valid IPv4 or IPv6 address") from None

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

    def _is_synthetic_alert(self, raw_details):
        """Recognize legacy fixture rows and explicit synthetic event metadata."""
        if not isinstance(raw_details, str):
            return False
        if raw_details.startswith(SYNTHETIC_ALERT_DETAILS_PREFIX):
            fixture_id = raw_details[len(SYNTHETIC_ALERT_DETAILS_PREFIX):]
            if fixture_id.isascii() and fixture_id.isdigit():
                return True

        try:
            details = json.loads(raw_details)
        except json.JSONDecodeError:
            return False
        return (
            isinstance(details, dict)
            and details.get(SYNTHETIC_ALERT_FLAG) is True
        )

    def _matching_ml_confidence(self, conn, alert_rows):
        """Return the strongest valid node/type-matched prediction near chain evidence."""
        pair_times = {}
        for row in alert_rows:
            target_node = row["target_node"]
            attack_type = row["attack_type"]
            if (
                not isinstance(target_node, str)
                or not target_node.strip()
                or not isinstance(attack_type, str)
                or attack_type.strip().lower() not in ATTACK_WEIGHTS
            ):
                continue
            parsed = self.parse_ts(row["timestamp"])
            if parsed is not None:
                pair = (target_node.strip(), attack_type.strip().lower())
                pair_times.setdefault(pair, []).append(parsed)
        if not pair_times:
            return None

        pair_conditions = " OR ".join(
            "(target_node = ? AND lower(trim(predicted_class)) = ?)"
            for _ in pair_times
        )
        pair_parameters = tuple(
            value for pair in sorted(pair_times) for value in pair
        )
        predictions = conn.execute(
            f"""
            SELECT timestamp, target_node, predicted_class, confidence
            FROM ml_predictions
            WHERE {pair_conditions}
            """,
            pair_parameters,
        ).fetchall()

        matching_confidences = []
        for prediction in predictions:
            pair = (
                prediction["target_node"],
                prediction["predicted_class"].strip().lower()
                if isinstance(prediction["predicted_class"], str)
                else "",
            )
            prediction_time = self.parse_ts(prediction["timestamp"])
            if pair not in pair_times or prediction_time is None or not any(
                abs((prediction_time - alert_time).total_seconds())
                <= ML_CONFIDENCE_MATCH_WINDOW_SECONDS
                for alert_time in pair_times[pair]
            ):
                continue
            try:
                confidence = float(prediction["confidence"])
            except (TypeError, ValueError):
                continue
            if math.isfinite(confidence) and 0 <= confidence <= 1:
                matching_confidences.append(confidence)
        return max(matching_confidences) if matching_confidences else None

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
            rows = [
                row for row in rows
                if not self._is_synthetic_alert(row["raw_details"])
            ]

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
                        logger.warning("Skipping alert id=%s with invalid timestamp", row["id"])
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
                    activity_dt = max(row["_dt"] for row in window)

                    existing = conn.execute(
                        """
                        SELECT chain_id, alert_ids, mitre_sequence, start_time,
                               last_activity_at, status
                        FROM attack_chains WHERE chain_id = ?
                        """,
                        (chain_id,),
                    ).fetchone()

                    if not existing:
                        # Reuse a chain created by the previous ID scheme so new
                        # evidence updates it instead of leaving a stale duplicate.
                        for candidate in conn.execute(
                            """
                            SELECT chain_id, alert_ids, mitre_sequence, start_time,
                                   last_activity_at, status
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

                    while existing and existing["status"] == "resolved":
                        try:
                            resolved_ids = json.loads(existing["alert_ids"])
                        except (TypeError, json.JSONDecodeError):
                            resolved_ids = []
                        if not isinstance(resolved_ids, list):
                            resolved_ids = []
                        resolved_activity = self.parse_ts(
                            existing["last_activity_at"]
                        )
                        if resolved_activity is not None:
                            new_activity = [
                                row for row in window
                                if row["_dt"] > resolved_activity
                            ]
                        else:
                            resolved_ids = set(resolved_ids)
                            new_activity = [
                                row for row in window
                                if row["id"] not in resolved_ids
                            ]
                        if not new_activity:
                            break

                        anchor = min(
                            new_activity,
                            key=lambda row: (row["_dt"], row["id"]),
                        )
                        chain_id = "chain-" + hashlib.sha1(
                            f"{chain_id}|after|{anchor['id']}".encode("utf-8")
                        ).hexdigest()[:12]
                        existing = conn.execute(
                            """
                            SELECT chain_id, alert_ids, mitre_sequence, start_time,
                                   last_activity_at, status
                            FROM attack_chains WHERE chain_id = ?
                            """,
                            (chain_id,),
                        ).fetchone()

                    if existing and existing["status"] == "resolved":
                        logger.info(
                            "Leaving resolved chain %s unchanged",
                            existing["chain_id"],
                        )
                        consumed_ids.update(ordered_alert_ids)
                        continue

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

                    existing_activity = (
                        self.parse_ts(existing["last_activity_at"])
                        if existing
                        else None
                    )
                    persisted_activity = max(
                        activity_dt,
                        existing_activity or activity_dt,
                    )
                    activity_changed = bool(
                        existing
                        and (
                            existing_activity is None
                            or persisted_activity > existing_activity
                        )
                    )

                    if existing and changed:
                        conn.execute(
                            """
                            UPDATE attack_chains
                            SET alert_ids = ?, mitre_sequence = ?, start_time = ?,
                                last_updated = ?, last_activity_at = ?
                            WHERE chain_id = ?
                            """,
                            (
                                json.dumps(ordered_alert_ids),
                                mitre_sequence,
                                start_timestamp,
                                last_updated,
                                persisted_activity.isoformat(),
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
                            (chain_id, alert_ids, mitre_sequence, start_time, last_updated,
                             last_activity_at, status)
                            VALUES (?, ?, ?, ?, ?, ?, 'active')
                            """,
                            (
                                chain_id,
                                json.dumps(ordered_alert_ids),
                                mitre_sequence,
                                start_timestamp,
                                last_updated,
                                activity_dt.isoformat(),
                            ),
                        )
                        logger.info(
                            "Created chain %s with %s alerts",
                            chain_id,
                            len(ordered_alert_ids),
                        )
                    else:
                        if activity_changed:
                            conn.execute(
                                """
                                UPDATE attack_chains SET last_activity_at = ?
                                WHERE chain_id = ? AND status = 'active'
                                """,
                                (persisted_activity.isoformat(), chain_id),
                            )
                        else:
                            logger.info("Duplicate chain skipped for %s", chain_id)

                    if not existing or changed or activity_changed:
                        conn.commit()
                    if not existing or changed:
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
        """Score active chains and apply deterministic inactivity decay."""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            chains = conn.execute(
                """
                SELECT id, chain_id, alert_ids, start_time, last_updated,
                       last_activity_at
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
                    SELECT id, timestamp, attack_type, source_ip, target_ip, target_node,
                           raw_details
                    FROM alerts
                    WHERE id IN ({placeholders})
                """
                fetched_rows = conn.execute(sql, tuple(alert_ids)).fetchall()
                rows_by_id = {row["id"]: dict(row) for row in fetched_rows}
                alert_ids = [alert_id for alert_id in alert_ids if alert_id in rows_by_id]
                rows = [rows_by_id[alert_id] for alert_id in alert_ids if alert_id in rows_by_id]
                if not rows:
                    continue
                if any(self._is_synthetic_alert(row["raw_details"]) for row in rows):
                    deleted_scores = conn.execute(
                        "DELETE FROM threat_scores WHERE chain_id = ?",
                        (chain["chain_id"],),
                    ).rowcount
                    if deleted_scores:
                        conn.commit()
                    logger.warning(
                        "Skipping threat scoring for chain %s containing synthetic alerts; "
                        "removed %s stale score(s)",
                        chain["chain_id"],
                        deleted_scores,
                    )
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

                rule_based_score = sum(
                    ATTACK_WEIGHTS.get(row["attack_type"], 5) for row in selected
                )
                if set(PREREQUISITE).issubset(set(row["attack_type"] for row in selected)):
                    rule_based_score += 20
                if "ddos" in {row["attack_type"] for row in selected}:
                    rule_based_score += 15
                if len(selected) >= 4:
                    rule_based_score += 10

                rule_based_score = max(0, min(100, rule_based_score))
                evidence_severity = self.severity_for_score(rule_based_score)
                ml_confidence = self._matching_ml_confidence(conn, rows)
                ml_confidence_bonus = 0
                if ml_confidence is not None:
                    ml_confidence_bonus = int(
                        ml_confidence * ML_CONFIDENCE_MAX_BONUS_POINTS + 0.5
                    )
                severity_limits = {
                    "Low": 29,
                    "Medium": 49,
                    "High": 84,
                    "Critical": 100,
                }
                evidence_score = min(
                    100,
                    rule_based_score + ml_confidence_bonus,
                    severity_limits[evidence_severity],
                )
                stored_activity_dt = self.parse_ts(chain["last_activity_at"])
                activity_dt = stored_activity_dt
                latest_alert_timestamps = []
                for row in rows:
                    parsed = self.parse_ts(row["timestamp"])
                    if parsed is not None:
                        latest_alert_timestamps.append(parsed)
                latest_alert_dt = (
                    max(latest_alert_timestamps)
                    if latest_alert_timestamps
                    else None
                )
                if latest_alert_dt and (
                    activity_dt is None or latest_alert_dt > activity_dt
                ):
                    activity_dt = latest_alert_dt
                if activity_dt is None:
                    activity_dt = self.parse_ts(chain["last_updated"])
                if activity_dt is None:
                    activity_dt = self.parse_ts(chain["start_time"])
                activity_updated = bool(
                    activity_dt
                    and (
                        stored_activity_dt is None
                        or activity_dt > stored_activity_dt
                    )
                )
                if activity_updated:
                    conn.execute(
                        "UPDATE attack_chains SET last_activity_at = ? WHERE id = ?",
                        (activity_dt.isoformat(), chain["id"]),
                    )

                now_dt = self.parse_ts(self.now_iso())
                inactivity_seconds = (
                    max(0, (now_dt - activity_dt).total_seconds())
                    if now_dt is not None and activity_dt is not None
                    else 0
                )
                decay_intervals = max(
                    0,
                    math.floor(
                        max(0, inactivity_seconds - SCORE_DECAY_GRACE_SECONDS)
                        / SCORE_DECAY_INTERVAL_SECONDS
                    ),
                )
                decay_points = decay_intervals * SCORE_DECAY_POINTS_PER_INTERVAL
                score = max(0, min(100, evidence_score - decay_points))
                severity = self.severity_for_score(score)
                timestamp = now_dt.isoformat() if now_dt else self.now_iso()
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
                    "evidence_score": evidence_score,
                    "decay_points": decay_points,
                }
                if ml_confidence is not None:
                    factors["rule_based_score"] = rule_based_score
                    factors["ml_confidence"] = ml_confidence
                    factors["ml_confidence_bonus"] = ml_confidence_bonus

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
                latest_factors = None
                if latest:
                    try:
                        latest_factors = json.loads(latest["factors_json"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        latest_factors = None
                stable_factors = dict(factors)
                stable_factors.pop("decay_points", None)
                if isinstance(latest_factors, dict):
                    latest_factors.pop("decay_points", None)
                if (
                    latest
                    and float(latest["score"]) == float(score)
                    and latest["severity_label"] == severity
                    and latest_factors == stable_factors
                ):
                    logger.info("Skip duplicate unchanged score for chain %s", chain["chain_id"])
                    score_changed = False
                else:
                    conn.execute(
                        """
                        INSERT INTO threat_scores
                        (chain_id, timestamp, score, severity_label, factors_json)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (chain["chain_id"], timestamp, score, severity, new_factors),
                    )
                    score_changed = True

                resolution_period = {
                    "Low": CHAIN_RESOLUTION_LOW_MEDIUM_SECONDS,
                    "Medium": CHAIN_RESOLUTION_LOW_MEDIUM_SECONDS,
                    "High": CHAIN_RESOLUTION_HIGH_SECONDS,
                    "Critical": CHAIN_RESOLUTION_CRITICAL_SECONDS,
                }[evidence_severity]
                resolved = False
                if (
                    activity_dt is not None
                    and score == 0
                    and inactivity_seconds >= resolution_period
                ):
                    resolved = conn.execute(
                        """
                        UPDATE attack_chains
                        SET status = 'resolved', last_updated = ?
                        WHERE id = ? AND status = 'active'
                        """,
                        (timestamp, chain["id"]),
                    ).rowcount == 1

                if score_changed or resolved or activity_updated:
                    conn.commit()

                if score_changed:
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

                if resolved:
                    resolution_payload = {
                        "chain_id": chain["chain_id"],
                        "status": "resolved",
                        "score": score,
                        "severity_label": severity,
                        "evidence_severity": evidence_severity,
                        "timestamp": timestamp,
                        "last_activity_at": activity_dt.isoformat(),
                        "inactivity_seconds": inactivity_seconds,
                        "reason": "inactivity",
                    }
                    try:
                        self.bus.publish(
                            EventBus.CHAIN_RESOLVED,
                            resolution_payload,
                        )
                        logger.info(
                            "Published %s for %s",
                            EventBus.CHAIN_RESOLVED,
                            chain["chain_id"],
                        )
                    except Exception:
                        logger.exception(
                            "CHAIN_RESOLVED publish failed for %s",
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
            logger.warning("Malformed NEW_ALERT ignored: expected an object")
            return

        try:
            timestamp_value = payload.get("timestamp")
            if not isinstance(timestamp_value, str) or not timestamp_value.strip():
                raise ValueError("timestamp must be a non-empty string")
            event_dtt = self.normalize_timestamp(timestamp_value)
            source_ip = self._validated_ip(payload.get("source_ip"), "source_ip")
            target_ip = self._validated_ip(payload.get("target_ip"), "target_ip")
            target_node = payload.get("target_node")
            attack_type = payload.get("attack_type")
            detection_source = payload.get("detection_source")
            if detection_source is None:
                detection_source = "unknown"

            if not isinstance(attack_type, str) or not attack_type.strip():
                raise ValueError("attack_type is required")
            if not isinstance(detection_source, str):
                raise ValueError("detection_source must be a string")
            if target_node is not None and not isinstance(target_node, str):
                raise ValueError("target_node must be a string or null")

            if target_node is not None:
                target_node = target_node.strip() or None
            normalized_attack_type = attack_type.strip().lower()
            if normalized_attack_type in ATTACK_TO_MITRE:
                attack_type = normalized_attack_type
            detection_source = detection_source.strip() or "unknown"
            event_time = self.parse_ts(event_dtt)
            raw_details = json.dumps(payload, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError):
            logger.warning("Malformed NEW_ALERT ignored: validation failed")
            return

        seen_key = (
            f"{event_dtt}|{source_ip}|{target_ip}|{target_node or ''}|"
            f"{attack_type}|{detection_source}"
        )
        safe_event_id = hashlib.sha256(seen_key.encode("utf-8")).hexdigest()[:12]
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
                logger.info("Duplicate alert ignored (event=%s)", safe_event_id)
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
                    ATTACK_TO_MITRE.get(attack_type),
                    raw_details,
                ),
            )
            conn.commit()
            logger.info("Inserted NEW_ALERT (event=%s)", safe_event_id)
        except Exception:
            conn.rollback()
            logger.error("NEW_ALERT insertion failed (database error)")
            return
        finally:
            conn.close()

        self.map_mitre_tactics()
        self.correlate_chains()
        self.score_chains()

    def insert_ml_prediction_from_event(self, payload):
        """Safely store an ML_PREDICTION event if it is well-formed for the shared schema in shared/schema.sql."""
        if not isinstance(payload, dict):
            logger.warning("Malformed ML_PREDICTION ignored: expected an object")
            return

        try:
            timestamp_value = payload.get("timestamp")
            if not isinstance(timestamp_value, str) or not timestamp_value.strip():
                raise ValueError("timestamp must be a non-empty string")
            timestamp = self.normalize_timestamp(timestamp_value)
            target_node = payload.get("target_node")
            predicted_class = payload.get("predicted_class")
            confidence_value = payload.get("confidence")
            prediction_id = payload.get("prediction_id")
            if prediction_id is not None and (
                isinstance(prediction_id, bool)
                or not isinstance(prediction_id, int)
                or prediction_id <= 0
            ):
                raise ValueError("prediction_id must be a positive integer")
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
        except (TypeError, ValueError):
            logger.warning("Malformed ML_PREDICTION ignored: validation failed")
            return

        conn = self.connect()
        stored = False
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing_by_id = (
                conn.execute(
                    """
                    SELECT timestamp, target_node, predicted_class, confidence
                    FROM ml_predictions WHERE id = ?
                    """,
                    (prediction_id,),
                ).fetchone()
                if prediction_id is not None
                else None
            )
            if existing_by_id:
                existing_time = self.parse_ts(existing_by_id["timestamp"])
                payload_time = self.parse_ts(timestamp)
                if (
                    existing_time == payload_time
                    and existing_by_id["target_node"] == target_node
                    and existing_by_id["predicted_class"] == predicted_class
                    and float(existing_by_id["confidence"]) == confidence
                ):
                    stored = True
                    logger.info("Existing ML prediction reused")
                else:
                    logger.warning("ML prediction identifier did not match stored record")

            if not stored:
                existing = conn.execute(
                    """
                    SELECT id FROM ml_predictions
                    WHERE timestamp = ? AND target_node IS ?
                      AND predicted_class = ? AND confidence = ?
                    LIMIT 1
                    """,
                    (timestamp, target_node, predicted_class, confidence),
                ).fetchone()
                if existing:
                    stored = True
                    logger.info("Duplicate ML prediction ignored")
                else:
                    insert_id = (
                        prediction_id
                        if prediction_id is not None and existing_by_id is None
                        else None
                    )
                    if insert_id is None:
                        conn.execute(
                            """
                            INSERT INTO ml_predictions
                            (timestamp, window_start, window_end, target_node,
                             predicted_class, confidence, features_json)
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
                    else:
                        conn.execute(
                            """
                            INSERT INTO ml_predictions
                            (id, timestamp, window_start, window_end, target_node,
                             predicted_class, confidence, features_json)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                insert_id,
                                timestamp,
                                window_start,
                                window_end,
                                target_node,
                                predicted_class,
                                confidence,
                                features_json,
                            ),
                        )
                    stored = True
            conn.commit()
        except Exception:
            conn.rollback()
            logger.error("ML_PREDICTION insertion failed (database error)")
        finally:
            conn.close()
        if stored:
            self.score_chains()

    def _event_messages(self):
        pubsub = getattr(self.bus, "pubsub", None)
        if pubsub is None:
            for event in self.bus.listen():
                if not isinstance(event, (tuple, list)) or len(event) != 2:
                    logger.warning("Malformed Redis event ignored: invalid event envelope")
                    continue
                yield event[0], event[1]
            return

        for message in pubsub.listen():
            if not isinstance(message, dict):
                logger.warning("Malformed Redis event ignored: invalid message")
                continue
            if message.get("type") != "message":
                continue
            channel = message.get("channel")
            if not isinstance(channel, str):
                logger.warning("Malformed Redis event ignored: invalid channel")
                continue
            try:
                payload = json.loads(message.get("data"))
            except (TypeError, ValueError):
                logger.warning("Malformed Redis event ignored: invalid JSON")
                continue
            yield channel, payload

    def start_event_listener(self):
        """Subscribe to both NEW_ALERT and ML_PREDICTION while allowing fixture/database mode to remain independent of Person A."""
        def worker():
            while True:
                try:
                    self.bus.subscribe([EventBus.NEW_ALERT, EventBus.ML_PREDICTION])
                    for channel, payload in self._event_messages():
                        try:
                            if channel == EventBus.NEW_ALERT:
                                self.insert_alert_from_event(payload)
                            elif channel == EventBus.ML_PREDICTION:
                                self.insert_ml_prediction_from_event(payload)
                        except Exception as exc:
                            logger.warning(
                                "Redis event processing failed (%s)",
                                type(exc).__name__,
                            )
                except Exception as exc:
                    logger.warning(
                        "Redis listener stopped or unavailable (%s)",
                        type(exc).__name__,
                    )
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
