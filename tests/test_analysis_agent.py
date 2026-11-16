import importlib.util
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

ANALYSIS_SRC = os.path.join(ROOT, "person-b-analysis", "src")
if ANALYSIS_SRC not in sys.path:
    sys.path.insert(0, ANALYSIS_SRC)

from analysis_agent import AnalysisAgent


class FakeBus:
    def __init__(self):
        self.events = []

    def publish(self, event_type, payload):
        self.events.append((event_type, payload))

    def subscribe(self, event_types):
        return None

    def listen(self):
        return iter(())


class TemporaryAnalysisAgent(AnalysisAgent):
    def __init__(self, db_path):
        self.database_path = str(db_path)
        self.redis_host = "localhost"
        self.redis_port = 6379
        self.bus = FakeBus()
        self.alert_seen_keys = set()
        self.ensure_schema()


def seed_alerts(agent, rows):
    conn = sqlite3.connect(agent.database_path)
    conn.executemany(
        """
        INSERT INTO alerts
        (timestamp, source_ip, target_ip, target_node, attack_type, detection_source, mitre_tactic, raw_details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()
    conn.close()


def test_map_mitre_tactics_backfills_and_corrects_existing_alerts(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    now = datetime.now(timezone.utc)
    seed_alerts(
        agent,
        [
            (now.isoformat(), "10.0.0.5", "10.0.0.11", "edge-node-1", "port_scan", "scapy", None, "{}"),
            ( (now + timedelta(minutes=2)).isoformat(), "10.0.0.5", "10.0.0.12", "edge-node-2", "ddos", "both", "TA0008", "{}"),
        ],
    )

    agent.map_mitre_tactics()
    conn = sqlite3.connect(agent.database_path)
    mapped = {row[0]: row[1] for row in conn.execute("SELECT attack_type, mitre_tactic FROM alerts ORDER BY timestamp")}
    conn.close()

    assert mapped["port_scan"] == "TA0043"
    assert mapped["ddos"] == "TA0040"


def test_correlate_chains_across_different_nodes_and_target_ips(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    rows = [
        (base.isoformat(), "203.0.113.10", "10.0.0.11", "edge-node-1", "port_scan", "scapy", None, json.dumps({"n": 1})),
        ( (base + timedelta(minutes=1)).isoformat(), "203.0.113.10", "10.0.0.12", "edge-node-2", "brute_force", "both", None, json.dumps({"n": 2})),
        ( (base + timedelta(minutes=2)).isoformat(), "203.0.113.10", "10.0.0.13", "edge-node-3", "lateral_movement", "suricata", None, json.dumps({"n": 3})),
        ( (base + timedelta(minutes=3)).isoformat(), "203.0.113.10", "10.0.0.12", "edge-node-2", "ddos", "both", None, json.dumps({"n": 4})),
    ]
    seed_alerts(agent, rows)

    agent.correlate_chains()

    conn = sqlite3.connect(agent.database_path)
    chain_rows = conn.execute("SELECT chain_id, alert_ids, mitre_sequence FROM attack_chains").fetchall()
    conn.close()

    assert len(chain_rows) == 1
    chain = chain_rows[0]
    assert chain[2] == "TA0043 -> TA0006 -> TA0008 -> TA0040"
    assert json.loads(chain[1]) == [1, 2, 3, 4]


def test_same_source_multiple_campaigns_are_kept_separate(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 1, 3, 9, 0, 0, tzinfo=timezone.utc)
    rows = [
        (base.isoformat(), "198.51.100.44", "10.0.0.11", "edge-node-1", "port_scan", "scapy", None, "{}"),
        ((base + timedelta(minutes=1)).isoformat(), "198.51.100.44", "10.0.0.12", "edge-node-2", "brute_force", "both", None, "{}"),
        ((base + timedelta(minutes=2)).isoformat(), "198.51.100.44", "10.0.0.13", "edge-node-3", "lateral_movement", "suricata", None, "{}"),
        ((base + timedelta(minutes=20)).isoformat(), "198.51.100.44", "10.0.0.11", "edge-node-1", "port_scan", "scapy", None, "{}"),
        ((base + timedelta(minutes=21)).isoformat(), "198.51.100.44", "10.0.0.12", "edge-node-2", "brute_force", "both", None, "{}"),
        ((base + timedelta(minutes=22)).isoformat(), "198.51.100.44", "10.0.0.13", "edge-node-3", "lateral_movement", "suricata", None, "{}"),
    ]
    seed_alerts(agent, rows)

    agent.correlate_chains()

    conn = sqlite3.connect(agent.database_path)
    chain_count = conn.execute("SELECT COUNT(*) FROM attack_chains").fetchone()[0]
    chain_ids = [row[0] for row in conn.execute("SELECT chain_id FROM attack_chains ORDER BY start_time")]
    conn.close()

    assert chain_count == 2
    assert len(chain_ids) == 2


def test_normalize_timestamp_handles_utc_offsets(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    assert agent.normalize_timestamp("2026-01-04T08:30:00+05:30") == "2026-01-04T03:00:00+00:00"
    assert agent.normalize_timestamp("2026-01-04T03:00:00") == "2026-01-04T03:00:00+00:00"
    assert agent.normalize_timestamp("2026-01-04T03:00:00Z") == "2026-01-04T03:00:00+00:00"


def test_mixed_timestamps_sort_and_correlate_in_same_campaign(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    rows = [
        ("2026-01-06T12:00:00", "198.51.100.66", "10.0.0.11", "edge-node-1", "port_scan", "scapy", None, "{}"),
        ("2026-01-06T07:01:00-05:00", "198.51.100.66", "10.0.0.12", "edge-node-2", "brute_force", "both", None, "{}"),
        ("2026-01-06T07:02:00-05:00", "198.51.100.66", "10.0.0.13", "edge-node-3", "lateral_movement", "suricata", None, "{}"),
        ("2026-01-06T12:03:00+00:00", "198.51.100.66", "10.0.0.12", "edge-node-2", "ddos", "both", None, "{}"),
    ]
    seed_alerts(agent, rows)

    agent.correlate_chains()

    conn = sqlite3.connect(agent.database_path)
    record = conn.execute("SELECT alert_ids, mitre_sequence FROM attack_chains").fetchone()
    conn.close()

    assert record is not None
    assert json.loads(record[0]) == [1, 2, 3, 4]
    assert record[1] == "TA0043 -> TA0006 -> TA0008 -> TA0040"


def test_mixed_timestamp_campaign_respects_fifteen_minute_window(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    rows = [
        ("2026-01-07T08:00:00", "203.0.113.99", "10.0.0.11", "edge-node-1", "port_scan", "scapy", None, "{}"),
        ("2026-01-07T08:10:00+00:00", "203.0.113.99", "10.0.0.12", "edge-node-2", "brute_force", "both", None, "{}"),
        ("2026-01-07T08:16:00+00:00", "203.0.113.99", "10.0.0.13", "edge-node-3", "lateral_movement", "suricata", None, "{}"),
    ]
    seed_alerts(agent, rows)

    agent.correlate_chains()

    conn = sqlite3.connect(agent.database_path)
    count = conn.execute("SELECT COUNT(*) FROM attack_chains").fetchone()[0]
    conn.close()

    assert count == 0


def test_insert_alert_from_event_is_idempotent(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    payload = {
        "timestamp": "2026-01-05T12:00:00+00:00",
        "source_ip": "192.0.2.77",
        "target_ip": "10.0.0.11",
        "target_node": "edge-node-1",
        "attack_type": "port_scan",
        "detection_source": "scapy",
    }

    agent.insert_alert_from_event(payload)
    agent.insert_alert_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    count = conn.execute("SELECT COUNT(*) FROM alerts WHERE source_ip = '192.0.2.77' AND attack_type = 'port_scan'").fetchone()[0]
    conn.close()
    assert count == 1


def test_shared_eventbus_contract_matches_analysis_agent_usage():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    spec = importlib.util.spec_from_file_location("shared.eventbus_client", os.path.join(root, "shared", "eventbus_client.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert hasattr(module, "EventBus")
    assert hasattr(module.EventBus, "NEW_ALERT")
    assert hasattr(module.EventBus, "ML_PREDICTION")
    assert hasattr(module.EventBus, "CHAIN_DETECTED")
    assert hasattr(module.EventBus, "SCORE_COMPUTED")
    assert callable(module.EventBus.publish)
    assert callable(module.EventBus.subscribe)
    assert callable(module.EventBus.listen)


def test_analysis_agent_imports_shared_eventbus_in_repo_context():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sys.path.insert(0, root)
    agent_path = os.path.join(root, "person-b-analysis", "src", "analysis_agent.py")
    spec = importlib.util.spec_from_file_location("analysis_agent_repo", agent_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert hasattr(module, "EventBus")
    assert module.EventBus.__name__ == "EventBus"


def test_correlate_chains_rejects_wrong_order_and_outside_fifteen_minutes(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    rows = [
        (base.isoformat(), "198.51.100.7", "10.0.0.11", "edge-node-1", "lateral_movement", "suricata", None, "{}"),
        ( (base + timedelta(minutes=5)).isoformat(), "198.51.100.7", "10.0.0.12", "edge-node-2", "brute_force", "both", None, "{}"),
        ( (base + timedelta(minutes=22)).isoformat(), "198.51.100.7", "10.0.0.11", "edge-node-1", "port_scan", "scapy", None, "{}"),
    ]
    seed_alerts(agent, rows)

    agent.correlate_chains()

    conn = sqlite3.connect(agent.database_path)
    count = conn.execute("SELECT COUNT(*) FROM attack_chains").fetchone()[0]
    conn.close()

    assert count == 0


def test_score_chains_ignores_duplicate_evidence_but_updates_on_new_evidence(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 1, 2, 8, 0, 0, tzinfo=timezone.utc)
    rows = [
        (base.isoformat(), "192.0.2.30", "10.0.0.11", "edge-node-1", "port_scan", "scapy", "TA0043", "{}"),
        ( (base + timedelta(minutes=1)).isoformat(), "192.0.2.30", "10.0.0.12", "edge-node-2", "brute_force", "both", "TA0006", "{}"),
        ( (base + timedelta(minutes=2)).isoformat(), "192.0.2.30", "10.0.0.13", "edge-node-3", "lateral_movement", "suricata", "TA0008", "{}"),
    ]
    seed_alerts(agent, rows)

    conn = sqlite3.connect(agent.database_path)
    conn.execute(
        "INSERT INTO attack_chains (chain_id, alert_ids, mitre_sequence, start_time, last_updated, status) VALUES (?, ?, ?, ?, ?, ?)",
        ("chain-abc", json.dumps([1, 2, 3]), "TA0043 -> TA0006 -> TA0008", rows[0][0], rows[2][0], "active"),
    )
    conn.commit()
    conn.close()

    agent.score_chains()
    conn = sqlite3.connect(agent.database_path)
    first_count = conn.execute("SELECT COUNT(*) FROM threat_scores").fetchone()[0]
    first_score = conn.execute("SELECT score, severity_label, factors_json FROM threat_scores WHERE chain_id = 'chain-abc' ORDER BY timestamp DESC LIMIT 1").fetchone()
    conn.close()

    assert first_score[0] == 75
    assert first_score[1] == "High"
    assert first_count == 1

    # New evidence is captured by a second score update with a new ddos stage.
    ddos_row = (
        (base + timedelta(minutes=4)).isoformat(),
        "192.0.2.30",
        "10.0.0.11",
        "edge-node-1",
        "ddos",
        "both",
        "TA0040",
        "{}",
    )
    seed_alerts(agent, [ddos_row])

    conn = sqlite3.connect(agent.database_path)
    current = conn.execute("SELECT MAX(id) FROM alerts").fetchone()[0]
    conn.execute(
        "UPDATE attack_chains SET alert_ids = ?, last_updated = ? WHERE chain_id = 'chain-abc'",
        (json.dumps([1, 2, 3, current]), datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()

    agent.score_chains()
    conn = sqlite3.connect(agent.database_path)
    rows = conn.execute("SELECT score, severity_label, factors_json FROM threat_scores WHERE chain_id = 'chain-abc' ORDER BY timestamp DESC LIMIT 2").fetchall()
    conn.close()

    assert len(rows) == 2
    assert rows[0][0] == 100
    assert rows[0][1] == "Critical"
    assert "attack_types" in json.loads(rows[0][2])
