import importlib.util
import json
import os
import sqlite3
import sys
import threading
from datetime import datetime, timedelta, timezone

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

ANALYSIS_SRC = os.path.join(ROOT, "person-b-analysis", "src")
analysis_spec = importlib.util.spec_from_file_location(
    "analysis_agent",
    os.path.join(ANALYSIS_SRC, "analysis_agent.py"),
)
if analysis_spec is None or analysis_spec.loader is None:
    raise ImportError("Could not load Person B analysis agent")
analysis_agent_module = importlib.util.module_from_spec(analysis_spec)
analysis_spec.loader.exec_module(analysis_agent_module)

AnalysisAgent = analysis_agent_module.AnalysisAgent


class FakeBus:
    def __init__(self):
        self.events = []
        self.subscriptions = []

    def publish(self, event_type, payload):
        self.events.append((event_type, payload))

    def subscribe(self, event_types):
        self.subscriptions.append(list(event_types))
        return None

    def listen(self):
        return iter(())


class TemporaryAnalysisAgent(AnalysisAgent):
    def __init__(self, db_path):
        self.database_path = str(db_path)
        self.redis_host = "localhost"
        self.redis_port = 6379
        self.bus = FakeBus()
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
            ((now + timedelta(minutes=1)).isoformat(), "10.0.0.5", "10.0.0.12", "edge-node-2", "brute_force", "both", None, "{}"),
            ((now + timedelta(minutes=2)).isoformat(), "10.0.0.5", "10.0.0.13", "edge-node-3", "lateral_movement", "suricata", None, "{}"),
            ( (now + timedelta(minutes=2)).isoformat(), "10.0.0.5", "10.0.0.12", "edge-node-2", "ddos", "both", "TA0008", "{}"),
            ((now + timedelta(minutes=3)).isoformat(), "10.0.0.5", "10.0.0.14", "edge-node-4", "unknown", "scapy", None, "{}"),
        ],
    )

    agent.map_mitre_tactics()
    conn = sqlite3.connect(agent.database_path)
    mapped = {
        row[0]: row[1]
        for row in conn.execute("SELECT attack_type, mitre_tactic FROM alerts")
    }
    conn.close()

    assert mapped["port_scan"] == "TA0043"
    assert mapped["brute_force"] == "TA0006"
    assert mapped["lateral_movement"] == "TA0008"
    assert mapped["ddos"] == "TA0040"
    assert mapped["unknown"] is None


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


def test_out_of_order_alert_insertions_are_chronologically_correlated(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 1, 6, 12, 0, 0, tzinfo=timezone.utc)
    rows = [
        ((base + timedelta(minutes=3)).isoformat(), "198.51.100.67", "10.0.0.14", "edge-node-2", "ddos", "both", None, "{}"),
        ((base + timedelta(minutes=2)).isoformat(), "198.51.100.67", "10.0.0.13", "edge-node-3", "lateral_movement", "suricata", None, "{}"),
        ((base + timedelta(minutes=1)).isoformat(), "198.51.100.67", "10.0.0.12", "edge-node-2", "brute_force", "both", None, "{}"),
        (base.isoformat(), "198.51.100.67", "10.0.0.11", "edge-node-1", "port_scan", "scapy", None, "{}"),
    ]
    seed_alerts(agent, rows)

    agent.correlate_chains()

    conn = sqlite3.connect(agent.database_path)
    record = conn.execute(
        "SELECT alert_ids, mitre_sequence FROM attack_chains"
    ).fetchone()
    conn.close()
    assert json.loads(record[0]) == [4, 3, 2, 1]
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


def test_correlate_chains_updates_same_chain_when_ddos_arrives(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 2, 1, 12, 0, tzinfo=timezone.utc)
    rows = [
        (base.isoformat(), "192.0.2.40", "10.0.0.11", "edge-node-1", "port_scan", "scapy", None, "{}"),
        ((base + timedelta(minutes=1)).isoformat(), "192.0.2.40", "10.0.0.12", "edge-node-2", "brute_force", "both", None, "{}"),
        ((base + timedelta(minutes=2)).isoformat(), "192.0.2.40", "10.0.0.13", "edge-node-3", "lateral_movement", "suricata", None, "{}"),
    ]
    seed_alerts(agent, rows)

    agent.correlate_chains()
    conn = sqlite3.connect(agent.database_path)
    original_chain_id = conn.execute("SELECT chain_id FROM attack_chains").fetchone()[0]
    conn.close()

    seed_alerts(
        agent,
        [
            ((base + timedelta(minutes=3)).isoformat(), "192.0.2.40", "10.0.0.14", "edge-node-4", "ddos", "both", None, "{}"),
        ],
    )
    agent.correlate_chains()
    agent.correlate_chains()

    conn = sqlite3.connect(agent.database_path)
    chains = conn.execute(
        "SELECT chain_id, alert_ids, mitre_sequence FROM attack_chains"
    ).fetchall()
    conn.close()

    assert len(chains) == 1
    assert chains[0][0] == original_chain_id
    assert json.loads(chains[0][1]) == [1, 2, 3, 4]
    assert chains[0][2] == "TA0043 -> TA0006 -> TA0008 -> TA0040"
    chain_events = [event for event in agent.bus.events if event[0] == "CHAIN_DETECTED"]
    assert len(chain_events) == 2
    assert chain_events[-1][1]["chain_id"] == original_chain_id


def test_correlate_chains_separates_overlapping_campaign_ids(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 2, 2, 12, 0, tzinfo=timezone.utc)
    events = [
        (0, "campaign-a", "port_scan", "edge-node-1"),
        (10, "campaign-b", "port_scan", "edge-node-2"),
        (60, "campaign-a", "brute_force", "edge-node-2"),
        (70, "campaign-b", "brute_force", "edge-node-3"),
        (120, "campaign-a", "lateral_movement", "edge-node-3"),
        (130, "campaign-b", "lateral_movement", "edge-node-1"),
    ]
    rows = [
        (
            (base + timedelta(seconds=seconds)).isoformat(),
            (
                "192.0.2.41"
                if campaign == "campaign-a"
                else f"192.0.2.{42 + index}"
            ),
            f"10.0.0.{index + 11}",
            node,
            attack,
            "both",
            None,
            json.dumps({"campaign_id": campaign}),
        )
        for index, (seconds, campaign, attack, node) in enumerate(events)
    ]
    seed_alerts(agent, rows)

    agent.correlate_chains()

    conn = sqlite3.connect(agent.database_path)
    chains = [
        json.loads(row[0])
        for row in conn.execute("SELECT alert_ids FROM attack_chains")
    ]
    conn.close()

    assert sorted(chains) == [[1, 3, 5], [2, 4, 6]]


def test_alert_event_deduplicates_existing_sensor_record_and_after_restart(tmp_path):
    db_path = tmp_path / "edgeshield.db"
    agent = TemporaryAnalysisAgent(db_path)
    timestamp = "2026-02-03T08:00:00-05:00"
    payload = {
        "timestamp": timestamp,
        "source_ip": "192.0.2.42",
        "target_ip": "10.0.0.11",
        "target_node": "edge-node-1",
        "attack_type": "port_scan",
        "detection_source": "scapy",
    }
    seed_alerts(
        agent,
        [
            (
                timestamp,
                payload["source_ip"],
                payload["target_ip"],
                payload["target_node"],
                payload["attack_type"],
                payload["detection_source"],
                None,
                "{}",
            ),
        ],
    )

    agent.insert_alert_from_event(payload)
    restarted_agent = TemporaryAnalysisAgent(db_path)
    restarted_agent.insert_alert_from_event(payload)

    conn = sqlite3.connect(db_path)
    count = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE source_ip = ?",
        (payload["source_ip"],),
    ).fetchone()[0]
    conn.close()
    assert count == 1


def test_new_alert_payloads_flow_through_chain_scoring(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 2, 3, 12, 0, tzinfo=timezone.utc)
    payloads = [
        {
            "timestamp": base.isoformat(),
            "source_ip": "192.0.2.46",
            "target_ip": "10.0.0.11",
            "target_node": "edge-node-1",
            "attack_type": "port_scan",
            "detection_source": "scapy",
            "campaign_id": "campaign-46",
        },
        {
            "timestamp": (base + timedelta(minutes=1)).isoformat(),
            "source_ip": "192.0.2.47",
            "target_ip": "10.0.0.12",
            "target_node": "edge-node-2",
            "attack_type": "brute_force",
            "detection_source": "both",
            "campaign_id": "campaign-46",
        },
        {
            "timestamp": (base + timedelta(minutes=2)).isoformat(),
            "source_ip": "192.0.2.48",
            "target_ip": "10.0.0.13",
            "target_node": "edge-node-3",
            "attack_type": "lateral_movement",
            "detection_source": "suricata",
            "campaign_id": "campaign-46",
        },
    ]

    for payload in payloads:
        agent.insert_alert_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    chain = conn.execute(
        "SELECT alert_ids, mitre_sequence FROM attack_chains"
    ).fetchone()
    score = conn.execute(
        "SELECT score, severity_label FROM threat_scores"
    ).fetchone()
    alerts = conn.execute(
        "SELECT source_ip, target_ip, target_node, attack_type, mitre_tactic FROM alerts ORDER BY id"
    ).fetchall()
    conn.close()

    assert len(alerts) == 3
    assert [row[4] for row in alerts] == ["TA0043", "TA0006", "TA0008"]
    assert json.loads(chain[0]) == [1, 2, 3]
    assert chain[1] == "TA0043 -> TA0006 -> TA0008"
    assert score == (75, "High")
    assert [event[0] for event in agent.bus.events] == [
        "CHAIN_DETECTED",
        "SCORE_COMPUTED",
    ]
    assert agent.bus.events[-1][1]["evidence_count"] == 3


def test_concurrent_duplicate_alert_events_create_one_row(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    payload = {
        "timestamp": "2026-02-03T12:00:00Z",
        "source_ip": "192.0.2.49",
        "target_ip": "10.0.0.11",
        "target_node": "edge-node-1",
        "attack_type": "port_scan",
        "detection_source": "scapy",
    }
    barrier = threading.Barrier(2)

    def insert_duplicate():
        barrier.wait()
        agent.insert_alert_from_event(payload)

    threads = [threading.Thread(target=insert_duplicate) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert all(not thread.is_alive() for thread in threads)
    conn = sqlite3.connect(agent.database_path)
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    assert count == 1


@pytest.mark.parametrize(
    "payload",
    [
        {"source_ip": "192.0.2.43", "target_ip": "10.0.0.11"},
        {
            "timestamp": "not-a-timestamp",
            "source_ip": "192.0.2.43",
            "target_ip": "10.0.0.11",
            "attack_type": "port_scan",
            "detection_source": "scapy",
        },
        {
            "timestamp": "2026-02-03T12:00:00Z",
            "source_ip": "192.0.2.43",
            "attack_type": "port_scan",
            "detection_source": "scapy",
        },
        {
            "timestamp": "2026-02-03T12:00:00Z",
            "source_ip": "192.0.2.43",
            "target_ip": "10.0.0.11",
            "attack_type": "unknown",
            "detection_source": "scapy",
        },
    ],
)
def test_malformed_alert_events_are_rejected(tmp_path, payload):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")

    agent.insert_alert_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    assert count == 0


def test_ml_prediction_is_validated_normalized_and_deduplicated(tmp_path):
    db_path = tmp_path / "edgeshield.db"
    agent = TemporaryAnalysisAgent(db_path)
    payload = {
        "timestamp": "2026-02-04T08:00:00-05:00",
        "window_start": "2026-02-04T07:59:00-05:00",
        "window_end": "2026-02-04T08:00:00-05:00",
        "target_node": "edge-node-1",
        "predicted_class": "brute_force",
        "confidence": 0.9,
        "features_json": {"packet_count": 12},
    }

    agent.insert_ml_prediction_from_event(payload)
    agent.insert_ml_prediction_from_event(payload)
    TemporaryAnalysisAgent(db_path).insert_ml_prediction_from_event(payload)

    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT timestamp, window_start, window_end, confidence FROM ml_predictions"
    ).fetchall()
    conn.close()

    assert rows == [
        (
            "2026-02-04T13:00:00+00:00",
            "2026-02-04T12:59:00+00:00",
            "2026-02-04T13:00:00+00:00",
            0.9,
        )
    ]


@pytest.mark.parametrize("confidence", [-0.01, 1.01, float("nan"), float("inf"), "not-a-number", None])
def test_malformed_ml_predictions_are_rejected(tmp_path, confidence):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    payload = {
        "timestamp": "2026-02-04T12:00:00Z",
        "predicted_class": "port_scan",
        "confidence": confidence,
    }

    agent.insert_ml_prediction_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    count = conn.execute("SELECT COUNT(*) FROM ml_predictions").fetchone()[0]
    conn.close()
    assert count == 0


def test_ml_prediction_accepts_zero_confidence(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    agent.insert_ml_prediction_from_event(
        {
            "timestamp": "2026-02-04T12:00:00Z",
            "predicted_class": "benign",
            "confidence": 0,
        }
    )

    conn = sqlite3.connect(agent.database_path)
    confidence = conn.execute("SELECT confidence FROM ml_predictions").fetchone()[0]
    conn.close()
    assert confidence == 0


@pytest.mark.parametrize(
    "payload",
    [
        {"predicted_class": "port_scan", "confidence": 0.8},
        {"timestamp": "2026-02-04T12:00:00Z", "confidence": 0.8},
        {"timestamp": "2026-02-04T12:00:00Z", "predicted_class": "port_scan"},
    ],
)
def test_ml_prediction_requires_timestamp_class_and_confidence(tmp_path, payload):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")

    agent.insert_ml_prediction_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    count = conn.execute("SELECT COUNT(*) FROM ml_predictions").fetchone()[0]
    conn.close()
    assert count == 0


def test_event_listener_subscribes_to_alert_and_prediction_channels(tmp_path, monkeypatch):
    class StopListener(Exception):
        pass

    class ImmediateThread:
        def __init__(self, target, name, daemon):
            self.target = target
            self.name = name
            self.daemon = daemon

        def start(self):
            try:
                self.target()
            except StopListener:
                pass

    def stop_after_sleep(seconds):
        assert seconds == 5
        raise StopListener()

    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    bus = FakeBus()
    agent.bus = bus
    monkeypatch.setattr(analysis_agent_module.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(analysis_agent_module.time, "sleep", stop_after_sleep)

    agent.start_event_listener()

    assert bus.subscriptions == [[
        analysis_agent_module.EventBus.NEW_ALERT,
        analysis_agent_module.EventBus.ML_PREDICTION,
    ]]


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "Low"),
        (29, "Low"),
        (30, "Medium"),
        (49, "Medium"),
        (50, "High"),
        (84, "High"),
        (85, "Critical"),
        (100, "Critical"),
    ],
)
def test_severity_classification_boundaries(tmp_path, score, expected):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    assert agent.severity_for_score(score) == expected


def test_scores_preserve_correlated_order_for_timezone_mixed_alerts(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    rows = [
        ("2026-02-05T12:00:00+00:00", "192.0.2.44", "10.0.0.11", "edge-node-1", "port_scan", "scapy", "TA0043", "{}"),
        ("2026-02-05T08:01:00-04:00", "192.0.2.44", "10.0.0.12", "edge-node-2", "brute_force", "both", "TA0006", "{}"),
        ("2026-02-05T04:02:00-08:00", "192.0.2.44", "10.0.0.13", "edge-node-3", "lateral_movement", "suricata", "TA0008", "{}"),
    ]
    seed_alerts(agent, rows)
    conn = sqlite3.connect(agent.database_path)
    conn.execute(
        """
        INSERT INTO attack_chains
        (chain_id, alert_ids, mitre_sequence, start_time, last_updated, status)
        VALUES (?, ?, ?, ?, ?, 'active')
        """,
        (
            "chain-order",
            json.dumps([1, 2, 3]),
            "TA0043 -> TA0006 -> TA0008",
            rows[0][0],
            rows[-1][0],
        ),
    )
    conn.commit()
    conn.close()

    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    factors = json.loads(
        conn.execute(
            "SELECT factors_json FROM threat_scores WHERE chain_id = 'chain-order'"
        ).fetchone()[0]
    )
    conn.close()
    assert factors["attack_types_ordered"] == [
        "port_scan",
        "brute_force",
        "lateral_movement",
    ]


def test_failed_redis_publish_does_not_lose_persisted_analysis(tmp_path, caplog):
    class FailingBus(FakeBus):
        def publish(self, event_type, payload):
            raise RuntimeError(
                f"Redis unavailable while publishing {event_type} with {len(payload)} fields"
            )

    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    agent.bus = FailingBus()
    base = datetime(2026, 2, 6, 12, 0, tzinfo=timezone.utc)
    seed_alerts(
        agent,
        [
            (base.isoformat(), "192.0.2.45", "10.0.0.11", "edge-node-1", "port_scan", "scapy", None, "{}"),
            ((base + timedelta(minutes=1)).isoformat(), "192.0.2.45", "10.0.0.12", "edge-node-2", "brute_force", "both", None, "{}"),
            ((base + timedelta(minutes=2)).isoformat(), "192.0.2.45", "10.0.0.13", "edge-node-3", "lateral_movement", "suricata", None, "{}"),
        ],
    )

    agent.correlate_chains()
    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    chain_count = conn.execute("SELECT COUNT(*) FROM attack_chains").fetchone()[0]
    score_count = conn.execute("SELECT COUNT(*) FROM threat_scores").fetchone()[0]
    conn.close()
    assert chain_count == 1
    assert score_count == 1
    assert "CHAIN_DETECTED publish failed" in caplog.text
    assert "SCORE_COMPUTED publish failed" in caplog.text
