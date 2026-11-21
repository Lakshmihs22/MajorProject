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

MOCK_ALERTS_SPEC = importlib.util.spec_from_file_location(
    "mock_alerts",
    os.path.join(ROOT, "fixtures", "mock_alerts.py"),
)
if MOCK_ALERTS_SPEC is None or MOCK_ALERTS_SPEC.loader is None:
    raise ImportError("Could not load mock alert fixture")
mock_alerts_module = importlib.util.module_from_spec(MOCK_ALERTS_SPEC)
MOCK_ALERTS_SPEC.loader.exec_module(mock_alerts_module)


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


def freeze_agent_time(agent, timestamp):
    agent.now_iso = lambda: timestamp.isoformat()


def seed_scoring_chain(agent, attack_types, base, chain_id="chain-decay"):
    alert_rows = [
        (
            (base + timedelta(minutes=index)).isoformat(),
            "192.0.2.201",
            f"10.1.0.{index + 1}",
            f"edge-node-{index + 1}",
            attack_type,
            "scapy",
            None,
            "{}",
        )
        for index, attack_type in enumerate(attack_types)
    ]
    seed_alerts(agent, alert_rows)
    conn = sqlite3.connect(agent.database_path)
    alert_ids = [
        row[0]
        for row in conn.execute(
            "SELECT id FROM alerts ORDER BY id"
        ).fetchall()
    ]
    start_time = alert_rows[0][0]
    last_activity_at = alert_rows[-1][0]
    conn.execute(
        """
        INSERT INTO attack_chains
        (chain_id, alert_ids, mitre_sequence, start_time, last_updated,
         last_activity_at, status)
        VALUES (?, ?, ?, ?, ?, ?, 'active')
        """,
        (
            chain_id,
            json.dumps(alert_ids),
            " -> ".join(analysis_agent_module.ATTACK_TO_MITRE[attack] for attack in attack_types),
            start_time,
            last_activity_at,
            last_activity_at,
        ),
    )
    conn.commit()
    conn.close()
    return chain_id


def seed_ml_prediction(
    agent,
    timestamp,
    target_node,
    predicted_class,
    confidence,
    prediction_id=None,
    window_start=None,
    window_end=None,
    features_json="{}",
):
    conn = sqlite3.connect(agent.database_path)
    if prediction_id is None:
        conn.execute(
            """
            INSERT INTO ml_predictions
            (timestamp, window_start, window_end, target_node, predicted_class,
             confidence, features_json)
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
            (id, timestamp, window_start, window_end, target_node, predicted_class,
             confidence, features_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                prediction_id,
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
            ((now + timedelta(minutes=3)).isoformat(), "10.0.0.5", "10.0.0.14", "edge-node-4", "unknown", "scapy", "TA0001", "{}"),
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


def test_synthetic_fixture_alerts_do_not_mix_with_or_replace_live_chains(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    seed_alerts(
        agent,
        [
            (
                base.isoformat(),
                "203.0.113.10",
                "10.0.0.11",
                "edge-node-1",
                "port_scan",
                "scapy",
                None,
                "mock alert #0",
            ),
            (
                (base + timedelta(minutes=1)).isoformat(),
                "203.0.113.10",
                "10.0.0.12",
                "edge-node-2",
                "brute_force",
                "both",
                None,
                json.dumps({"is_synthetic": True}),
            ),
            (
                (base + timedelta(minutes=2)).isoformat(),
                "203.0.113.10",
                "10.0.0.13",
                "edge-node-3",
                "lateral_movement",
                "suricata",
                None,
                "{}",
            ),
            (
                base.isoformat(),
                "203.0.113.20",
                "10.0.1.11",
                "edge-node-1",
                "port_scan",
                "scapy",
                None,
                "{}",
            ),
            (
                (base + timedelta(minutes=1)).isoformat(),
                "203.0.113.20",
                "10.0.1.12",
                "edge-node-2",
                "brute_force",
                "both",
                None,
                "{}",
            ),
            (
                (base + timedelta(minutes=2)).isoformat(),
                "203.0.113.20",
                "10.0.1.13",
                "edge-node-3",
                "lateral_movement",
                "suricata",
                None,
                "{}",
            ),
        ],
    )

    agent.correlate_chains()

    conn = sqlite3.connect(agent.database_path)
    alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    chains = conn.execute("SELECT alert_ids FROM attack_chains").fetchall()
    conn.close()

    assert alert_count == 6
    assert [json.loads(row[0]) for row in chains] == [[4, 5, 6]]


def test_mock_alert_generator_reuses_campaign_and_marks_alerts_synthetic(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "edgeshield.db"
    monkeypatch.setattr(
        mock_alerts_module.random,
        "randint",
        lambda lower, upper: lower,
    )

    mock_alerts_module.main(str(db_path))
    conn = sqlite3.connect(db_path)
    first_run = [
        json.loads(row[0])
        for row in conn.execute(
            "SELECT raw_details FROM alerts ORDER BY id"
        )
    ]
    conn.close()

    mock_alerts_module.main(str(db_path))
    conn = sqlite3.connect(db_path)
    all_runs = [
        json.loads(row[0])
        for row in conn.execute(
            "SELECT raw_details FROM alerts ORDER BY id"
        )
    ]
    conn.close()
    second_run = all_runs[len(first_run):]

    first_campaign_ids = {details["campaign_id"] for details in first_run}
    second_campaign_ids = {details["campaign_id"] for details in second_run}
    assert len(first_run) == 50
    assert len(second_run) == 50
    assert len(first_campaign_ids) == 1
    assert len(second_campaign_ids) == 1
    assert first_campaign_ids.isdisjoint(second_campaign_ids)
    assert all(details["is_synthetic"] is True for details in all_runs)

    agent = TemporaryAnalysisAgent(db_path)
    agent.correlate_chains()
    conn = sqlite3.connect(db_path)
    chain_count = conn.execute(
        "SELECT COUNT(*) FROM attack_chains"
    ).fetchone()[0]
    conn.close()
    assert chain_count == 0


@pytest.mark.parametrize(
    "raw_details",
    [
        None,
        '{"sensor": "scapy"}',
        '{"is_synthetic": false, "sensor": "scapy"}',
        "mock alert #not-a-fixture-id",
    ],
)
def test_genuine_alerts_with_null_or_json_details_correlate(tmp_path, raw_details):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
    seed_alerts(
        agent,
        [
            (
                base.isoformat(),
                "203.0.113.30",
                "10.0.2.11",
                "edge-node-1",
                "port_scan",
                "scapy",
                None,
                raw_details,
            ),
            (
                (base + timedelta(minutes=1)).isoformat(),
                "203.0.113.30",
                "10.0.2.12",
                "edge-node-2",
                "brute_force",
                "both",
                None,
                raw_details,
            ),
            (
                (base + timedelta(minutes=2)).isoformat(),
                "203.0.113.30",
                "10.0.2.13",
                "edge-node-3",
                "lateral_movement",
                "suricata",
                None,
                raw_details,
            ),
        ],
    )

    agent.correlate_chains()

    conn = sqlite3.connect(agent.database_path)
    chains = conn.execute("SELECT alert_ids FROM attack_chains").fetchall()
    conn.close()
    assert [json.loads(row[0]) for row in chains] == [[1, 2, 3]]


def test_existing_chains_with_synthetic_alerts_are_not_scored(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 1, 3, 12, 0, 0, tzinfo=timezone.utc)
    seed_alerts(
        agent,
        [
            (base.isoformat(), "203.0.113.40", "10.0.3.11", "edge-node-1", "port_scan", "scapy", None, "mock alert #0"),
            ((base + timedelta(minutes=1)).isoformat(), "203.0.113.40", "10.0.3.12", "edge-node-2", "brute_force", "both", None, "mock alert #1"),
            ((base + timedelta(minutes=2)).isoformat(), "203.0.113.40", "10.0.3.13", "edge-node-3", "lateral_movement", "suricata", None, "mock alert #2"),
            (base.isoformat(), "203.0.113.50", "10.0.4.11", "edge-node-1", "port_scan", "scapy", None, "{}"),
            ((base + timedelta(minutes=1)).isoformat(), "203.0.113.50", "10.0.4.12", "edge-node-2", "brute_force", "both", None, '{"is_synthetic": true}'),
            ((base + timedelta(minutes=2)).isoformat(), "203.0.113.50", "10.0.4.13", "edge-node-3", "lateral_movement", "suricata", None, "{}"),
            (base.isoformat(), "203.0.113.60", "10.0.5.11", "edge-node-1", "port_scan", "scapy", None, "{}"),
            ((base + timedelta(minutes=1)).isoformat(), "203.0.113.60", "10.0.5.12", "edge-node-2", "brute_force", "both", None, "{}"),
            ((base + timedelta(minutes=2)).isoformat(), "203.0.113.60", "10.0.5.13", "edge-node-3", "lateral_movement", "suricata", None, "{}"),
        ],
    )
    conn = sqlite3.connect(agent.database_path)
    conn.executemany(
        """
        INSERT INTO attack_chains
        (chain_id, alert_ids, mitre_sequence, start_time, last_updated, status)
        VALUES (?, ?, ?, ?, ?, 'active')
        """,
        [
            ("chain-synthetic", json.dumps([1, 2, 3]), "TA0043 -> TA0006 -> TA0008", base.isoformat(), base.isoformat()),
            ("chain-mixed", json.dumps([4, 5, 6]), "TA0043 -> TA0006 -> TA0008", base.isoformat(), base.isoformat()),
            ("chain-genuine", json.dumps([7, 8, 9]), "TA0043 -> TA0006 -> TA0008", base.isoformat(), base.isoformat()),
        ],
    )
    existing_genuine_score = (
        "chain-genuine",
        base.isoformat(),
        42,
        "Medium",
        '{"historical": true}',
    )
    conn.execute(
        """
        INSERT INTO threat_scores
        (chain_id, timestamp, score, severity_label, factors_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        existing_genuine_score,
    )
    conn.executemany(
        """
        INSERT INTO threat_scores
        (chain_id, timestamp, score, severity_label, factors_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            ("chain-synthetic", base.isoformat(), 95, "Critical", '{"old": true}'),
            ("chain-mixed", base.isoformat(), 80, "High", '{"old": true}'),
        ],
    )
    conn.commit()
    conn.close()

    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    chain_count = conn.execute("SELECT COUNT(*) FROM attack_chains").fetchone()[0]
    stale_score_count = conn.execute(
        """
        SELECT COUNT(*) FROM threat_scores
        WHERE chain_id IN ('chain-synthetic', 'chain-mixed')
        """
    ).fetchone()[0]
    genuine_scores = conn.execute(
        """
        SELECT timestamp, score, severity_label, factors_json
        FROM threat_scores WHERE chain_id = 'chain-genuine'
        ORDER BY id
        """
    ).fetchall()
    chain_statuses = dict(
        conn.execute(
            "SELECT chain_id, status FROM attack_chains"
        ).fetchall()
    )
    conn.close()
    score_events = [
        event for event in agent.bus.events if event[0] == "SCORE_COMPUTED"
    ]
    assert chain_count == 3
    assert stale_score_count == 0
    assert len(genuine_scores) == 2
    assert genuine_scores[0] == existing_genuine_score[1:]
    assert [event[1]["chain_id"] for event in score_events] == ["chain-genuine"]
    assert chain_statuses["chain-synthetic"] == "active"
    assert chain_statuses["chain-mixed"] == "active"
    assert not [
        event
        for event in agent.bus.events
        if event[0] == "CHAIN_RESOLVED"
        and event[1]["chain_id"] in {"chain-synthetic", "chain-mixed"}
    ]


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


@pytest.mark.parametrize(
    ("attack_type", "mitre_tactic"),
    [
        ("port_scan", "TA0043"),
        ("brute_force", "TA0006"),
        ("lateral_movement", "TA0008"),
        ("ddos", "TA0040"),
    ],
)
def test_insert_alert_from_event_maps_supported_attack_types(
    tmp_path, attack_type, mitre_tactic
):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    payload = {
        "timestamp": "2026-02-03T12:00:00Z",
        "source_ip": "192.0.2.78",
        "target_ip": "10.0.0.11",
        "attack_type": attack_type,
        "detection_source": "scapy",
    }

    agent.insert_alert_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    row = conn.execute(
        "SELECT attack_type, mitre_tactic FROM alerts"
    ).fetchone()
    conn.close()
    assert row == (attack_type, mitre_tactic)


def test_insert_alert_from_event_preserves_unknown_attack_type_unmapped(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    original_attack_type = "  Novel_Probe  "
    payload = {
        "timestamp": "2026-02-03T12:00:00Z",
        "source_ip": "192.0.2.79",
        "target_ip": "10.0.0.11",
        "attack_type": original_attack_type,
        "detection_source": "scapy",
    }

    agent.insert_alert_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    row = conn.execute(
        "SELECT attack_type, mitre_tactic FROM alerts"
    ).fetchone()
    conn.close()
    assert row == (original_attack_type, None)


def test_insert_alert_from_event_defaults_missing_detection_source(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    payload = {
        "timestamp": "2026-02-03T12:00:00Z",
        "source_ip": "192.0.2.80",
        "target_ip": "10.0.0.11",
        "attack_type": "port_scan",
    }

    agent.insert_alert_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    row = conn.execute(
        "SELECT detection_source, mitre_tactic FROM alerts"
    ).fetchone()
    conn.close()
    assert row == ("unknown", "TA0043")


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
    assert module.EventBus.CHAIN_RESOLVED == "CHAIN_RESOLVED"
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
    freeze_agent_time(agent, base + timedelta(minutes=5))
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

    freeze_agent_time(agent, base + timedelta(minutes=5))
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

    freeze_agent_time(agent, base + timedelta(minutes=6))
    agent.score_chains()
    conn = sqlite3.connect(agent.database_path)
    rows = conn.execute("SELECT score, severity_label, factors_json FROM threat_scores WHERE chain_id = 'chain-abc' ORDER BY timestamp DESC LIMIT 2").fetchall()
    conn.close()

    assert len(rows) == 2
    assert rows[0][0] == 100
    assert rows[0][1] == "Critical"
    assert "attack_types" in json.loads(rows[0][2])


@pytest.mark.parametrize(
    ("minutes_inactive", "expected_score"),
    [(4, 10), (5, 10), (9, 10), (10, 5), (14, 5), (15, 0)],
)
def test_score_decay_grace_and_complete_intervals(
    tmp_path, minutes_inactive, expected_score
):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
    chain_id = seed_scoring_chain(agent, ["port_scan"], base)
    freeze_agent_time(agent, base + timedelta(minutes=minutes_inactive))

    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    score = conn.execute(
        "SELECT score FROM threat_scores WHERE chain_id = ? ORDER BY id DESC LIMIT 1",
        (chain_id,),
    ).fetchone()[0]
    status = conn.execute(
        "SELECT status FROM attack_chains WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()[0]
    conn.close()
    assert score == expected_score
    assert status == "active"


def test_score_decay_is_absolute_restart_stable_and_suppresses_duplicate_events(
    tmp_path,
):
    db_path = tmp_path / "edgeshield.db"
    agent = TemporaryAnalysisAgent(db_path)
    base = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)
    chain_id = seed_scoring_chain(
        agent,
        ["port_scan", "brute_force", "lateral_movement"],
        base,
    )
    frozen_now = base + timedelta(minutes=17)
    freeze_agent_time(agent, frozen_now)

    agent.score_chains()
    agent.score_chains()

    conn = sqlite3.connect(db_path)
    first_score = conn.execute(
        "SELECT score FROM threat_scores WHERE chain_id = ? ORDER BY id DESC LIMIT 1",
        (chain_id,),
    ).fetchone()[0]
    first_count = conn.execute(
        "SELECT COUNT(*) FROM threat_scores WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()[0]
    conn.close()
    assert first_score == 65
    assert first_count == 1
    assert len([event for event in agent.bus.events if event[0] == "SCORE_COMPUTED"]) == 1

    restarted_agent = TemporaryAnalysisAgent(db_path)
    freeze_agent_time(restarted_agent, frozen_now)
    restarted_agent.score_chains()

    conn = sqlite3.connect(db_path)
    scores = conn.execute(
        "SELECT score FROM threat_scores WHERE chain_id = ? ORDER BY id",
        (chain_id,),
    ).fetchall()
    conn.close()
    assert [row[0] for row in scores] == [65]
    assert restarted_agent.bus.events == []


def test_new_genuine_activity_resets_inactivity_clock(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 3, 3, 12, 0, tzinfo=timezone.utc)
    seed_alerts(
        agent,
        [
            (base.isoformat(), "192.0.2.202", "10.1.1.1", "edge-1", "port_scan", "scapy", None, "{}"),
            ((base + timedelta(minutes=1)).isoformat(), "192.0.2.202", "10.1.1.2", "edge-2", "brute_force", "scapy", None, "{}"),
            ((base + timedelta(minutes=2)).isoformat(), "192.0.2.202", "10.1.1.3", "edge-3", "lateral_movement", "scapy", None, "{}"),
        ],
    )
    freeze_agent_time(agent, base + timedelta(minutes=12))
    agent.correlate_chains()
    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    chain_id = conn.execute(
        "SELECT chain_id FROM attack_chains"
    ).fetchone()[0]
    first_score = conn.execute(
        "SELECT score FROM threat_scores WHERE chain_id = ? ORDER BY id DESC LIMIT 1",
        (chain_id,),
    ).fetchone()[0]
    conn.close()
    assert first_score == 70

    new_activity = base + timedelta(minutes=13)
    seed_alerts(
        agent,
        [
            (
                new_activity.isoformat(),
                "192.0.2.202",
                "10.1.1.4",
                "edge-4",
                "ddos",
                "scapy",
                None,
                "{}",
            )
        ],
    )
    freeze_agent_time(agent, new_activity)
    agent.correlate_chains()
    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    last_activity, score = conn.execute(
        """
        SELECT last_activity_at,
               (SELECT score FROM threat_scores
                WHERE chain_id = attack_chains.chain_id ORDER BY id DESC LIMIT 1)
        FROM attack_chains WHERE chain_id = ?
        """,
        (chain_id,),
    ).fetchone()
    conn.close()
    assert last_activity == new_activity.isoformat()
    assert score == 100


@pytest.mark.parametrize(
    (
        "attack_types",
        "pre_resolution_minutes",
        "pre_resolution_score",
        "resolution_minutes",
    ),
    [
        (["port_scan"], 15, 0, 30),
        (["port_scan", "brute_force"], 30, 5, 35),
        (["port_scan", "ddos"], 55, 0, 60),
        (["port_scan", "brute_force", "lateral_movement", "ddos"], 105, 0, 120),
    ],
)
def test_severity_specific_resolution_requires_minimum_inactivity_and_zero_score(
    tmp_path,
    attack_types,
    pre_resolution_minutes,
    pre_resolution_score,
    resolution_minutes,
):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 3, 4, 12, 0, tzinfo=timezone.utc)
    chain_id = seed_scoring_chain(agent, attack_types, base)
    last_activity = base + timedelta(minutes=len(attack_types) - 1)

    freeze_agent_time(
        agent,
        last_activity + timedelta(minutes=pre_resolution_minutes),
    )
    agent.score_chains()
    conn = sqlite3.connect(agent.database_path)
    before_status = conn.execute(
        "SELECT status FROM attack_chains WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()[0]
    before_score = conn.execute(
        "SELECT score FROM threat_scores WHERE chain_id = ? ORDER BY id DESC LIMIT 1",
        (chain_id,),
    ).fetchone()[0]
    conn.close()
    assert before_status == "active"
    assert before_score == pre_resolution_score

    freeze_agent_time(
        agent,
        last_activity + timedelta(minutes=resolution_minutes),
    )
    agent.score_chains()
    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    status = conn.execute(
        "SELECT status FROM attack_chains WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()[0]
    score_count = conn.execute(
        "SELECT COUNT(*) FROM threat_scores WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()[0]
    conn.close()
    assert status == "resolved"
    assert len([event for event in agent.bus.events if event[0] == "CHAIN_RESOLVED"]) == 1
    assert score_count == (1 if pre_resolution_score == 0 else 2)
    score_event = next(
        event[1]
        for event in agent.bus.events
        if event[0] == "SCORE_COMPUTED"
    )
    assert set(score_event) == {
        "chain_id",
        "score",
        "severity_label",
        "timestamp",
        "alert_ids",
        "evidence_count",
        "factors",
    }


def test_resolved_chain_stays_resolved_and_new_sequence_gets_new_chain(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 3, 5, 12, 0, tzinfo=timezone.utc)
    seed_alerts(
        agent,
        [
            (base.isoformat(), "192.0.2.203", "10.2.0.1", "edge-1", "port_scan", "scapy", None, "{}"),
            ((base + timedelta(minutes=1)).isoformat(), "192.0.2.203", "10.2.0.2", "edge-2", "brute_force", "scapy", None, "{}"),
            ((base + timedelta(minutes=2)).isoformat(), "192.0.2.203", "10.2.0.3", "edge-3", "lateral_movement", "scapy", None, "{}"),
        ],
    )
    agent.correlate_chains()
    conn = sqlite3.connect(agent.database_path)
    old_chain_id = conn.execute(
        "SELECT chain_id FROM attack_chains"
    ).fetchone()[0]
    conn.close()

    freeze_agent_time(agent, base + timedelta(minutes=82))
    agent.score_chains()
    agent.score_chains()
    assert len([event for event in agent.bus.events if event[0] == "CHAIN_RESOLVED"]) == 1

    new_base = base + timedelta(minutes=100)
    seed_alerts(
        agent,
        [
            (new_base.isoformat(), "192.0.2.203", "10.2.0.4", "edge-4", "port_scan", "scapy", None, "{}"),
            ((new_base + timedelta(minutes=1)).isoformat(), "192.0.2.203", "10.2.0.5", "edge-5", "brute_force", "scapy", None, "{}"),
            ((new_base + timedelta(minutes=2)).isoformat(), "192.0.2.203", "10.2.0.6", "edge-6", "lateral_movement", "scapy", None, "{}"),
        ],
    )
    freeze_agent_time(agent, new_base + timedelta(minutes=2))
    agent.correlate_chains()

    conn = sqlite3.connect(agent.database_path)
    chains = conn.execute(
        "SELECT chain_id, status FROM attack_chains ORDER BY id"
    ).fetchall()
    conn.close()
    assert len(chains) == 2
    assert chains[0] == (old_chain_id, "resolved")
    assert chains[1][1] == "active"
    assert chains[1][0] != old_chain_id


def test_last_activity_migration_is_idempotent_and_handles_bad_timestamps(tmp_path):
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            target_node TEXT,
            attack_type TEXT NOT NULL,
            detection_source TEXT NOT NULL,
            mitre_tactic TEXT,
            raw_details TEXT
        );
        CREATE TABLE attack_chains (
            id INTEGER PRIMARY KEY,
            chain_id TEXT UNIQUE NOT NULL,
            alert_ids TEXT NOT NULL,
            mitre_sequence TEXT,
            start_time TEXT NOT NULL,
            last_updated TEXT NOT NULL,
            status TEXT DEFAULT 'active'
        );
        INSERT INTO alerts
        (id, timestamp, source_ip, target_ip, attack_type, detection_source)
        VALUES (1, '2026-03-06T12:02:00+00:00', '192.0.2.204', '10.3.0.1',
                'port_scan', 'scapy');
        INSERT INTO attack_chains
        (chain_id, alert_ids, start_time, last_updated)
        VALUES ('chain-migrated', '[1]', '2026-03-06T12:00:00+00:00',
                '2026-03-06T12:01:00+00:00');
        INSERT INTO attack_chains
        (chain_id, alert_ids, start_time, last_updated)
        VALUES ('chain-malformed', 'not-json', 'bad-start', 'bad-update');
        """
    )
    conn.commit()
    conn.close()

    TemporaryAnalysisAgent(db_path)
    TemporaryAnalysisAgent(db_path)
    conn = sqlite3.connect(db_path)
    columns = {
        row[1] for row in conn.execute("PRAGMA table_info(attack_chains)")
    }
    activity_values = dict(
        conn.execute(
            "SELECT chain_id, last_activity_at FROM attack_chains"
        ).fetchall()
    )
    last_updated = conn.execute(
        "SELECT last_updated FROM attack_chains WHERE chain_id = 'chain-migrated'"
    ).fetchone()[0]
    conn.close()
    assert "last_activity_at" in columns
    assert activity_values == {
        "chain-migrated": "2026-03-06T12:02:00+00:00",
        "chain-malformed": None,
    }
    assert last_updated == "2026-03-06T12:01:00+00:00"


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
    freeze_agent_time(agent, base + timedelta(minutes=3))
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
    ("source_ip", "target_ip", "expected_source", "expected_target"),
    [
        ("192.0.2.10", "198.51.100.10", "192.0.2.10", "198.51.100.10"),
        ("2001:0db8::1", "2001:db8::2", "2001:db8::1", "2001:db8::2"),
        ("192.0.2.10", "2001:db8::2", "192.0.2.10", "2001:db8::2"),
    ],
)
def test_alert_ingestion_accepts_valid_ipv4_and_ipv6(
    tmp_path, source_ip, target_ip, expected_source, expected_target
):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    agent.insert_alert_from_event(
        {
            "timestamp": "2026-02-03T12:00:00Z",
            "source_ip": source_ip,
            "target_ip": target_ip,
            "attack_type": "port_scan",
        }
    )

    conn = sqlite3.connect(agent.database_path)
    row = conn.execute("SELECT source_ip, target_ip FROM alerts").fetchone()
    conn.close()
    assert row == (expected_source, expected_target)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_ip", "999.1.1.1"),
        ("source_ip", "2001:db8:::1"),
        ("target_ip", "256.0.0.1"),
        ("target_ip", "2001:db8::zz"),
    ],
)
def test_alert_ingestion_rejects_malformed_ip_addresses(tmp_path, field, value):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    payload = {
        "timestamp": "2026-02-03T12:00:00Z",
        "source_ip": "192.0.2.10",
        "target_ip": "198.51.100.10",
        "attack_type": "port_scan",
    }
    payload[field] = value

    agent.insert_alert_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    assert count == 0


@pytest.mark.parametrize("field", ["source_ip", "target_ip"])
def test_alert_ingestion_rejects_missing_ip_fields(tmp_path, field):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    payload = {
        "timestamp": "2026-02-03T12:00:00Z",
        "source_ip": "192.0.2.10",
        "target_ip": "198.51.100.10",
        "attack_type": "port_scan",
    }
    payload.pop(field)

    agent.insert_alert_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    assert count == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_ip", None),
        ("source_ip", ""),
        ("source_ip", "  "),
        ("source_ip", 7),
        ("source_ip", []),
        ("target_ip", None),
        ("target_ip", ""),
        ("target_ip", "  "),
        ("target_ip", {}),
    ],
)
def test_alert_ingestion_rejects_missing_null_empty_and_wrong_type_ips(
    tmp_path, field, value
):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    payload = {
        "timestamp": "2026-02-03T12:00:00Z",
        "source_ip": "192.0.2.10",
        "target_ip": "198.51.100.10",
        "attack_type": "port_scan",
    }
    if value is None:
        payload[field] = None
    else:
        payload[field] = value

    agent.insert_alert_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    assert count == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timestamp", None),
        ("timestamp", 1720000000),
        ("timestamp", {}),
        ("timestamp", ""),
        ("attack_type", None),
        ("attack_type", 12),
        ("attack_type", []),
        ("attack_type", "  "),
        ("detection_source", 0),
        ("detection_source", False),
        ("detection_source", []),
        ("target_node", 42),
        ("target_node", {}),
    ],
)
def test_alert_ingestion_rejects_wrong_type_or_empty_fields(
    tmp_path, field, value
):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    payload = {
        "timestamp": "2026-02-03T12:00:00Z",
        "source_ip": "192.0.2.10",
        "target_ip": "198.51.100.10",
        "attack_type": "port_scan",
        "detection_source": "scapy",
        "target_node": "edge-node-1",
    }
    payload[field] = value

    agent.insert_alert_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    assert count == 0


@pytest.mark.parametrize("payload", [[], "text", 7, None])
def test_non_object_alert_payloads_are_ignored(tmp_path, payload):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")

    agent.insert_alert_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    assert count == 0


def test_alert_validation_does_not_log_untrusted_payload_values(tmp_path, caplog):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    secret = "sensitive-password-8841"

    agent.insert_alert_from_event(
        {
            "timestamp": secret,
            "source_ip": "192.0.2.10",
            "target_ip": "198.51.100.10",
            "attack_type": "port_scan",
            "password": secret,
        }
    )
    agent.insert_alert_from_event(f"token={secret}")

    assert secret not in caplog.text


def test_malformed_redis_json_does_not_block_following_valid_alert(tmp_path, monkeypatch, caplog):
    class StopListener(Exception):
        pass

    class RawPubSub:
        def listen(self):
            for data in ("not-json", "[]", '"text"', "7", "null"):
                yield {
                    "type": "message",
                    "channel": "NEW_ALERT",
                    "data": data,
                }
            yield {
                "type": "message",
                "channel": "NEW_ALERT",
                "data": json.dumps(
                    {
                        "timestamp": "2026-02-03T12:00:00Z",
                        "source_ip": "192.0.2.11",
                        "target_ip": "198.51.100.11",
                        "attack_type": "port_scan",
                        "password": "do-not-log-this",
                    }
                ),
            }
            raise StopListener()

    class RawBus(FakeBus):
        def __init__(self):
            super().__init__()
            self.pubsub = RawPubSub()

    class ImmediateThread:
        def __init__(self, target, name, daemon):
            self.target = target

        def start(self):
            try:
                self.target()
            except StopListener:
                pass

    def stop_after_sleep(seconds):
        assert seconds == 5
        raise StopListener()

    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    agent.bus = RawBus()
    monkeypatch.setattr(analysis_agent_module.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(analysis_agent_module.time, "sleep", stop_after_sleep)

    agent.start_event_listener()

    conn = sqlite3.connect(agent.database_path)
    rows = conn.execute("SELECT source_ip, target_ip FROM alerts").fetchall()
    conn.close()
    assert rows == [("192.0.2.11", "198.51.100.11")]
    assert "do-not-log-this" not in caplog.text
    assert "Malformed Redis event ignored: invalid JSON" in caplog.text


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
            "attack_type": "",
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


def test_sensor_ml_prediction_id_reuses_existing_shared_database_row(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    timestamp = "2026-02-04T12:00:00+00:00"
    base = datetime.fromisoformat(timestamp)
    chain_id = seed_scoring_chain(agent, ["port_scan"], base)
    freeze_agent_time(agent, base + timedelta(minutes=1))
    seed_ml_prediction(
        agent,
        timestamp,
        "edge-node-1",
        "port_scan",
        0.9,
        prediction_id=41,
        window_start=None,
        window_end=timestamp,
        features_json='{"packet_rate": 3.5}',
    )
    payload = {
        "prediction_id": 41,
        "timestamp": timestamp,
        "target_node": "edge-node-1",
        "source_ip": "192.0.2.21",
        "predicted_class": "port_scan",
        "confidence": 0.9,
    }

    agent.insert_ml_prediction_from_event(payload)
    agent.insert_ml_prediction_from_event(payload)

    conn = sqlite3.connect(agent.database_path)
    rows = conn.execute(
        "SELECT id, window_start, features_json FROM ml_predictions"
    ).fetchall()
    scores = conn.execute(
        "SELECT score FROM threat_scores WHERE chain_id = ? ORDER BY id",
        (chain_id,),
    ).fetchall()
    conn.close()
    assert rows == [(41, None, '{"packet_rate": 3.5}')]
    assert [row[0] for row in scores] == [15]


@pytest.mark.parametrize(
    ("confidence", "expected_bonus"),
    [(0.0, 0), (1.0, 5)],
)
def test_ml_confidence_applies_bounded_bonus_at_probability_boundaries(
    tmp_path, confidence, expected_bonus
):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc)
    chain_id = seed_scoring_chain(agent, ["port_scan"], base)
    seed_ml_prediction(
        agent,
        (base + timedelta(minutes=1)).isoformat(),
        "edge-node-1",
        "port_scan",
        confidence,
    )
    freeze_agent_time(agent, base + timedelta(minutes=1))

    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    score, severity, factors_json = conn.execute(
        """
        SELECT score, severity_label, factors_json
        FROM threat_scores WHERE chain_id = ?
        """,
        (chain_id,),
    ).fetchone()
    conn.close()
    factors = json.loads(factors_json)
    assert score == 10 + expected_bonus
    assert severity == "Low"
    assert factors["rule_based_score"] == 10
    assert factors["ml_confidence"] == confidence
    assert factors["ml_confidence_bonus"] == expected_bonus


def test_ml_confidence_alone_does_not_create_a_chain_or_high_threat(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    seed_ml_prediction(
        agent,
        "2026-04-02T12:00:00+00:00",
        "edge-node-1",
        "port_scan",
        1.0,
    )

    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    score_count = conn.execute("SELECT COUNT(*) FROM threat_scores").fetchone()[0]
    chain_count = conn.execute("SELECT COUNT(*) FROM attack_chains").fetchone()[0]
    conn.close()
    assert score_count == 0
    assert chain_count == 0


def test_ml_confidence_is_limited_to_rule_based_severity_band(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 4, 3, 12, 0, tzinfo=timezone.utc)
    chain_id = seed_scoring_chain(
        agent,
        ["port_scan", "brute_force", "lateral_movement"],
        base,
    )
    seed_ml_prediction(
        agent,
        (base + timedelta(minutes=2)).isoformat(),
        "edge-node-3",
        "lateral_movement",
        1.0,
    )
    freeze_agent_time(agent, base + timedelta(minutes=2))

    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    score, severity, factors_json = conn.execute(
        """
        SELECT score, severity_label, factors_json
        FROM threat_scores WHERE chain_id = ?
        """,
        (chain_id,),
    ).fetchone()
    conn.close()
    assert score == 80
    assert severity == "High"
    assert json.loads(factors_json)["evidence_score"] == 80


def test_ml_confidence_requires_matching_node_type_and_time(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 4, 3, 13, 0, tzinfo=timezone.utc)
    chain_id = seed_scoring_chain(
        agent,
        ["port_scan", "brute_force"],
        base,
    )
    seed_ml_prediction(
        agent,
        (base + timedelta(minutes=1)).isoformat(),
        "edge-node-1",
        "brute_force",
        1.0,
    )
    seed_ml_prediction(
        agent,
        (base + timedelta(minutes=20)).isoformat(),
        "edge-node-1",
        "port_scan",
        1.0,
    )
    seed_ml_prediction(
        agent,
        (base + timedelta(minutes=1)).isoformat(),
        "edge-node-2",
        "lateral_movement",
        1.0,
    )
    freeze_agent_time(agent, base + timedelta(minutes=1))

    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    score, factors_json = conn.execute(
        "SELECT score, factors_json FROM threat_scores WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()
    conn.close()
    assert score == 30
    assert "ml_confidence" not in json.loads(factors_json)


def test_ml_confidence_does_not_double_count_detector_duplicates(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 4, 4, 12, 0, tzinfo=timezone.utc)
    seed_alerts(
        agent,
        [
            (base.isoformat(), "192.0.2.22", "10.4.0.1", "edge-node-1", "port_scan", "scapy", None, "{}"),
            ((base + timedelta(seconds=1)).isoformat(), "192.0.2.22", "10.4.0.1", "edge-node-1", "port_scan", "suricata", None, "{}"),
        ],
    )
    conn = sqlite3.connect(agent.database_path)
    conn.execute(
        """
        INSERT INTO attack_chains
        (chain_id, alert_ids, start_time, last_updated, last_activity_at, status)
        VALUES (?, ?, ?, ?, ?, 'active')
        """,
        (
            "chain-detector-duplicate",
            json.dumps([1, 2]),
            base.isoformat(),
            base.isoformat(),
            base.isoformat(),
        ),
    )
    conn.commit()
    conn.close()
    seed_ml_prediction(
        agent,
        (base + timedelta(seconds=2)).isoformat(),
        "edge-node-1",
        "port_scan",
        1.0,
    )
    freeze_agent_time(agent, base + timedelta(seconds=2))

    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    score = conn.execute(
        """
        SELECT score FROM threat_scores
        WHERE chain_id = 'chain-detector-duplicate'
        """
    ).fetchone()[0]
    conn.close()
    assert score == 15


def test_feature3_decay_uses_ml_adjusted_evidence_baseline(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 4, 5, 12, 0, tzinfo=timezone.utc)
    chain_id = seed_scoring_chain(
        agent,
        ["port_scan", "brute_force", "lateral_movement"],
        base,
    )
    seed_ml_prediction(
        agent,
        (base + timedelta(minutes=2)).isoformat(),
        "edge-node-3",
        "lateral_movement",
        1.0,
    )
    freeze_agent_time(agent, base + timedelta(minutes=17))

    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    score, factors_json = conn.execute(
        """
        SELECT score, factors_json FROM threat_scores
        WHERE chain_id = ?
        """,
        (chain_id,),
    ).fetchone()
    conn.close()
    factors = json.loads(factors_json)
    assert score == 70
    assert factors["evidence_score"] == 80
    assert factors["decay_points"] == 10
    assert 0 <= score <= 100


def test_ml_confidence_at_maximum_cannot_exceed_score_bounds(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 4, 6, 12, 0, tzinfo=timezone.utc)
    chain_id = seed_scoring_chain(
        agent,
        ["port_scan", "brute_force", "lateral_movement", "ddos"],
        base,
    )
    seed_ml_prediction(
        agent,
        (base + timedelta(minutes=3)).isoformat(),
        "edge-node-4",
        "ddos",
        1.0,
    )
    freeze_agent_time(agent, base + timedelta(minutes=3))

    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    score = conn.execute(
        "SELECT score FROM threat_scores WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()[0]
    conn.close()
    assert score == 100
    assert 0 <= score <= 100


def test_missing_ml_confidence_keeps_rule_based_risk_score(tmp_path):
    agent = TemporaryAnalysisAgent(tmp_path / "edgeshield.db")
    base = datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc)
    chain_id = seed_scoring_chain(agent, ["port_scan"], base)
    freeze_agent_time(agent, base + timedelta(minutes=1))
    agent.insert_ml_prediction_from_event(
        {
            "timestamp": (base + timedelta(minutes=1)).isoformat(),
            "target_node": "edge-node-1",
            "predicted_class": "port_scan",
        }
    )

    agent.score_chains()

    conn = sqlite3.connect(agent.database_path)
    score = conn.execute(
        "SELECT score FROM threat_scores WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()[0]
    prediction_count = conn.execute(
        "SELECT COUNT(*) FROM ml_predictions"
    ).fetchone()[0]
    conn.close()
    assert score == 10
    assert prediction_count == 0


@pytest.mark.parametrize(
    "confidence",
    [-0.01, 1.01, float("nan"), float("inf"), "not-a-number", None, True],
)
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
