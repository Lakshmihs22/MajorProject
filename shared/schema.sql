-- EdgeShield shared database schema
-- Agreed on Day 1 by all four people. Any change to this file must be
-- discussed by the whole team since every agent reads/writes these tables.

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    target_node TEXT,
    attack_type TEXT NOT NULL,       -- port_scan, brute_force, lateral_movement, ddos
    detection_source TEXT NOT NULL,  -- 'scapy', 'suricata', 'both'
    mitre_tactic TEXT,               -- filled in by Person B's tactic mapper
    raw_details TEXT
);

CREATE TABLE IF NOT EXISTS ml_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    window_start TEXT,
    window_end TEXT,
    target_node TEXT,
    predicted_class TEXT NOT NULL,
    confidence REAL NOT NULL,
    features_json TEXT
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id TEXT UNIQUE NOT NULL,
    alert_ids TEXT NOT NULL,         -- JSON array of alerts.id
    mitre_sequence TEXT,             -- e.g. "TA0043 -> TA0006 -> TA0008"
    start_time TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    status TEXT DEFAULT 'active'     -- active, resolved
);

CREATE TABLE IF NOT EXISTS threat_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    score REAL NOT NULL,
    severity_label TEXT NOT NULL,    -- Low, Medium, High, Critical
    factors_json TEXT,
    FOREIGN KEY (chain_id) REFERENCES attack_chains(chain_id)
);

CREATE TABLE IF NOT EXISTS responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id TEXT,
    timestamp TEXT NOT NULL,
    action_type TEXT NOT NULL,       -- monitor, rate_limit, block_ip, isolate_node, full_isolation
    target TEXT NOT NULL,
    rollback_command TEXT,
    status TEXT DEFAULT 'active',    -- active, rolled_back
    rolled_back_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_chains_status ON attack_chains(status);
CREATE INDEX IF NOT EXISTS idx_scores_chain ON threat_scores(chain_id);
CREATE INDEX IF NOT EXISTS idx_responses_status ON responses(status);
-- Node health information used by Person D dashboard

CREATE TABLE IF NOT EXISTS node_health (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_name TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL,
    cpu_usage REAL,
    memory_usage REAL,
    last_updated TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_node_health_status
ON node_health(status);