-- Person C extensions (applied by defender-agent at startup; safe to re-run)

CREATE TABLE IF NOT EXISTS device_registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    device_name TEXT NOT NULL,
    criticality TEXT NOT NULL DEFAULT 'medium',
    registered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS honeypot_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id TEXT NOT NULL,
    attacker_ip TEXT NOT NULL,
    honeypot_ip TEXT NOT NULL,
    started_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rollback_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id TEXT NOT NULL,
    response_id INTEGER,
    reason TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_registry_ip ON device_registry(ip_address);
CREATE INDEX IF NOT EXISTS idx_honeypot_sessions_chain ON honeypot_sessions(chain_id);
