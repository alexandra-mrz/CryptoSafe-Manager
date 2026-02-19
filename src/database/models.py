SCHEMA_VERSION = 1
VAULT_ENTRIES_SQL = """
CREATE TABLE IF NOT EXISTS vault_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    username TEXT,
    encrypted_password BLOB NOT NULL,
    url TEXT,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    tags TEXT
);
CREATE INDEX IF NOT EXISTS idx_vault_title ON vault_entries(title);
CREATE INDEX IF NOT EXISTS idx_vault_updated ON vault_entries(updated_at);
"""
AUDIT_LOG_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    entry_id INTEGER,
    details TEXT,
    signature TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
"""
SETTINGS_SQL = """
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key TEXT UNIQUE NOT NULL,
    setting_value BLOB,
    encrypted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(setting_key);
"""
KEY_STORE_SQL = """
CREATE TABLE IF NOT EXISTS key_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type TEXT NOT NULL,
    salt BLOB,
    hash BLOB,
    params TEXT
);
"""
ALL_TABLES = [VAULT_ENTRIES_SQL, AUDIT_LOG_SQL, SETTINGS_SQL, KEY_STORE_SQL]
