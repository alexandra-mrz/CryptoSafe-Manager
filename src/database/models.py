
from __future__ import annotations

# схема таблиц и инициализация БД

import sqlite3
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DB_PATH = _PROJECT_ROOT / "data" / "cryptosafe.db"
CURRENT_DB_VERSION = 3


def get_connection(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    path = Path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database(db_path: Path | str = DEFAULT_DB_PATH) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = get_connection(path)
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA user_version;")
        row = cur.fetchone()
        current_version = int(row[0]) if row is not None else 0

        if current_version == 0:
            _apply_initial_schema(cur)
            cur.execute(f"PRAGMA user_version = {CURRENT_DB_VERSION};")
            conn.commit()
        elif current_version == 1:
            _migrate_v1_to_v2(cur)
            cur.execute("PRAGMA user_version = 2;")
            conn.commit()
        elif current_version == 2:
            _migrate_v2_to_v3(cur)
            cur.execute("PRAGMA user_version = 3;")
            conn.commit()
    finally:
        conn.close()


def _apply_initial_schema(cur: sqlite3.Cursor) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            username TEXT,
            encrypted_password TEXT,
            url TEXT,
            notes TEXT,
            tags TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_vault_entries_title
            ON vault_entries (title);
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            entry_id INTEGER,
            details TEXT,
            signature TEXT,
            FOREIGN KEY (entry_id) REFERENCES vault_entries (id)
        );
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_log_entry_id
            ON audit_log (entry_id);
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT NOT NULL UNIQUE,
            setting_value TEXT,
            encrypted INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_settings_key
            ON settings (setting_key);
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS key_store (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_type TEXT NOT NULL,
            key_data BLOB,
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT
        );
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_key_store_type
            ON key_store (key_type);
        """
    )


def _migrate_v1_to_v2(cur: sqlite3.Cursor) -> None:
    cur.execute("PRAGMA table_info(key_store);")
    columns = [row[1] for row in cur.fetchall()]
    if "created_at" not in columns:
        cur.execute("ALTER TABLE key_store ADD COLUMN created_at TEXT;")


def _migrate_v2_to_v3(cur: sqlite3.Cursor) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS key_store_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_type TEXT NOT NULL,
            key_data BLOB,
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT
        );
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_key_store_new_type ON key_store_new (key_type);"
    )
    cur.execute("SELECT key_type, salt, hash, params, created_at FROM key_store")
    rows = cur.fetchall()
    import json
    from datetime import datetime
    now = datetime.utcnow().isoformat()
    auth_salt_hex = ""
    auth_params = ""
    enc_salt_hex = ""
    enc_params = ""
    for row in rows:
        key_type = row[0]
        salt = row[1] or ""
        hash_val = row[2] or ""
        params = row[3] or ""
        created = row[4] or now
        if key_type == "master_auth":
            auth_salt_hex = salt
            auth_params = params
            if hash_val:
                try:
                    cur.execute(
                        "INSERT INTO key_store_new (key_type, key_data, version, created_at) VALUES (?, ?, 1, ?)",
                        ("auth_hash", bytes.fromhex(hash_val), created),
                    )
                except Exception:
                    pass
        elif key_type == "master_enc":
            enc_salt_hex = salt
            enc_params = params
            if salt:
                try:
                    cur.execute(
                        "INSERT INTO key_store_new (key_type, key_data, version, created_at) VALUES (?, ?, 1, ?)",
                        ("enc_salt", bytes.fromhex(salt), created),
                    )
                except Exception:
                    pass
    params_blob = json.dumps({
        "auth_salt_hex": auth_salt_hex,
        "auth_params": auth_params,
        "enc_params": enc_params,
    }).encode("utf-8")
    cur.execute(
        "INSERT INTO key_store_new (key_type, key_data, version, created_at) VALUES (?, ?, 1, ?)",
        ("params", params_blob, now),
    )
    cur.execute("DROP TABLE key_store;")
    cur.execute("ALTER TABLE key_store_new RENAME TO key_store;")
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_key_store_type ON key_store (key_type);"
    )
