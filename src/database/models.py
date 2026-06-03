
from __future__ import annotations

# схема таблиц и инициализация БД

import sqlite3
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DB_PATH = _PROJECT_ROOT / "data" / "cryptosafe.db"
CURRENT_DB_VERSION = 10


def get_connection(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Get connection."""
    path = Path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database(db_path: Path | str = DEFAULT_DB_PATH) -> None:
    """Initialize database."""
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
        elif current_version == 3:
            _migrate_v3_to_v4(cur)
            cur.execute("PRAGMA user_version = 4;")
            conn.commit()
        elif current_version == 4:
            _migrate_v4_to_v5(cur)
            cur.execute("PRAGMA user_version = 5;")
            conn.commit()
        elif current_version == 5:
            _migrate_v5_to_v6(cur)
            cur.execute("PRAGMA user_version = 6;")
            conn.commit()
        elif current_version == 6:
            _migrate_v6_to_v7(cur)
            cur.execute("PRAGMA user_version = 7;")
            conn.commit()
        elif current_version == 7:
            _migrate_v7_to_v8(cur)
            cur.execute("PRAGMA user_version = 8;")
            conn.commit()
        elif current_version == 8:
            _migrate_v8_to_v9(cur)
            cur.execute("PRAGMA user_version = 9;")
            conn.commit()
        elif current_version == 9:
            _migrate_v9_to_v10(cur)
            cur.execute("PRAGMA user_version = 10;")
            conn.commit()

        _install_audit_sec_triggers(conn)
    finally:
        conn.close()


def _apply_initial_schema(cur: sqlite3.Cursor) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_data BLOB NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            tags TEXT
        );
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_vault_entries_created_at
            ON vault_entries (created_at);
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_vault_entries_updated_at
            ON vault_entries (updated_at);
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_vault_entries_tags
            ON vault_entries (tags);
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

    _create_audit_tables_v7(cur)

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

    # таблица для soft delete (CRUD-4)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS deleted_entries (
            id INTEGER PRIMARY KEY,
            encrypted_data BLOB NOT NULL,
            deleted_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            tags TEXT
        );
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_deleted_entries_expires_at ON deleted_entries (expires_at);"
    )
    _init_audit_rotation_defaults(cur)
    _create_audit_security_log_table(cur)
    _create_sprint6_io_tables(cur)


def _create_sprint6_io_tables(cur: sqlite3.Cursor) -> None:
    # DB-1: кто и когда поделился записью
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS shared_entries (
            shared_id TEXT PRIMARY KEY,
            original_entry_id INTEGER NOT NULL,
            encryption_method TEXT NOT NULL,
            recipient_info TEXT NOT NULL,
            permissions TEXT NOT NULL,
            shared_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_shared_entries_entry
            ON shared_entries (original_entry_id);
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_shared_entries_expires
            ON shared_entries (expires_at);
        """
    )

    # DB-2: история import/export
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS import_export_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_type TEXT NOT NULL,
            file_format TEXT NOT NULL,
            encryption_used TEXT NOT NULL,
            entry_count INTEGER NOT NULL DEFAULT 0,
            file_size INTEGER NOT NULL DEFAULT 0,
            checksum TEXT NOT NULL,
            verification_status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_io_history_type
            ON import_export_history (operation_type);
        """
    )

    # DB-3: контакты для обмена ключами
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS contacts (
            contact_id TEXT PRIMARY KEY,
            contact_name TEXT NOT NULL,
            public_key_pem TEXT NOT NULL,
            public_key_hex TEXT NOT NULL,
            key_fingerprint TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            fingerprint_verified INTEGER NOT NULL DEFAULT 0,
            last_used_at TEXT,
            created_at TEXT NOT NULL
        );
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_contacts_fingerprint
            ON contacts (key_fingerprint);
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS share_inbox (
            token TEXT PRIMARY KEY,
            package_json TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_share_inbox_expires
            ON share_inbox (expires_at);
        """
    )


def _migrate_v9_to_v10(cur: sqlite3.Cursor) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS share_inbox (
            token TEXT PRIMARY KEY,
            package_json TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_share_inbox_expires
            ON share_inbox (expires_at);
        """
    )


def _migrate_v8_to_v9(cur: sqlite3.Cursor) -> None:
    # Sprint 6: таблицы sharing / import-export / contacts
    _create_sprint6_io_tables(cur)


def _migrate_v7_to_v8(cur: sqlite3.Cursor) -> None:
    _create_audit_security_log_table(cur)
    cur.execute(
        """
        INSERT OR IGNORE INTO settings (setting_key, setting_value, encrypted)
        VALUES ('audit_verify_interval_hours', '24', 0)
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


def _migrate_v3_to_v4(cur: sqlite3.Cursor) -> None:
    # Sprint 3 (DATA-1): новая модель записи:
    # id, encrypted_data (BLOB nonce+ciphertext+tag), created_at, updated_at, tags
    # Старые данные переносим максимально аккуратно.
    import base64

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS vault_entries_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_data BLOB NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            tags TEXT
        );
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_vault_entries_new_created_at ON vault_entries_new (created_at);"
    )

    # Пытаемся перенести существующие строки:
    # - если encrypted_password выглядит как base64, декодируем и кладём в BLOB
    # - если не получается, сохраняем как bytes исходную строку (на всякий случай)
    try:
        cur.execute(
            "SELECT id, encrypted_password, created_at, updated_at, tags FROM vault_entries"
        )
        rows = cur.fetchall()
    except Exception:
        rows = []

    for row in rows:
        old_id = row[0]
        token = row[1] or ""
        created_at = row[2] or ""
        updated_at = row[3] or created_at
        tags = row[4] or ""

        blob: bytes
        if isinstance(token, bytes):
            blob = token
        else:
            try:
                blob = base64.b64decode(str(token).encode("ascii"))
            except Exception:
                blob = str(token).encode("utf-8")

        cur.execute(
            """
            INSERT INTO vault_entries_new (id, encrypted_data, created_at, updated_at, tags)
            VALUES (?, ?, ?, ?, ?)
            """,
            (old_id, blob, created_at, updated_at, tags),
        )

    cur.execute("DROP TABLE vault_entries;")
    cur.execute("ALTER TABLE vault_entries_new RENAME TO vault_entries;")


def _migrate_v4_to_v5(cur: sqlite3.Cursor) -> None:
    # CRUD-4 (soft delete): отдельная таблица для удалённых записей
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS deleted_entries (
            id INTEGER PRIMARY KEY,
            encrypted_data BLOB NOT NULL,
            deleted_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            tags TEXT
        );
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_deleted_entries_expires_at ON deleted_entries (expires_at);"
    )


def _migrate_v5_to_v6(cur: sqlite3.Cursor) -> None:
    # DB-1: индексы для vault_entries
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_vault_entries_created_at ON vault_entries (created_at);"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_vault_entries_updated_at ON vault_entries (updated_at);"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_vault_entries_tags ON vault_entries (tags);"
    )


def _create_audit_tables_v7(cur: sqlite3.Cursor) -> None:
    # DB-1: новая схема audit_log
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            entry_id INTEGER,
            previous_hash TEXT NOT NULL,
            entry_data BLOB NOT NULL,
            signature TEXT NOT NULL,
            FOREIGN KEY (entry_id) REFERENCES vault_entries (id)
        );
        """
    )
    # DB-1: публичный ключ Ed25519 (один раз)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_public_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            algorithm TEXT NOT NULL,
            public_key TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );
        """
    )
    # DB-4: архив старых записей
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log_archive (
            sequence_number INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            entry_id INTEGER,
            previous_hash TEXT NOT NULL,
            entry_data BLOB NOT NULL,
            signature TEXT NOT NULL,
            archived_at TEXT NOT NULL
        );
        """
    )
    _create_audit_indexes_v7(cur)
    _create_audit_security_log_table(cur)


def _install_audit_sec_triggers(conn: sqlite3.Connection) -> None:
    # SEC-2: только INSERT в audit_log
    from src.core.audit.audit_security import install_audit_security_triggers

    install_audit_security_triggers(conn)


def _create_audit_security_log_table(cur: sqlite3.Cursor) -> None:
    # VER-4: отдельный журнал событий безопасности
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_security_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL
        );
        """
    )


def _init_audit_rotation_defaults(cur: sqlite3.Cursor) -> None:
    # DB-4: значения по умолчанию
    cur.execute(
        """
        INSERT OR IGNORE INTO settings (setting_key, setting_value, encrypted)
        VALUES ('audit_max_entries', '10000', 0)
        """
    )
    cur.execute(
        """
        INSERT OR IGNORE INTO settings (setting_key, setting_value, encrypted)
        VALUES ('audit_max_age_days', '365', 0)
        """
    )


def _create_audit_indexes_v7(cur: sqlite3.Cursor) -> None:
    # DB-3: индексы для запросов и проверки целостности
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log (event_type);"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_log_sequence_number ON audit_log (sequence_number);"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_log_entry_id ON audit_log (entry_id);"
    )


def _migrate_v6_to_v7(cur: sqlite3.Cursor) -> None:
    import json

    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log';"
    )
    if cur.fetchone() is None:
        _create_audit_tables_v7(cur)
        return

    cur.execute("PRAGMA table_info(audit_log);")
    columns = {row[1] for row in cur.fetchall()}
    if "entry_data" in columns and "sequence_number" in columns:
        _create_audit_indexes_v7(cur)
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_public_keys';"
        )
        if cur.fetchone() is None:
            cur.execute(
                """
                CREATE TABLE audit_public_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    algorithm TEXT NOT NULL,
                    public_key TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                """
            )
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log_archive';"
        )
        if cur.fetchone() is None:
            cur.execute(
                """
                CREATE TABLE audit_log_archive (
                    sequence_number INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    entry_id INTEGER,
                    previous_hash TEXT NOT NULL,
                    entry_data BLOB NOT NULL,
                    signature TEXT NOT NULL,
                    archived_at TEXT NOT NULL
                );
                """
            )
        return

    cur.execute(
        """
        CREATE TABLE audit_log_new (
            sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            entry_id INTEGER,
            previous_hash TEXT NOT NULL,
            entry_data BLOB NOT NULL,
            signature TEXT NOT NULL
        );
        """
    )

    try:
        cur.execute(
            "SELECT id, action, timestamp, entry_id, details, signature FROM audit_log ORDER BY id ASC"
        )
        old_rows = cur.fetchall()
    except Exception:
        old_rows = []

    prev_hash = "0" * 64
    seq = 0
    for row in old_rows:
        _old_id, action, timestamp, entry_id, details_text, signature = row
        details_text = details_text or "{}"
        try:
            stored = json.loads(details_text)
        except json.JSONDecodeError:
            stored = {
                "entry_data": {
                    "timestamp": timestamp,
                    "event_type": action,
                    "severity": "INFO",
                    "user_id": "local",
                    "source": "migration",
                    "details": {"raw": details_text},
                    "entry_id": entry_id,
                },
                "sequence_number": seq,
                "previous_hash": prev_hash,
                "entry_hash": prev_hash,
            }

        if "entry_data" not in stored:
            stored = {
                "entry_data": stored,
                "sequence_number": seq,
                "previous_hash": prev_hash,
                "entry_hash": prev_hash,
            }

        stored["sequence_number"] = seq
        stored["previous_hash"] = prev_hash
        entry_data = stored.get("entry_data", {})
        event_type = str(entry_data.get("event_type", action))
        blob = json.dumps(stored, ensure_ascii=False, sort_keys=True).encode("utf-8")

        cur.execute(
            """
            INSERT INTO audit_log_new
            (timestamp, event_type, entry_id, previous_hash, entry_data, signature)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(entry_data.get("timestamp", timestamp)),
                event_type,
                entry_id,
                str(stored.get("previous_hash", prev_hash)),
                blob,
                signature or "",
            ),
        )
        prev_hash = str(stored.get("entry_hash", prev_hash))
        seq += 1

    cur.execute("DROP TABLE audit_log;")
    cur.execute("ALTER TABLE audit_log_new RENAME TO audit_log;")
    _create_audit_indexes_v7(cur)
    _init_audit_rotation_defaults(cur)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_public_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            algorithm TEXT NOT NULL,
            public_key TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log_archive (
            sequence_number INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            entry_id INTEGER,
            previous_hash TEXT NOT NULL,
            entry_data BLOB NOT NULL,
            signature TEXT NOT NULL,
            archived_at TEXT NOT NULL
        );
        """
    )

