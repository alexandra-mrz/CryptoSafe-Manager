from __future__ import annotations

# описание схемы таблиц и инициализация базы данных
# ddl вынесен сюда, чтобы db.py оставался простым помощником по подключению

import sqlite3
from pathlib import Path


DEFAULT_DB_PATH = Path("data/cryptosafe.db")
CURRENT_DB_VERSION = 1


def get_connection(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    # создать новое соединение с sqlite
    # предполагается, что в приложении может быть более одного соединения одновременно
    path = Path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database(db_path: Path | str = DEFAULT_DB_PATH) -> None:
    # проверить версию схемы и создать таблицы при первом запуске
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
    finally:
        conn.close()


def _apply_initial_schema(cur: sqlite3.Cursor) -> None:
    # создать таблицы первого варианта схемы
    # vault_entries
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

    # audit_log
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

    # settings
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

    # key_store (для будущего управления ключами)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS key_store (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_type TEXT NOT NULL,
            salt TEXT,
            hash TEXT,
            params TEXT
        );
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_key_store_type
            ON key_store (key_type);
        """
    )

