from __future__ import annotations

# Sprint 8: миграции БД (models.py) — пошаговое покрытие v1..v10

import base64
import sqlite3
import tempfile
import unittest
from pathlib import Path

from src.database import models


def _create_v1_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_password TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            tags TEXT
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT NOT NULL UNIQUE,
            setting_value TEXT,
            encrypted INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE key_store (
            id INTEGER PRIMARY KEY,
            key_type TEXT,
            salt TEXT,
            hash TEXT,
            params TEXT
        );
        """
    )
    cur.execute(
        """
        INSERT INTO vault_entries (encrypted_password, created_at, updated_at, tags)
        VALUES (?, '2020-01-01', '2020-01-01', 't');
        """,
        (base64.b64encode(b"cipher").decode("ascii"),),
    )
    cur.execute(
        """
        INSERT INTO key_store (key_type, salt, hash, params)
        VALUES ('master_auth', ?, ?, '{}');
        """,
        ("aa" * 16, "bb" * 32),
    )
    cur.execute(
        """
        INSERT INTO key_store (key_type, salt, hash, params)
        VALUES ('master_enc', ?, '', '{}');
        """,
        ("cc" * 16,),
    )
    cur.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()


def _create_v6_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE vault_entries (
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
        CREATE TABLE settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT NOT NULL UNIQUE,
            setting_value TEXT,
            encrypted INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE key_store (
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
        CREATE TABLE deleted_entries (
            id INTEGER PRIMARY KEY,
            encrypted_data BLOB NOT NULL,
            deleted_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            tags TEXT
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            timestamp TEXT,
            entry_id INTEGER,
            details TEXT,
            signature TEXT
        );
        """
    )
    cur.execute(
        """
        INSERT INTO audit_log (action, timestamp, entry_id, details, signature)
        VALUES ('Login', '2020-01-01T00:00:00Z', 1, '{"event_type":"Login"}', 'sig');
        """
    )
    cur.execute("PRAGMA user_version = 6")
    conn.commit()
    conn.close()


class TestSprint8ModelsMigrations(unittest.TestCase):
    def test_initialize_fresh_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fresh.db"
            models.initialize_database(path)
            conn = models.get_connection(path)
            try:
                (ver,) = conn.execute("PRAGMA user_version").fetchone()
                self.assertEqual(int(ver), models.CURRENT_DB_VERSION)
            finally:
                conn.close()

    def test_migrate_v1_to_v2_adds_created_at(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "v1.db"
            conn = sqlite3.connect(path)
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE key_store (
                    id INTEGER PRIMARY KEY,
                    key_type TEXT,
                    salt TEXT,
                    hash TEXT,
                    params TEXT
                );
                """
            )
            conn.commit()
            models._migrate_v1_to_v2(cur)
            conn.commit()
            cur.execute("PRAGMA table_info(key_store)")
            cols = [r[1] for r in cur.fetchall()]
            self.assertIn("created_at", cols)
            conn.close()

    def test_direct_migrations_v1_through_v6(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "direct.db"
            _create_v1_db(path)
            conn = sqlite3.connect(path)
            cur = conn.cursor()
            models._migrate_v1_to_v2(cur)
            models._migrate_v2_to_v3(cur)
            models._migrate_v3_to_v4(cur)
            models._migrate_v4_to_v5(cur)
            models._migrate_v5_to_v6(cur)
            conn.commit()
            cur.execute("PRAGMA table_info(vault_entries)")
            cols = [r[1] for r in cur.fetchall()]
            self.assertIn("encrypted_data", cols)
            conn.close()

    def test_stepwise_migrations_v6_to_v10(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "step.db"
            _create_v6_db(path)
            for expected in range(7, models.CURRENT_DB_VERSION + 1):
                models.initialize_database(path)
                conn = sqlite3.connect(path)
                try:
                    (ver,) = conn.execute("PRAGMA user_version").fetchone()
                    self.assertEqual(int(ver), expected)
                finally:
                    conn.close()

    def test_migrate_v6_old_audit_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "v6.db"
            _create_v6_db(path)
            models.initialize_database(path)
            conn = sqlite3.connect(path)
            try:
                (ver,) = conn.execute("PRAGMA user_version").fetchone()
                self.assertEqual(int(ver), 7)
                cols = [r[1] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()]
                self.assertIn("entry_data", cols)
            finally:
                conn.close()
            models.initialize_database(path)
            conn = sqlite3.connect(path)
            try:
                (ver,) = conn.execute("PRAGMA user_version").fetchone()
                self.assertGreaterEqual(int(ver), 8)
            finally:
                conn.close()

    def test_migration_chain_via_initialize(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "chain.db"
            models.initialize_database(path)
            conn = sqlite3.connect(path)
            conn.execute(f"PRAGMA user_version = {models.CURRENT_DB_VERSION - 1}")
            conn.commit()
            conn.close()
            models.initialize_database(path)
            conn = sqlite3.connect(path)
            try:
                (ver,) = conn.execute("PRAGMA user_version").fetchone()
                self.assertEqual(int(ver), models.CURRENT_DB_VERSION)
            finally:
                conn.close()
