
import os
import sqlite3
import tempfile
import unittest

from src.database.db import Database
from src.database import models


class TestDatabaseConnectivityAndSchema(unittest.TestCase):
    def setUp(self) -> None:
        # создаём временный файл бд
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        # инициализируем схему через наш helper
        self.db = Database(self.path)

    def tearDown(self) -> None:
        try:
            os.remove(self.path)
        except OSError:
            pass

    def test_tables_exist(self) -> None:
        conn = sqlite3.connect(self.path)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='table'
                """
            )
            names = {row[0] for row in cur.fetchall()}
            self.assertIn("vault_entries", names)
            self.assertIn("audit_log", names)
            self.assertIn("audit_public_keys", names)
            self.assertIn("audit_security_log", names)
            self.assertIn("settings", names)
            self.assertIn("key_store", names)
            self.assertIn("shared_entries", names)
            self.assertIn("import_export_history", names)
            self.assertIn("contacts", names)
        finally:
            conn.close()

    def test_user_version_set(self) -> None:
        conn = sqlite3.connect(self.path)
        try:
            cur = conn.cursor()
            cur.execute("PRAGMA user_version;")
            (version,) = cur.fetchone()
            self.assertEqual(version, models.CURRENT_DB_VERSION)
        finally:
            conn.close()

    def test_backup_and_restore_roundtrip(self) -> None:
        conn = self.db.create_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO vault_entries (encrypted_data, created_at, updated_at, tags) "
                "VALUES (?, ?, ?, ?)",
                (b"\x00" * 32, "2020-01-01", "2020-01-01", "t"),
            )
            conn.commit()
        finally:
            conn.close()

        fd, backup_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            self.db.backup_database(backup_path)
            conn = self.db.create_connection()
            try:
                conn.execute("DELETE FROM vault_entries")
                conn.commit()
            finally:
                conn.close()

            self.db.restore_database(backup_path)
            conn2 = sqlite3.connect(self.path)
            try:
                count = conn2.execute("SELECT COUNT(*) FROM vault_entries").fetchone()[0]
                self.assertEqual(int(count), 1)
            finally:
                conn2.close()
        finally:
            try:
                os.remove(backup_path)
            except OSError:
                pass

    def test_restore_rejects_invalid_file(self) -> None:
        fd, bad_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            with open(bad_path, "wb") as f:
                f.write(b"not a sqlite database")
            with self.assertRaises(ValueError):
                self.db.restore_database(bad_path)
        finally:
            try:
                os.remove(bad_path)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
