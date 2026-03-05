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
            self.assertIn("settings", names)
            self.assertIn("key_store", names)
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


if __name__ == "__main__":
    unittest.main()


