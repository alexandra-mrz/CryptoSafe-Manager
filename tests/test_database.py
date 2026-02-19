import os
import sys
import unittest
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from conftest import DatabaseTestCase

class TestDatabase(DatabaseTestCase):
    def test_db_connection_and_schema(self):
        with self.test_db.get_connection() as conn:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            tables = [r[0] for r in cur.fetchall()]
        self.assertIn("vault_entries", tables)
        self.assertIn("audit_log", tables)
        self.assertIn("settings", tables)
        self.assertIn("key_store", tables)
        with self.test_db.get_connection() as conn:
            cur = conn.execute("PRAGMA user_version")
            self.assertGreaterEqual(cur.fetchone()[0], 1)
    def test_vault_entries_columns(self):
        with self.test_db.get_connection() as conn:
            cur = conn.execute("PRAGMA table_info(vault_entries)")
            cols = {r[1] for r in cur.fetchall()}
        self.assertIn("id", cols)
        self.assertIn("title", cols)
        self.assertIn("username", cols)
        self.assertIn("encrypted_password", cols)
        self.assertIn("url", cols)
        self.assertIn("notes", cols)
        self.assertIn("created_at", cols)
        self.assertIn("updated_at", cols)
        self.assertIn("tags", cols)
    def test_audit_log_columns(self):
        with self.test_db.get_connection() as conn:
            cur = conn.execute("PRAGMA table_info(audit_log)")
            cols = {r[1] for r in cur.fetchall()}
        self.assertIn("signature", cols)
        self.assertIn("action", cols)
        self.assertIn("timestamp", cols)
