import os
import sys
import unittest
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

class TestConfig(unittest.TestCase):
    def test_config_has_db_path(self):
        from src.core.config import get_config
        cfg = get_config()
        path = cfg.db_path
        self.assertIsNotNone(path)
        self.assertTrue(path.endswith(".db") or "vault" in path)
    def test_config_set_db_path(self):
        from src.core.config import get_config
        cfg = get_config()
        cfg.db_path = "/tmp/test_vault.db"
        self.assertEqual(cfg.db_path, "/tmp/test_vault.db")
