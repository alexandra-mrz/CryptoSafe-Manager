import os
import sys
import tempfile
import unittest
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

class DatabaseTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        from src.database.db import DatabaseHelper
        self.test_db = DatabaseHelper(self.temp_db_path)
        self.test_db.init_schema()
    def tearDown(self):
        try:
            os.unlink(self.temp_db_path)
        except Exception:
            pass
