import sqlite3
import threading
from contextlib import contextmanager
from . import models
class DatabaseHelper:
    def __init__(self, db_path: str):
        self._db_path = db_path
        self._local = threading.local()
    def _get_connection(self):
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
    @contextmanager
    def get_connection(self):
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    def init_schema(self):
        with self.get_connection() as conn:
            cur = conn.execute("PRAGMA user_version")
            version = cur.fetchone()[0]
            if version == 0:
                for sql in models.ALL_TABLES:
                    conn.executescript(sql)
                conn.execute(f"PRAGMA user_version = {models.SCHEMA_VERSION}")
                conn.commit()
    def get_schema_version(self) -> int:
        with self.get_connection() as conn:
            cur = conn.execute("PRAGMA user_version")
            return cur.fetchone()[0]
    def backup(self, target_path: str) -> None:
        pass
    def restore(self, source_path: str) -> None:
        pass
_db_helper: DatabaseHelper | None = None
_lock = threading.Lock()
def get_db(db_path: str = None) -> DatabaseHelper:
    global _db_helper
    with _lock:
        if _db_helper is None:
            if db_path is None:
                from src.core.config import get_config
                db_path = get_config().db_path
            _db_helper = DatabaseHelper(db_path)
            _db_helper.init_schema()
    return _db_helper
