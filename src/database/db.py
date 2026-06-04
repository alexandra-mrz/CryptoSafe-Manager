
from __future__ import annotations

from pathlib import Path

import shutil
import sqlite3
import queue
from datetime import datetime, timezone
from typing import Optional

from .models import DEFAULT_DB_PATH, initialize_database

# Минимальный набор таблиц для проверки файла резервной копии CryptoSafe.
_BACKUP_REQUIRED_TABLES = frozenset(
    {"vault_entries", "settings", "key_store", "audit_log"},
)


def validate_cryptosafe_database_file(path: Path | str) -> None:
    """Проверить, что файл — целая SQLite-БД CryptoSafe."""
    db_file = Path(path)
    if not db_file.is_file():
        raise ValueError("файл резервной копии не найден")
    conn = sqlite3.connect(db_file)
    try:
        cur = conn.cursor()
        try:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        except sqlite3.DatabaseError as exc:
            raise ValueError("файл не является базой SQLite CryptoSafe") from exc
        names = {str(row[0]) for row in cur.fetchall()}
        missing = _BACKUP_REQUIRED_TABLES - names
        if missing:
            raise ValueError(
                "файл не является резервной копией CryptoSafe "
                f"(отсутствуют таблицы: {', '.join(sorted(missing))})"
            )
        cur.execute("PRAGMA integrity_check")
        row = cur.fetchone()
        if row is None or str(row[0]).lower() != "ok":
            detail = row[0] if row else "unknown"
            raise ValueError(f"повреждённая база данных: {detail}")
    finally:
        conn.close()


class _PooledConnection:
    """Обёртка: close() возвращает соединение в пул."""

    def __init__(self, conn: sqlite3.Connection, pool: "_ConnectionPool") -> None:
        """Создать прокси для pooled connection."""
        self._conn = conn
        self._pool = pool
        self._closed = False

    def close(self) -> None:
        """Вернуть соединение в пул."""
        if self._closed:
            return
        self._closed = True
        self._pool.release(self._conn)

    def __getattr__(self, item):
        """Прокинуть остальные вызовы в sqlite connection."""
        return getattr(self._conn, item)


class _ConnectionPool:
    """Простой пул соединений sqlite."""

    def __init__(self, db_path: Path, size: int = 5) -> None:
        """Создать пул для файла БД."""
        self._db_path = Path(db_path)
        self._size = int(size)
        self._q: "queue.LifoQueue[sqlite3.Connection]" = queue.LifoQueue()
        self._created = 0
        self._all: list[sqlite3.Connection] = []

    def _new_conn(self) -> sqlite3.Connection:
        """Создать новое соединение."""
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        self._all.append(conn)
        return conn

    def acquire(self) -> sqlite3.Connection:
        """Взять соединение из пула."""
        try:
            return self._q.get_nowait()
        except Exception:
            pass

        if self._created < self._size:
            self._created += 1
            return self._new_conn()

        return self._q.get()

    def release(self, conn: sqlite3.Connection) -> None:
        """Вернуть соединение в пул."""
        try:
            conn.rollback()
        except Exception:
            pass
        self._q.put(conn)


_pools: dict[str, _ConnectionPool] = {}


def _get_pool(db_path: Path) -> _ConnectionPool:
    """Получить или создать пул для пути БД."""
    key = str(Path(db_path).resolve())
    pool = _pools.get(key)
    if pool is None:
        pool = _ConnectionPool(Path(db_path), size=5)
        _pools[key] = pool
    return pool


def close_connection_pool(db_path: Path | str) -> None:
    """Закрыть пул для конкретной БД."""
    key = str(Path(db_path).resolve())
    pool = _pools.pop(key, None)
    if pool is None:
        return
    for conn in list(pool._all):  # noqa: SLF001
        try:
            conn.close()
        except Exception:
            pass


def close_all_pools() -> None:
    """Закрыть все активные пулы."""
    for k in list(_pools.keys()):
        close_connection_pool(k)


class Database:
    """Небольшая обёртка над sqlite и инициализацией схемы."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH, *, use_pool: bool = True) -> None:
        """Создать Database с optional pooling."""
        self._db_path = Path(db_path)
        self._use_pool = bool(use_pool)
        initialize_database(self._db_path)

    def create_connection(self) -> sqlite3.Connection:
        """Вернуть соединение с БД."""
        if not self._use_pool:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            return conn

        pool = _get_pool(self._db_path)
        conn = pool.acquire()
        return _PooledConnection(conn, pool)

    def backup_database(self, destination_path: Path | str) -> None:
        """Создать резервную копию SQLite (Sprint 8 / error recovery)."""
        dest = Path(destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        close_connection_pool(self._db_path)
        src_conn = sqlite3.connect(self._db_path)
        try:
            dst_conn = sqlite3.connect(dest)
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
        finally:
            src_conn.close()
        validate_cryptosafe_database_file(dest)

    def restore_database(self, source_path: Path | str) -> None:
        """Восстановить БД из резервной копии; текущий файл сохраняется как *.db.old."""
        src = Path(source_path)
        validate_cryptosafe_database_file(src)
        close_connection_pool(self._db_path)
        if self._db_path.is_file():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            old_path = self._db_path.with_name(f"{self._db_path.stem}.pre-restore-{stamp}{self._db_path.suffix}")
            shutil.copy2(self._db_path, old_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, self._db_path)
        initialize_database(self._db_path)
        validate_cryptosafe_database_file(self._db_path)


def get_default_database() -> Database:
    """Вернуть Database с путём по умолчанию."""
    return Database()
