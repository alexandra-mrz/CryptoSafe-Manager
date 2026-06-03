
from __future__ import annotations

from pathlib import Path

import sqlite3
import queue
from typing import Optional

from .models import DEFAULT_DB_PATH, initialize_database


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
        """Заглушка backup (будет в Sprint 8)."""
        raise NotImplementedError("Backup будет реализован в Sprint 8.")

    def restore_database(self, source_path: Path | str) -> None:
        """Заглушка restore (будет в Sprint 8)."""
        raise NotImplementedError("Restore будет реализован в Sprint 8.")


def get_default_database() -> Database:
    """Вернуть Database с путём по умолчанию."""
    return Database()
