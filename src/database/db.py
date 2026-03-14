
from __future__ import annotations

# простой помощник для работы с sqlite
# здесь ничего не шифруется, считается, что
# все чувствительные данные будут зашифрованы
# на уровне core перед вставкой в базу

from pathlib import Path

import sqlite3

from .models import DEFAULT_DB_PATH, get_connection, initialize_database


class Database:
    # небольшой класс-обёртка вокруг функций из models.py

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self._db_path = Path(db_path)
        initialize_database(self._db_path)

    def create_connection(self) -> sqlite3.Connection:
        # вернуть новое соединение с базой
        # в приложении может существовать несколько таких соединений одновременно
        return get_connection(self._db_path)

    # ===== Заглушки для бэкапа и восстановления (Sprint 8) =====

    def backup_database(self, destination_path: Path | str) -> None:
        # заглушка для механизма резервного копирования
        # реальная логика появится в спринте 8
        raise NotImplementedError("Backup будет реализован в Sprint 8.")

    def restore_database(self, source_path: Path | str) -> None:
        # заглушка для механизма восстановления из бэкапа
        # реальная логика появится в спринте 8
        raise NotImplementedError("Restore будет реализован в Sprint 8.")


def get_default_database() -> Database:
    # утилита для создания стандартного экземпляра базы данных
    return Database()
