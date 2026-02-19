# CFG-2: Настройки хранятся в таблице settings с шифрованием для конфиденциальных опций

from src.database.db import get_db


def get_setting(key: str, default=None):
    """Читает настройку из таблицы settings."""
    try:
        db = get_db()
        with db.get_connection() as conn:
            row = conn.execute(
                "SELECT setting_value, encrypted FROM settings WHERE setting_key = ?",
                (key,)
            ).fetchone()
            if row is None:
                return default
            value, encrypted = row[0], row[1]
            if encrypted and value is not None:
                # Заглушка: в продакшене расшифровать через EncryptionService
                return value  # пока храним как есть
            return value.decode("utf-8") if isinstance(value, bytes) else value
    except Exception:
        return default


def set_setting(key: str, value, encrypted: bool = False) -> None:
    """Записывает настройку. encrypted=True — конфиденциальная (шифровать в Спринте 3)."""
    try:
        db = get_db()
        data = value.encode("utf-8") if isinstance(value, str) else value
        enc_flag = 1 if encrypted else 0
        with db.get_connection() as conn:
            conn.execute(
                """INSERT INTO settings (setting_key, setting_value, encrypted)
                   VALUES (?, ?, ?) ON CONFLICT(setting_key) DO UPDATE SET
                   setting_value = excluded.setting_value, encrypted = excluded.encrypted""",
                (key, data, enc_flag)
            )
    except Exception:
        pass
