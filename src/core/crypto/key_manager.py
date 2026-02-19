# CRY-3: Заглушка KeyManager для интеграции в Спринте 2


class KeyManager:
    """Заглушка: derive_key — фиксированный ключ из пароля; store_key/load_key — заглушки."""

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Заглушка: в Спринте 2 заменить на реальный KDF (например PBKDF2)."""
        # Простая заглушка: хэш от пароля + соль как ключ фиксированной длины
        raw = (password.encode("utf-8") + salt)[:32]
        if len(raw) < 32:
            raw = raw + b"\x00" * (32 - len(raw))
        return raw[:32]

    def store_key(self, key: bytes, path: str) -> None:
        """Заглушка для Спринта 2: сохранение ключа."""
        # В Спринте 2 — запись в key_store или защищённый файл
        pass

    def load_key(self, path: str) -> bytes:
        """Заглушка для Спринта 2: загрузка ключа."""
        # В Спринте 2 — чтение из key_store
        return b"\x00" * 32
