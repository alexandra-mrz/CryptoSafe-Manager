from __future__ import annotations

# простой keymanager для спринта 1
# cry-3: здесь только заготовки методов, чтобы
# в следующих спринтах добавить реальную логику

from typing import Optional

from .crypto.abstract import EncryptionService
from .crypto.memory import zero_bytearray
from .crypto.placeholder import AES256Placeholder


class KeyManager:
    # небольшой менеджер ключей

    def __init__(self, service: Optional[EncryptionService] = None) -> None:
        self.service = service or AES256Placeholder()

    def derive_key(self, password: str, salt: bytes) -> bytes:
        # cry-3: заглушка функции derive_key
        # сейчас это очень простая логика, которую
        # можно будет заменить на нормальный kdf
        # перевод пароля в байты, чтобы потом занулить
        password_bytes = bytearray(password.encode("utf-8"))

        try:
            # простая псевдо-kdf: повтор пароля и соли
            combined = bytes(password_bytes) + salt
            # берём первые 32 байта и при необходимости дополняем нулями
            key = combined[:32].ljust(32, b"\0")
            return key
        finally:
            # cry-4: зануляем пароль в памяти, чтобы он не оставался в bytearray
            zero_bytearray(password_bytes)

    def store_key(self, key_id: str, key: bytes) -> None:
        # cry-3: заглушка для хранения ключа (будет реализована в sprint 2)
        raise NotImplementedError("store_key() будет реализован в Sprint 2.")

    def load_key(self, key_id: str) -> bytes:
        # cry-3: заглушка для загрузки ключа (будет реализована в sprint 2)
        raise NotImplementedError("load_key() будет реализован в Sprint 2.")

