
from __future__ import annotations

from typing import TYPE_CHECKING

# абстракция для сервиса шифрования: методы работают с байтами, чтобы можно было заменить заглушку на реальный aes

if TYPE_CHECKING:
    # импорт только для подсказок типов, чтобы не было циклов
    from src.core.key_manager import KeyManager


class EncryptionService:
    # базовые методы, которые работают с уже готовым байтовым ключом

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        raise NotImplementedError("encrypt() должен быть реализован в наследнике.")

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        raise NotImplementedError("decrypt() должен быть реализован в наследнике.")

    # методы второго спринта: принимают keymanager вместо сырого ключа

    def encrypt_with_manager(self, data: bytes, key_manager: "KeyManager", key_id: str) -> bytes:
        key = key_manager.load_key(key_id)
        return self.encrypt(data, key)

    def decrypt_with_manager(self, ciphertext: bytes, key_manager: "KeyManager", key_id: str) -> bytes:
        key = key_manager.load_key(key_id)
        return self.decrypt(ciphertext, key)
