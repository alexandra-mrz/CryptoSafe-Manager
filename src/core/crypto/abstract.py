from __future__ import annotations

# абстракция для сервиса шифрования: методы работают с байтами, чтобы можно было заменить заглушку на реальный aes


class EncryptionService:
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        raise NotImplementedError("encrypt() должен быть реализован в наследнике.")

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        raise NotImplementedError("decrypt() должен быть реализован в наследнике.")

