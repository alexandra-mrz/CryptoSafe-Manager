
from __future__ import annotations

# заглушка aes256placeholder: вместо реального aes используется простое xor-шифрование по байтам

from .abstract import EncryptionService
from .memory import zero_bytearray


class AES256Placeholder(EncryptionService):

    """Публичный класс AES256Placeholder."""
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Encrypt."""
        if not data or not key:
            return b""

        temp = bytearray(data)
        out = bytearray(len(temp))

        for i, b in enumerate(temp):
            out[i] = b ^ key[i % len(key)]

        zero_bytearray(temp)

        return bytes(out)

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt."""
        return self.encrypt(ciphertext, key)


def get_default_encryption_service() -> EncryptionService:
    """Get default encryption service."""
    return AES256Placeholder()
