
from __future__ import annotations

# заглушка aes256placeholder: вместо реального aes используется простое xor-шифрование по байтам

from .abstract import EncryptionService
from .memory import zero_bytearray


class AES256Placeholder(EncryptionService):

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        if not data or not key:
            return b""

        temp = bytearray(data)
        out = bytearray(len(temp))

        for i, b in enumerate(temp):
            out[i] = b ^ key[i % len(key)]

        zero_bytearray(temp)

        return bytes(out)

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        return self.encrypt(ciphertext, key)


def get_default_encryption_service() -> EncryptionService:
    return AES256Placeholder()
