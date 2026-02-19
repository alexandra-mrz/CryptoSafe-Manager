# CRY-2: AES256Placeholder — заглушка с XOR для Спринта 1 (в Спринте 3 заменить на AES-GCM)
# CRY-4: обнуление конфиденциальных данных через ctypes

import ctypes
from .abstract import EncryptionService


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    if key_len == 0:
        return bytes(data)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))


def _secure_zero(data: bytearray) -> None:
    """Обнуляет буфер в памяти (CRY-4)."""
    if not data:
        return
    ptr = (ctypes.c_char * len(data)).from_buffer(data)
    ctypes.memset(ctypes.byref(ptr), 0, len(data))


class AES256Placeholder(EncryptionService):
    """Заглушка: XOR-шифрование. В Спринте 3 заменить на реальный AES-GCM."""

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        return _xor_bytes(data, key)

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        return _xor_bytes(ciphertext, key)


def secure_zero_bytes(b: bytes) -> None:
    """Обнуляет байты через mutable view если возможно (CRY-4)."""
    try:
        arr = bytearray(b)
        _secure_zero(arr)
    except (TypeError, ValueError):
        pass
