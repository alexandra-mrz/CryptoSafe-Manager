import ctypes
from .abstract import EncryptionService
def _xor_bytes(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    if key_len == 0:
        return bytes(data)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))
def _secure_zero(data: bytearray) -> None:
    if not data:
        return
    ptr = (ctypes.c_char * len(data)).from_buffer(data)
    ctypes.memset(ctypes.byref(ptr), 0, len(data))
class AES256Placeholder(EncryptionService):
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        return _xor_bytes(data, key)
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        return _xor_bytes(ciphertext, key)
def secure_zero_bytes(b: bytes) -> None:
    try:
        arr = bytearray(b)
        _secure_zero(arr)
    except (TypeError, ValueError):
        pass
