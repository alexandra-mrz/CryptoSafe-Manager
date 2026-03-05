import unittest

from src.core.crypto.abstract import EncryptionService
from src.core.crypto.placeholder import AES256Placeholder
from src.core.key_manager import KeyManager


class TestEncryptionPlaceholder(unittest.TestCase):
    def setUp(self) -> None:
        self.service: EncryptionService = AES256Placeholder()
        self.key = b"test-key-32-bytes------1234567890"[:32]

    def test_encrypt_decrypt_roundtrip(self) -> None:
        data = b"hello world"
        cipher = self.service.encrypt(data, self.key)
        plain = self.service.decrypt(cipher, self.key)
        self.assertEqual(plain, data)

    def test_same_input_same_output(self) -> None:
        data = b"abc"
        c1 = self.service.encrypt(data, self.key)
        c2 = self.service.encrypt(data, self.key)
        self.assertEqual(c1, c2)


class TestKeyManager(unittest.TestCase):
    def test_derive_key_length(self) -> None:
        km = KeyManager()
        key = km.derive_key("password", b"salt")
        self.assertEqual(len(key), 32)


if __name__ == "__main__":
    unittest.main()


