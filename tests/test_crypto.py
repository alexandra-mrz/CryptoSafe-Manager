import os
import sys
import unittest
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from src.core.crypto.abstract import EncryptionService
from src.core.crypto.placeholder import AES256Placeholder

class TestCrypto(unittest.TestCase):
    def test_placeholder_encrypt_decrypt(self):
        svc = AES256Placeholder()
        key = b"x" * 32
        data = b"secret password"
        ct = svc.encrypt(data, key)
        self.assertNotEqual(ct, data)
        dec = svc.decrypt(ct, key)
        self.assertEqual(dec, data)
    def test_placeholder_is_encryption_service(self):
        self.assertTrue(issubclass(AES256Placeholder, EncryptionService))
