# тесты безопасности: argon2, pbkdf2, кэш ключей, смена пароля

import binascii
import os
import tempfile
import unittest
from unittest.mock import patch

from src.core.crypto.key_derivation import (
    derive_key_argon2,
    derive_key_pbkdf2,
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_HASH_LENGTH,
)
from src.core.crypto.memory import zero_bytearray
from src.core.crypto.key_storage import (
    cache_key,
    clear_all_keys,
    get_cached_key,
    set_app_active,
    save_key_metadata,
)
from src.core.crypto.authentication import (
    set_master_password,
    verify_master_password,
    get_encryption_key,
    unlock_session,
)
from src.core.vault.encryption_service import VaultEncryptionService
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database


class TestArgon2ParameterValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.password = "TestPassword123!"
        self.salt = b"1234567890123456"

    def test_default_params_yield_valid_hash(self) -> None:
        key = derive_key_argon2(self.password, self.salt)
        self.assertEqual(len(key), ARGON2_HASH_LENGTH)
        self.assertNotEqual(key, b"")

    def test_different_time_cost_yield_valid_hashes(self) -> None:
        for t in (1, 2, 3):
            key = derive_key_argon2(
                self.password, self.salt, time_cost=t
            )
            self.assertEqual(len(key), 32)
            self.assertIsInstance(key, bytes)

    def test_different_memory_cost_yield_valid_hashes(self) -> None:
        for m in (16 * 1024, 32 * 1024, 64 * 1024):
            key = derive_key_argon2(
                self.password, self.salt, memory_cost=m
            )
            self.assertEqual(len(key), 32)
            self.assertNotEqual(key, b"")

    def test_different_parallelism_yield_valid_hashes(self) -> None:
        for p in (1, 2, 4):
            key = derive_key_argon2(
                self.password, self.salt, parallelism=p
            )
            self.assertEqual(len(key), 32)


class TestKeyDerivationConsistency(unittest.TestCase):
    def test_pbkdf2_same_input_same_output_100_times(self) -> None:
        password = "SamePassword!"
        salt = b"fixed_salt_16bytes"
        results = []
        for _ in range(100):
            key = derive_key_pbkdf2(password, salt)
            results.append(key)
        for i in range(1, 100):
            self.assertEqual(results[0], results[i])

    def test_argon2_same_input_same_output_100_times(self) -> None:
        password = "SamePassword!"
        salt = b"fixed_salt_16bytes"
        results = []
        for _ in range(100):
            key = derive_key_argon2(password, salt)
            results.append(key)
        for i in range(1, 100):
            self.assertEqual(results[0], results[i])


class TestConstantTimeComparison(unittest.TestCase):
    def setUp(self) -> None:
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.db = Database(self.path)

    def tearDown(self) -> None:
        try:
            os.remove(self.path)
        except OSError:
            pass

    def test_verify_password_uses_compare_digest(self) -> None:
        with patch("src.core.crypto.key_storage.get_default_database", return_value=self.db):
            set_master_password("MyStr0ng!PassOne")
            with patch("src.core.crypto.authentication.secrets.compare_digest") as mock_compare:
                verify_master_password("wrong_password")
                mock_compare.assert_called_once()


class TestMemorySecurity(unittest.TestCase):
    def test_zero_bytearray_clears_buffer(self) -> None:
        data = bytearray(b"secret_key_data_here!!!")
        zero_bytearray(data)
        self.assertEqual(data, bytearray(len(data)))

    def test_clear_all_keys_removes_cached_key(self) -> None:
        set_app_active(True)
        with patch("src.core.crypto.authentication.is_session_unlocked", return_value=True):
            cache_key("test_id", b"some_key_bytes_32!!!")
        self.assertIsNotNone(get_cached_key("test_id"))
        clear_all_keys()
        self.assertIsNone(get_cached_key("test_id"))


class TestPasswordChangeIntegration(unittest.TestCase):
    PASSWORD_A = "MyStr0ng!PassOne"
    PASSWORD_B = "MyStr0ng!PassTwo"

    def setUp(self) -> None:
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.db = Database(self.path, use_pool=False)
        self._patcher = patch("src.core.crypto.key_storage.get_default_database", return_value=self.db)
        self._patcher.start()

    def tearDown(self) -> None:
        self._patcher.stop()
        try:
            os.remove(self.path)
        except OSError:
            pass

    def test_change_password_all_entries_accessible_with_new(self) -> None:
        # 1) хранилище с паролем A (схема Sprint 3: encrypted_data BLOB)
        set_master_password(self.PASSWORD_A)
        self.assertTrue(unlock_session(self.PASSWORD_A))

        # 2) 10 записей через EntryManager (AES-GCM внутри encrypted_data)
        self.plaintext_passwords = [f"password_{i}" for i in range(10)]
        em = EntryManager(self.db)
        for i in range(10):
            em.create_entry(
                {
                    "title": f"Entry{i}",
                    "username": f"user{i}",
                    "password": self.plaintext_passwords[i],
                    "url": "",
                    "notes": "",
                    "tags": "",
                }
            )

        # 3) ротация как в change_password_dialog._rotate_keys (ветка encrypted_data)
        if not verify_master_password(self.PASSWORD_A):
            self.fail("старый пароль должен быть верным")
        old_key = get_encryption_key(self.PASSWORD_A)
        salt_new = os.urandom(16)
        new_key = derive_key_pbkdf2(
            self.PASSWORD_B, salt_new, length=32, iterations=100_000
        )
        vault_cipher = VaultEncryptionService()
        conn = self.db.create_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, encrypted_data FROM vault_entries ORDER BY id")
            rows = cur.fetchall()
            self.assertEqual(len(rows), 10)
            conn.execute("BEGIN")
            for row in rows:
                enc_value = row["encrypted_data"]
                if not enc_value:
                    continue
                payload = vault_cipher.decrypt_entry(bytes(enc_value), old_key)
                data = payload.get("data") or {}
                if not isinstance(data, dict):
                    data = {}
                created_at_payload = str(payload.get("created_at", "") or "")
                version_payload = int(payload.get("v", 1) or 1)
                new_blob = vault_cipher.encrypt_entry(
                    data,
                    new_key,
                    created_at=created_at_payload,
                    version=version_payload,
                )
                cur.execute(
                    "UPDATE vault_entries SET encrypted_data = ? WHERE id = ?",
                    (new_blob, row["id"]),
                )
            conn.commit()
        finally:
            conn.close()

        salt_auth = os.urandom(16)
        auth_key = derive_key_argon2(self.PASSWORD_B, salt_auth)
        auth_hash_hex = binascii.hexlify(auth_key).decode("ascii")
        auth_salt_hex = binascii.hexlify(salt_auth).decode("ascii")
        save_key_metadata(
            "master_auth",
            auth_salt_hex,
            auth_hash_hex,
            "argon2id_t3_m64mb_p4_32",
        )
        cache_key("master_auth", auth_key)
        save_key_metadata(
            "master_enc",
            binascii.hexlify(salt_new).decode("ascii"),
            "",
            "pbkdf2_sha256_100000_32",
        )
        cache_key("master_enc", new_key)

        # 4) все записи читаются с ключом от пароля B
        key_b = get_encryption_key(self.PASSWORD_B)
        conn = self.db.create_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT encrypted_data FROM vault_entries ORDER BY id")
            rows = cur.fetchall()
            self.assertEqual(len(rows), 10)
            for i, row in enumerate(rows):
                dec = vault_cipher.decrypt_entry(bytes(row["encrypted_data"]), key_b)
                data = dec.get("data") or {}
                self.assertEqual(data.get("password"), self.plaintext_passwords[i])
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
