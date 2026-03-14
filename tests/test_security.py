# тесты безопасности: argon2, pbkdf2, кэш ключей, смена пароля

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
    load_key_metadata,
)
from src.core.crypto.authentication import (
    set_master_password,
    verify_master_password,
    get_encryption_key,
)
from src.core.crypto.placeholder import AES256Placeholder
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
        self.db = Database(self.path)
        self._patcher = patch("src.core.crypto.key_storage.get_default_database", return_value=self.db)
        self._patcher.start()

    def tearDown(self) -> None:
        self._patcher.stop()
        try:
            os.remove(self.path)
        except OSError:
            pass

    def test_change_password_all_entries_accessible_with_new(self) -> None:
        # 1) создать хранилище с паролем "А"
        set_master_password(self.PASSWORD_A)
        key_a = get_encryption_key(self.PASSWORD_A)
        cipher = AES256Placeholder()

        # 2) добавить 10 записей
        conn = self.db.create_connection()
        try:
            cur = conn.cursor()
            from datetime import datetime
            now = datetime.utcnow().isoformat()
            self.plaintexts = []
            for i in range(10):
                plain = f"password_{i}".encode("utf-8")
                self.plaintexts.append(plain)
                enc = cipher.encrypt(plain, key_a)
                cur.execute(
                    """
                    INSERT INTO vault_entries
                    (title, username, encrypted_password, url, notes, tags, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (f"Entry{i}", f"user{i}", enc.hex(), "", "", "", now, now),
                )
            conn.commit()
        finally:
            conn.close()

        # 3) сменить пароль на "В" (логика ротации как в change_password_dialog)
        import binascii
        from src.core.crypto.key_derivation import derive_key_pbkdf2, derive_key_argon2

        if not verify_master_password(self.PASSWORD_A):
            self.fail("старый пароль должен быть верным")
        old_key = get_encryption_key(self.PASSWORD_A)
        salt_new = os.urandom(16)
        new_key = derive_key_pbkdf2(
            self.PASSWORD_B, salt_new, length=32, iterations=100_000
        )
        conn = self.db.create_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, encrypted_password FROM vault_entries")
            rows = cur.fetchall()
            for row in rows:
                entry_id = row[0]
                enc_value = row[1]
                if enc_value:
                    old_bytes = bytes.fromhex(enc_value)
                    plain = cipher.decrypt(old_bytes, old_key)
                    new_bytes = cipher.encrypt(plain, new_key)
                    cur.execute(
                        "UPDATE vault_entries SET encrypted_password = ? WHERE id = ?",
                        (new_bytes.hex(), entry_id),
                    )
            conn.commit()
        finally:
            conn.close()

        auth_salt = os.urandom(16)
        auth_key = derive_key_argon2(self.PASSWORD_B, auth_salt)
        auth_hash_hex = binascii.hexlify(auth_key).decode("ascii")
        auth_salt_hex = binascii.hexlify(auth_salt).decode("ascii")
        save_key_metadata("master_auth", auth_salt_hex, auth_hash_hex, "argon2id_t3_m64mb_p4_32")
        save_key_metadata("master_enc", binascii.hexlify(salt_new).decode("ascii"), "", "pbkdf2_sha256_100000_32")

        # 4) убедиться, что все записи доступны с новым паролем
        key_b = get_encryption_key(self.PASSWORD_B)
        conn = self.db.create_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, encrypted_password FROM vault_entries ORDER BY id")
            rows = cur.fetchall()
            self.assertEqual(len(rows), 10)
            for i, row in enumerate(rows):
                enc_value = row[1]
                dec = cipher.decrypt(bytes.fromhex(enc_value), key_b)
                self.assertEqual(dec, self.plaintexts[i])
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
