from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core.vault.encryption_service import VaultEncryptionService
from src.core.vault.entry_manager import EntryManager
from src.core.vault.password_generator import PasswordGenOptions, generate_password
from src.database.db import Database


class TestSprint3EncryptionRoundTrip(unittest.TestCase):
    def test_encryption_round_trip(self) -> None:
        """Проверить шифрование/расшифровку и целостность."""
        service = VaultEncryptionService()
        key = b"\x11" * 32

        entry = {
            "title": "Example",
            "username": "user@example.com",
            "password": "Secret123!",
            "url": "https://example.com",
            "notes": "Additional information",
            "category": "Work",
            "version": 1,
        }

        blob = service.encrypt_entry(entry, key)
        self.assertIsInstance(blob, (bytes, bytearray))

        # BLOB не должен содержать plaintext.
        self.assertNotIn(b"Example", blob)
        self.assertNotIn(b"Secret123", blob)

        # Проверяем корректную расшифровку.
        payload = service.decrypt_entry(bytes(blob), key)
        self.assertEqual(payload.get("v"), 1)
        data = payload.get("data")
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("title"), "Example")
        self.assertEqual(data.get("password"), "Secret123!")


class TestSprint3CrudIntegration(unittest.TestCase):
    def _make_manager(self) -> EntryManager:
        """Создать менеджер на временной базе."""
        tmp = tempfile.TemporaryDirectory()
        db_path = Path(tmp.name) / "test.db"
        db = Database(db_path, use_pool=False)
        self.addCleanup(tmp.cleanup)
        return EntryManager(db=db)

    def test_crud_integration_100_entries(self) -> None:
        """Проверить create/update/delete на 100 записей."""
        mgr = self._make_manager()
        key = b"\x22" * 32

        # Патчим проверку сессии и получение ключа.
        with patch("src.core.vault.entry_manager.is_session_unlocked", return_value=True), patch(
            "src.core.key_manager.KeyManager.get_vault_encryption_key", return_value=key
        ):
            ids = []
            for i in range(100):
                e = mgr.create_entry(
                    {
                        "title": f"Site {i}",
                        "username": f"user{i}@mail.com",
                        "password": f"Pass{i}!Aa1",
                        "url": f"https://example{i}.com",
                        "notes": "n",
                        "category": "c",
                        "version": 1,
                        "tags": "t",
                    }
                )
                ids.append(int(e.id or 0))

            all_items = mgr.get_all_entries()
            self.assertEqual(len(all_items), 100)

            for entry_id in ids[:10]:
                mgr.update_entry(entry_id, {"title": "Updated", "version": 1})

            for entry_id in ids[10:20]:
                mgr.delete_entry(entry_id, soft_delete=True)

            after = mgr.get_all_entries()
            self.assertEqual(len(after), 90)

            found_updated = any(it.get("title") == "Updated" for it in after)
            self.assertTrue(found_updated)


class TestSprint3Concurrency(unittest.TestCase):
    def test_concurrency_simple(self) -> None:
        """Проверить простую конкурентную запись."""
        tmp = tempfile.TemporaryDirectory()
        db_path = Path(tmp.name) / "test.db"
        db = Database(db_path, use_pool=False)
        self.addCleanup(tmp.cleanup)
        key = b"\x33" * 32

        import threading

        errors: list[str] = []

        def worker(prefix: str) -> None:
            mgr = EntryManager(db=db)
            try:
                for i in range(30):
                    mgr.create_entry(
                        {
                            "title": f"{prefix}-{i}",
                            "username": "u",
                            "password": "P@ssw0rdAa1!",
                            "url": "https://example.com",
                            "notes": "",
                            "category": "",
                            "version": 1,
                            "tags": "",
                        }
                    )
            except Exception as e:  # noqa: BLE001
                errors.append(str(e))

        with patch("src.core.vault.entry_manager.is_session_unlocked", return_value=True), patch(
            "src.core.key_manager.KeyManager.get_vault_encryption_key", return_value=key
        ):
            threads = [threading.Thread(target=worker, args=(f"t{n}",)) for n in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(errors, [])
            mgr2 = EntryManager(db=db)
            items = mgr2.get_all_entries()
            self.assertEqual(len(items), 4 * 30)


class TestSprint3PasswordGenerator(unittest.TestCase):
    def test_generator_10000(self) -> None:
        """Проверить генератор на 10 000 паролей."""
        opts = PasswordGenOptions(length=16, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True)
        seen = set()
        for _ in range(10_000):
            pw = generate_password(opts)
            self.assertTrue(8 <= len(pw) <= 64)
            self.assertTrue(any(c.isupper() for c in pw))
            self.assertTrue(any(c.islower() for c in pw))
            self.assertTrue(any(c.isdigit() for c in pw))
            self.assertTrue(any(c in "!@#$%^&*" for c in pw))
            score = 0
            if len(pw) >= 12:
                score += 1
            if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
                score += 1
            if any(c.isdigit() for c in pw):
                score += 1
            if any(c in "!@#$%^&*" for c in pw):
                score += 1
            self.assertGreaterEqual(score, 3)

            seen.add(pw)

        self.assertEqual(len(seen), 10_000)

