from __future__ import annotations

import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core.vault.entry_manager import EntryManager
from src.database.db import Database


class TestSprint3Performance(unittest.TestCase):
    def _make_manager_with_data(self, n: int = 1000) -> EntryManager:
        """Создать менеджер и заполнить тестовыми записями."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = Path(tmp.name) / "perf.db"
        db = Database(db_path, use_pool=False)
        mgr = EntryManager(db=db)

        key = b"\x44" * 32
        with patch("src.core.vault.entry_manager.is_session_unlocked", return_value=True), patch(
            "src.core.key_manager.KeyManager.get_vault_encryption_key", return_value=key
        ):
            for i in range(n):
                mgr.create_entry(
                    {
                        "title": f"Site {i}",
                        "username": f"user{i}@mail.com",
                        "password": f"Pass{i}!Aa1",
                        "url": f"https://example{i}.com",
                        "notes": "note text",
                        "category": "work",
                        "version": 1,
                        "tags": "tag1,tag2",
                    }
                )
        return mgr

    def test_perf_loading_1000_under_2s_and_memory_under_50mb(self) -> None:
        """Проверить загрузку 1000 записей и память."""
        mgr = self._make_manager_with_data(1000)
        key = b"\x44" * 32

        with patch("src.core.vault.entry_manager.is_session_unlocked", return_value=True), patch(
            "src.core.key_manager.KeyManager.get_vault_encryption_key", return_value=key
        ):
            tracemalloc.start()
            t0 = time.perf_counter()
            items = mgr.get_all_entries()
            dt = time.perf_counter() - t0
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

        self.assertEqual(len(items), 1000)
        self.assertLess(dt, 2.0)
        self.assertLess(peak, 50 * 1024 * 1024)

    def test_perf_search_1000_under_200ms(self) -> None:
        """Проверить время простого поиска на 1000 записях."""
        mgr = self._make_manager_with_data(1000)
        key = b"\x44" * 32

        with patch("src.core.vault.entry_manager.is_session_unlocked", return_value=True), patch(
            "src.core.key_manager.KeyManager.get_vault_encryption_key", return_value=key
        ):
            items = mgr.get_all_entries()

        # Поиск как в GUI: подстрока по нескольким полям.
        needle = "example99"
        t0 = time.perf_counter()
        found = []
        nlow = needle.lower()
        for e in items:
            hay = " ".join(
                [
                    str(e.get("title", "")),
                    str(e.get("username", "")),
                    str(e.get("url", "")),
                    str(e.get("notes", "")),
                ]
            ).lower()
            if nlow in hay:
                found.append(e)
        dt = time.perf_counter() - t0

        self.assertLess(dt, 0.2)
        self.assertTrue(len(found) >= 1)

