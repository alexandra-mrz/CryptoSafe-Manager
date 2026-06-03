from __future__ import annotations

# раздел 8 ТЗ Sprint 5: PERF-1 … PERF-5

import os
import tempfile
import time
import tracemalloc
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

import src.core.audit.audit_logger as audit_logger_module
from src.core.audit.audit_logger import (
    AuditLogger,
    fetch_all_rows,
    reload_chain_state,
    setup_audit_subscribers,
)
from src.core.audit.log_entry import filter_audit_items, parse_log_rows
from src.core.audit.log_verifier import verify_chain
from src.core.events import EventBus


class TestSprint5AuditPerformance(unittest.TestCase):
    # тесты производительности журнала аудита

    _rows_10k: list[tuple] | None = None  # кэш 10k записей для PERF-3 и PERF-4

    def setUp(self) -> None:
        # временная БД и ключ подписи
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        from src.database.db import Database

        self.db = Database(self.path)
        private_key = Ed25519PrivateKey.generate()
        self.seed = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def tearDown(self) -> None:
        # удалить временный файл БД
        try:
            os.remove(self.path)
        except OSError:
            pass

    def _db_patches(self):
        # подмена БД, ключа, сессии; ротация выключена
        return (
            patch("src.core.audit.log_signer.get_audit_signing_key", return_value=self.seed),
            patch("src.core.audit.audit_logger.get_default_database", return_value=self.db),
            patch("src.core.audit.log_storage.get_default_database", return_value=self.db),
            patch("src.core.audit.audit_security.is_session_unlocked", return_value=True),
            patch("src.core.audit.audit_logger.apply_log_rotation"),
        )

    def _start_patches(self, patches):
        # включить все patch
        for p in patches:
            p.start()

    def _stop_patches(self, patches):
        # выключить patch
        for p in reversed(patches):
            p.stop()

    def _write_logs(self, count: int) -> None:
        # записать count событий в тестовую БД
        patches = self._db_patches()
        self._start_patches(patches)
        try:
            reload_chain_state()
            logger = AuditLogger()
            for i in range(count):
                logger.log_event("ClipboardCopied", {"source": "perf", "n": i})
        finally:
            self._stop_patches(patches)

    def _load_10k_rows(self) -> list[tuple]:
        # один раз создать 10000 записей и прочитать из БД
        if TestSprint5AuditPerformance._rows_10k is None:
            self._write_logs(10000)
            patches = self._db_patches()
            self._start_patches(patches)
            try:
                TestSprint5AuditPerformance._rows_10k = fetch_all_rows()
            finally:
                self._stop_patches(patches)
            self.assertEqual(len(TestSprint5AuditPerformance._rows_10k), 10000)
        return TestSprint5AuditPerformance._rows_10k

    def test_perf1_log_under_10ms(self) -> None:
        # PERF-1: одна запись в журнал < 10 ms
        patches = self._db_patches()
        self._start_patches(patches)
        try:
            reload_chain_state()
            logger = AuditLogger()
            t0 = time.perf_counter()
            logger.log_event("ClipboardCopied", {"source": "perf"})
            dt_ms = (time.perf_counter() - t0) * 1000.0
        finally:
            self._stop_patches(patches)
        self.assertLess(dt_ms, 10.0)

    def test_perf2_verify_1000_under_1s(self) -> None:
        # PERF-2: проверка 1000 записей < 1 с
        patches = self._db_patches()
        self._start_patches(patches)
        try:
            reload_chain_state()
            logger = AuditLogger()
            for i in range(1000):
                logger.log_event("ClipboardCopied", {"source": "perf", "n": i})
            rows = fetch_all_rows()
            t0 = time.perf_counter()
            ok, _ = verify_chain(rows)
            dt = time.perf_counter() - t0
        finally:
            self._stop_patches(patches)
        self.assertTrue(ok)
        self.assertLess(dt, 1.0)

    def test_perf3_filter_10000_under_500ms(self) -> None:
        # PERF-3: фильтр 10000 записей из БД < 500 ms
        rows = self._load_10k_rows()
        items = parse_log_rows(rows)
        t0 = time.perf_counter()
        filter_audit_items(items, search="clipboard")
        dt_ms = (time.perf_counter() - t0) * 1000.0
        self.assertLess(dt_ms, 500.0)

    def test_perf4_viewer_memory_under_50mb(self) -> None:
        # PERF-4: parse + filter 10000 записей, память < 50 MB
        rows = self._load_10k_rows()
        tracemalloc.start()
        items = parse_log_rows(rows)
        filter_audit_items(items, search="clipboard")
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertEqual(len(items), 10000)
        self.assertLess(peak, 50 * 1024 * 1024)

    def test_perf5_async_logging(self) -> None:
        # PERF-5: publish не ждёт асинхронной записи в audit_log
        bus = EventBus()
        audit_logger_module._subscribers_ready = False
        patches = self._db_patches()
        self._start_patches(patches)
        try:
            setup_audit_subscribers(bus)
            reload_chain_state()
            t0 = time.perf_counter()
            bus.publish("ClipboardCopied", {"source": "perf"})
            dt_ms = (time.perf_counter() - t0) * 1000.0
            time.sleep(0.3)
            rows = fetch_all_rows()
        finally:
            self._stop_patches(patches)
            bus.stop()

        self.assertLess(dt_ms, 10.0)
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
