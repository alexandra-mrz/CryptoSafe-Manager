from __future__ import annotations

# раздел 9 ТЗ Sprint 5: TEST-1 … TEST-5

import json
import os
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from src.core.audit.audit_logger import AuditLogger, fetch_all_rows, reload_chain_state
from src.core.audit.log_export import (
    export_audit_log,
    load_signed_json_export,
    rows_from_signed_json,
    verify_export_independent,
)
from src.core.audit.log_integrity import (
    recover_audit_log_clear,
    safe_verify_manual_full,
    verify_manual_full,
    check_audit_table_exists,
)
from src.core.audit.log_verifier import verify_chain
from src.database.db import Database


class TestAuditSprint5Validation(unittest.TestCase):
    # приёмочные тесты журнала аудита

    def setUp(self) -> None:
        # временная БД и ключ подписи для каждого теста
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.db = Database(self.path)
        private_key = Ed25519PrivateKey.generate()
        self.seed = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.password = "test-password"

    def tearDown(self) -> None:
        # удалить временный файл БД
        try:
            os.remove(self.path)
        except OSError:
            pass

    def _patches(self):
        # подмена БД, ключа, сессии и отключение ротации
        return (
            patch("src.core.audit.log_signer.get_audit_signing_key", return_value=self.seed),
            patch("src.core.audit.audit_logger.get_default_database", return_value=self.db),
            patch("src.core.audit.log_storage.get_default_database", return_value=self.db),
            patch("src.core.audit.log_export.get_default_database", return_value=self.db),
            patch("src.core.audit.log_integrity.get_default_database", return_value=self.db),
            patch("src.core.audit.log_export.verify_master_password", return_value=True),
            patch("src.core.audit.audit_logger.apply_log_rotation"),
            patch("src.core.audit.audit_security.is_session_unlocked", return_value=True),
            patch("src.core.audit.audit_security.get_default_database", return_value=self.db),
        )

    def _start_patches(self, patches):
        # включить все patch
        for p in patches:
            p.start()

    def _stop_patches(self, patches):
        # выключить patch в обратном порядке
        for p in reversed(patches):
            p.stop()

    def _write_logs(self, count: int) -> None:
        # записать count событий в тестовую БД
        patches = self._patches()
        self._start_patches(patches)
        try:
            reload_chain_state()
            logger = AuditLogger()
            for i in range(count):
                logger.log_event("ClipboardCopied", {"source": "test", "n": i})
        finally:
            self._stop_patches(patches)

    def _last_entry_details(self) -> dict:
        # details последней записи из audit_log (для TEST-5)
        conn = self.db.create_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT entry_data FROM audit_log ORDER BY sequence_number DESC LIMIT 1"
            )
            row = cur.fetchone()
        finally:
            conn.close()
        raw = row[0]
        if isinstance(raw, memoryview):
            raw = raw.tobytes()
        body = json.loads(raw.decode("utf-8"))
        return body.get("entry_data", {}).get("details", {})

    def test_test1_integrity_tamper_detected(self) -> None:
        # TEST-1: 1) 1000 записей 2) вмешательство 3) обнаружение при проверке
        self._write_logs(1000)
        conn = self.db.create_connection()
        try:
            conn.execute("DROP TRIGGER IF EXISTS audit_log_block_update")
            conn.execute(
                "UPDATE audit_log SET signature = 'tampered' WHERE sequence_number = 500"
            )
            conn.commit()
        finally:
            conn.close()

        patches = self._patches()
        self._start_patches(patches)
        try:
            result = verify_manual_full()
        finally:
            self._stop_patches(patches)

        self.assertFalse(result["ok"])

    def test_test2_performance_throughput(self) -> None:
        # TEST-2: 1) 10000 событий  2) измерить throughput  3) измерить время verify
        patches = self._patches()
        self._start_patches(patches)
        try:
            reload_chain_state()
            logger = AuditLogger()
            # шаг 1: записать ровно 10000 событий
            t0 = time.perf_counter()
            for i in range(10000):
                logger.log_event("ClipboardCopied", {"source": "perf", "n": i})
            log_time = time.perf_counter() - t0

            rows = fetch_all_rows()
            self.assertEqual(len(rows), 10000)

            # шаг 2: throughput (событий в секунду)
            self.assertGreater(log_time, 0.0)
            throughput = 10000.0 / log_time

            # шаг 3: время полной проверки цепочки и подписей
            t1 = time.perf_counter()
            chain_ok, chain_errors = verify_chain(rows)
            verify_time = time.perf_counter() - t1
        finally:
            self._stop_patches(patches)

        self.assertTrue(chain_ok, chain_errors)
        self.assertGreater(throughput, 0.0)
        self.assertGreater(verify_time, 0.0)
        # PERF-2: 1000 записей < 1 с → для 10000 ожидаем < 10 с
        self.assertLess(verify_time, 10.0)
        # метрики TEST-2 (для отчёта / демонстрации преподавателю)
        self.__class__._last_test2_log_time = log_time
        self.__class__._last_test2_throughput = throughput
        self.__class__._last_test2_verify_time = verify_time

    def test_test3_export_import_verify(self) -> None:
        # TEST-3: 1) signed JSON  2) independent verifier  3) import + integrity
        self._write_logs(50)
        patches = self._patches()
        self._start_patches(patches)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "audit.json")
                out = export_audit_log("json", path, self.password, encrypt=False)
                data = load_signed_json_export(out, self.password)
                ok, errors = verify_export_independent(data, self.seed)
                self.assertTrue(ok, errors)

                imported_rows = rows_from_signed_json(data)
                chain_ok, chain_errors = verify_chain(imported_rows)
                self.assertTrue(chain_ok, chain_errors)
        finally:
            self._stop_patches(patches)

    def test_test4_failure_recovery(self) -> None:
        # TEST-4: порча БД → деградация → восстановление
        self._write_logs(10)
        conn = self.db.create_connection()
        try:
            conn.execute("DROP TRIGGER IF EXISTS audit_log_block_update")
            conn.execute(
                "UPDATE audit_log SET entry_data = ? WHERE sequence_number = 0",
                (b"broken",),
            )
            conn.commit()
        finally:
            conn.close()

        patches = self._patches()
        self._start_patches(patches)
        try:
            result = safe_verify_manual_full()
            self.assertFalse(result["ok"])

            recover_audit_log_clear()
            result2 = verify_manual_full()
            self.assertTrue(result2["ok"])
        finally:
            self._stop_patches(patches)

    def test_test5_security_sql_and_tamper(self) -> None:
        # TEST-5: SQL injection, privilege escalation, tampering — blocked and logged
        patches = self._patches()
        self._start_patches(patches)
        try:
            reload_chain_state()
            logger = AuditLogger()
            sql_attack = "'; DROP TABLE audit_log; --"
            logger.log_event(
                "UserLoggedIn",
                {"source": "test", "comment": sql_attack, "password": "secret"},
            )

            self.assertTrue(check_audit_table_exists())
            details = self._last_entry_details()
            self.assertEqual(details.get("password"), "[REDACTED]")

            conn = self.db.create_connection()
            try:
                with self.assertRaises(sqlite3.Error):
                    conn.execute(
                        "UPDATE audit_log SET signature='hack' WHERE sequence_number=0"
                    )
            finally:
                conn.close()

            conn = self.db.create_connection()
            try:
                conn.execute("DROP TRIGGER IF EXISTS audit_log_block_update")
                conn.execute(
                    "UPDATE audit_log SET signature='hack' WHERE sequence_number=0"
                )
                conn.commit()
            finally:
                conn.close()

            result = verify_manual_full()
            self.assertFalse(result["ok"])

            conn = self.db.create_connection()
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT COUNT(*) FROM audit_security_log
                    WHERE event_type = 'TAMPERING_DETECTED'
                    """
                )
                sec_count = int(cur.fetchone()[0])
            finally:
                conn.close()
            self.assertGreaterEqual(sec_count, 1)
        finally:
            self._stop_patches(patches)

        # privilege escalation: без входа читать журнал нельзя (SEC-4)
        with patch("src.core.audit.audit_security.is_session_unlocked", return_value=False):
            with self.assertRaises(PermissionError):
                fetch_all_rows()


if __name__ == "__main__":
    unittest.main()
