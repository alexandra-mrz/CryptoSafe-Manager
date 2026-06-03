from __future__ import annotations

# Sprint 7 / §11: PERF-1 … PERF-4

import gc
import hashlib
import hmac
import os
import statistics
import tempfile
import time
import tracemalloc
import unittest
from contextlib import ExitStack
from typing import Callable
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from src.core.audit.audit_logger import AuditLogger, reload_chain_state
from src.core.clipboard.clipboard_service import SecureClipboardItem
from src.core.import_export.import_security import keys_differ, wipe_sensitive
from src.core.import_export.importer import VaultImporter
from src.core.import_export.share_crypto import _sign_plain, _verify_plain
from src.core.security.activity_monitor import ActivityMonitor
from src.core.security.integration import secure_contains
from src.core.security.security_config import (
    PROFILE_STANDARD,
    SecuritySettings,
    apply_profile,
    validate_settings,
)
from src.core.security.side_channel_protection import constant_time_compare
from src.core.vault.encryption_service import VaultEncryptionService
from src.database.db import Database


def _has_pyqt6() -> bool:
    try:
        import PyQt6.QtWidgets  # noqa: F401

        return True
    except ImportError:
        return False


def _fast_constant_time_compare(a, b) -> bool:
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return a == b


_CT_PATCH_TARGETS = (
    "src.core.security.side_channel_protection.constant_time_compare",
    "src.core.crypto.authentication.constant_time_compare",
    "src.core.import_export.import_security.constant_time_compare",
    "src.core.import_export.importer.constant_time_compare",
    "src.core.import_export.share_crypto.constant_time_compare",
    "src.core.audit.log_signer.constant_time_compare",
    "src.core.security.integration.constant_time_compare",
)


def _overhead_ratio(baseline: Callable[[], None], secured: Callable[[], None], *, rounds: int = 5) -> float:
    def _median(fn: Callable[[], None]) -> float:
        fn()
        samples = []
        for _ in range(rounds):
            gc.collect()
            t0 = time.perf_counter()
            fn()
            samples.append(time.perf_counter() - t0)
        return statistics.median(samples)

    t_base = _median(baseline)
    t_sec = _median(secured)
    return (t_sec - t_base) / max(t_base, 1e-9)


def _retained_traced_memory(fn: Callable[[], None]) -> int:
    gc.collect()
    tracemalloc.start()
    fn()
    gc.collect()
    retained, _peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return retained


def _clipboard_wipe_no_secure(self) -> None:
    self.data_type = ""
    self.source_entry_id = None
    self.masked_data = bytearray()
    self.mask = bytearray()
    self.clipboard_value = ""
    self.secure_locked = False


def _memory_protection_patches() -> list:
    return [
        patch("src.core.vault.encryption_service.wipe_local", lambda _b: None),
        patch("src.core.security.memory_guard.secure_wipe", lambda _b: None),
        patch("src.core.security.memory_guard.wipe_local", lambda _b: None),
        patch("src.core.import_export.import_security.secure_wipe", lambda _b: None),
        patch(
            "src.core.clipboard.clipboard_service.SecureClipboardItem.secure_wipe",
            _clipboard_wipe_no_secure,
        ),
        patch("src.core.audit.audit_logger.wipe_local", lambda _b: None),
    ]


class TestPerf1ConstantTimeOverhead(unittest.TestCase):
    # PERF-1: constant-time operations add < 10% overhead

    def test_perf1_constant_time_overhead_under_10_percent(self) -> None:
        meta = {"salt": "00" * 16, "hash": "ab" * 32}
        derived = b"\xcd" * 32
        k1 = b"\x01" * 32
        k2 = b"\x02" * 32
        plain = b'{"entry":{"title":"t"}}'
        share_pw = "share-pw"
        share_pkg = {
            "integrity": {"hash": hashlib.sha256(plain).hexdigest()},
            "signature": {"value": _sign_plain(plain, share_pw)},
        }
        importer = VaultImporter()
        imp_pkg = {"integrity": {"hash": hashlib.sha256(plain).hexdigest()}}

        from src.core.crypto import authentication
        from src.core.audit import log_signer

        audit_key = b"\xaa" * 32
        audit_data = b"audit-payload"
        audit_sig = hmac.new(audit_key, audit_data, hashlib.sha256).hexdigest()

        def _work() -> None:
            for _ in range(40):
                authentication.verify_master_password("pw")
                keys_differ(k1, k2)
                importer._verify_integrity(plain, imp_pkg)
                _verify_plain(plain, share_pkg, share_pw)
                log_signer._verify_hmac(audit_data, audit_sig)
                secure_contains("site", "my site title")

        def _run(use_fast: bool) -> None:
            stack = ExitStack()
            if use_fast:
                for target in _CT_PATCH_TARGETS:
                    stack.enter_context(patch(target, _fast_constant_time_compare))
            stack.enter_context(patch.object(authentication, "load_key_metadata", return_value=meta))
            stack.enter_context(patch.object(authentication, "derive_key_argon2", return_value=derived))
            stack.enter_context(patch.object(authentication, "stack_canary_ok", return_value=True))
            stack.enter_context(patch.object(authentication, "wipe_local"))
            stack.enter_context(patch.object(log_signer, "get_audit_signing_key", return_value=audit_key))
            with stack:
                _work()

        overhead = _overhead_ratio(lambda: _run(True), lambda: _run(False), rounds=9)
        self.assertLess(overhead, 0.10)


class TestPerf2MemoryProtectionOverhead(unittest.TestCase):
    # PERF-2: memory protection adds < 5% memory overhead

    def test_perf2_memory_protection_overhead_under_5_percent(self) -> None:
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        private_key = Ed25519PrivateKey.generate()
        seed = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        db = Database(path)
        patches = [
            patch("src.core.audit.log_signer.get_audit_signing_key", return_value=seed),
            patch("src.core.audit.audit_logger.get_default_database", return_value=db),
            patch("src.core.audit.log_storage.get_default_database", return_value=db),
            patch("src.core.audit.audit_security.is_session_unlocked", return_value=True),
            patch("src.core.audit.audit_logger.apply_log_rotation"),
        ]
        from datetime import datetime, timezone

        key = b"\x55" * 32
        entry = {"title": "t", "username": "u", "password": "p", "url": "", "notes": ""}
        svc = VaultEncryptionService()

        def _work(logger: AuditLogger) -> None:
            for _ in range(35):
                blob = svc.encrypt_entry(entry, key)
                svc.decrypt_entry(blob, key)
            for _ in range(15):
                item = SecureClipboardItem(
                    masked_data=bytearray(os.urandom(64)),
                    data_type="password",
                    source_entry_id="1",
                    copied_at=datetime.now(timezone.utc),
                    mask=bytearray(os.urandom(64)),
                )
                item.secure_wipe()
            for i in range(12):
                logger.log_event("SecurityHardening", {"n": i})

        try:
            stack = ExitStack()
            for p in patches:
                stack.enter_context(p)
            reload_chain_state()
            logger = AuditLogger()

            def _secured() -> None:
                _work(logger)

            def _baseline() -> None:
                with ExitStack() as no_mem:
                    for p in _memory_protection_patches():
                        no_mem.enter_context(p)
                    _work(logger)

            retained_baseline = _retained_traced_memory(_baseline)
            retained_secured = _retained_traced_memory(_secured)
            ratio = retained_secured / max(retained_baseline, 1)
            self.assertLess(ratio, 1.05)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass


class TestPerf3AutoLockCpuIdle(unittest.TestCase):
    # PERF-3: auto-lock monitoring uses < 1% CPU when idle

    def test_perf3_auto_lock_idle_cpu_under_1_percent(self) -> None:
        fired: list[str] = []
        monitor = ActivityMonitor(
            lambda: fired.append("lock"),
            {
                "lock_timeout_minutes": 480,
                "check_interval": 1.0,
                "activity_sensitivity": "medium",
                "device_type": "desktop",
            },
        )
        wall0 = time.perf_counter()
        cpu0 = time.process_time()
        monitor.start_monitoring()
        time.sleep(3.0)
        monitor.stop_monitoring()
        cpu1 = time.process_time()
        wall1 = time.perf_counter()

        wall = max(wall1 - wall0, 1e-6)
        cpu_pct = ((cpu1 - cpu0) / wall) * 100.0
        self.assertLess(cpu_pct, 1.0)
        self.assertEqual(fired, [])


@unittest.skipUnless(_has_pyqt6(), "PERF-4: требуется PyQt6")
class TestPerf4ApplicationStartup(unittest.TestCase):
    # PERF-4: startup with security features completes in < 3 seconds

    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls._app = QApplication.instance() or QApplication([])

    def test_perf4_application_startup_under_3_seconds(self) -> None:
        from src.core.audit.audit_logger import setup_audit_subscribers
        from src.core.events import get_event_bus
        from src.gui.main_window import MainWindow

        import src.core.audit_logger  # noqa: F401
        import src.core.state_manager  # noqa: F401

        t0 = time.perf_counter()
        setup_audit_subscribers(get_event_bus())
        settings = apply_profile(PROFILE_STANDARD, SecuritySettings())
        ok, _ = validate_settings(settings)
        self.assertTrue(ok)
        window = MainWindow()
        window.hide()
        window.close()
        dt = time.perf_counter() - t0
        self.assertLess(dt, 3.0)


if __name__ == "__main__":
    unittest.main()
