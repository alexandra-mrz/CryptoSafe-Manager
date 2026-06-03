from __future__ import annotations

# Sprint 7 / §12: SEC-1, SEC-2, SEC-4 (SEC-3 — без отдельного теста в ТЗ)

import unittest

from src.core.import_export.importer import VaultImporter
from src.core.security.panic_mode import PanicMode
from src.core.security.security_config import (
    SecuritySettings,
    non_default_warnings,
    validate_settings,
)


class TestSec1DefenseInDepth(unittest.TestCase):
    def test_sec1_multiple_protection_layers_active(self) -> None:
        settings = SecuritySettings()
        ok, errors = validate_settings(settings)
        self.assertTrue(ok)
        self.assertEqual(errors, [])

        importer = VaultImporter()
        with self.assertRaises(ValueError):
            importer._verify_integrity(b"data", {"integrity": {"hash": "00"}})


class TestSec2FailSecureDefaults(unittest.TestCase):
    def test_sec2_defaults_are_most_secure(self) -> None:
        settings = SecuritySettings()
        ok, errors = validate_settings(settings)
        self.assertTrue(ok)
        self.assertEqual(errors, [])
        self.assertGreaterEqual(settings.auto_lock_minutes, 1)
        self.assertGreater(settings.clipboard_timeout_seconds, 0)
        self.assertGreaterEqual(settings.memory_wipe_passes, 1)
        self.assertEqual(non_default_warnings(settings), [])


class TestSec4GracefulDegradation(unittest.TestCase):
    def test_sec4_panic_handler_failure_does_not_block_others(self) -> None:
        calls: list[str] = []

        def bad() -> None:
            raise RuntimeError("handler failure")

        def good() -> None:
            calls.append("ok")

        panic = PanicMode({}, register_defaults=False)
        panic.register_handler(bad)
        panic.register_handler(good)
        panic.activate("test")
        self.assertEqual(calls, ["ok"])
        panic.reset()

    def test_sec4_integrity_failure_fails_secure(self) -> None:
        importer = VaultImporter()
        with self.assertRaises(ValueError):
            importer._verify_integrity(b"data", {"integrity": {"hash": "deadbeef"}})


if __name__ == "__main__":
    unittest.main()
