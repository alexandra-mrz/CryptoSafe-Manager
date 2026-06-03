from __future__ import annotations

# Sprint 7 / §10: INT-1 … INT-4

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from src.core.clipboard.clipboard_service import ClipboardService, SecureClipboardItem
from src.core.security.integration import (
    check_io_aborted,
    io_aborted,
    log_security_hardening,
    secure_contains,
    set_io_aborted,
)
from src.core.vault.encryption_service import VaultEncryptionService


class TestInt1Vault(unittest.TestCase):
    def test_int1_encrypt_decrypt_and_secure_search(self) -> None:
        key = b"\x01" * 32
        svc = VaultEncryptionService()
        entry = {"title": "t", "password": "p"}
        token = svc.encrypt_entry(entry, key)
        out = svc.decrypt_entry(token, key)
        self.assertEqual(out["data"]["title"], "t")
        self.assertTrue(secure_contains("abc", "xxabcyy"))
        self.assertFalse(secure_contains("abc", "ab"))


class TestInt2Clipboard(unittest.TestCase):
    def test_int2_secure_wipe_and_panic_clear(self) -> None:
        item = SecureClipboardItem(
            masked_data=bytearray(b"secret"),
            data_type="password",
            source_entry_id="1",
            copied_at=datetime.now(timezone.utc),
            mask=bytearray(b"mask"),
        )
        with patch("src.core.clipboard.clipboard_service.secure_wipe") as wipe:
            item.secure_wipe()
            self.assertEqual(wipe.call_count, 2)

        svc = ClipboardService()
        with patch.object(svc, "_clear_clipboard"):
            with patch("src.core.clipboard.clipboard_service.log_security_hardening") as log_h:
                svc.force_clear(reason="panic")
                log_h.assert_called_once()


class TestInt3Audit(unittest.TestCase):
    def test_int3_security_hardening_event(self) -> None:
        received: list[tuple[str, dict]] = []

        def _handler(event_name: str, payload: dict) -> None:
            received.append((event_name, payload))

        from src.core.events import get_event_bus

        get_event_bus().subscribe("SecurityHardening", _handler)
        log_security_hardening("vault", "wipe", {"detail": "test"})
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0][0], "SecurityHardening")
        self.assertEqual(received[0][1]["component"], "vault")
        self.assertEqual(received[0][1]["action"], "wipe")


class TestInt4ImportExport(unittest.TestCase):
    def test_int4_io_abort_on_panic(self) -> None:
        set_io_aborted(False)
        self.assertFalse(io_aborted())
        set_io_aborted(True)
        self.assertTrue(io_aborted())
        with self.assertRaises(InterruptedError):
            check_io_aborted()
        set_io_aborted(False)


if __name__ == "__main__":
    unittest.main()
