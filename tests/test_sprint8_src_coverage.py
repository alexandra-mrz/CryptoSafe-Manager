from __future__ import annotations

# Sprint 8 / TEST-2: дополнительное покрытие src (честный --cov=src, без omit core-модулей)

import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.core.audit.audit_compliance import format_cef_from_row
from src.core.audit.log_formatters import export_csv, export_json, export_pdf
from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.clipboard.platform_adapter import (
    InMemoryClipboardAdapter,
    create_platform_adapter,
)
from src.core.import_export.io_integration import (
    copy_share_link_to_clipboard,
    extract_share_link,
    format_qr_scan_error,
    scan_qr_from_png_bytes,
)
from src.core.import_export.key_exchange import ALGO_ECC_P256, KeyExchange
from src.core.import_export.qr_code_service import PAYLOAD_PUBKEY, QRCodeService
from src.core.import_export.share_crypto import decrypt_password_package, encrypt_password_package
from src.core.security.integration import (
    check_io_aborted,
    io_aborted,
    log_security_hardening,
    secure_contains,
    set_io_aborted,
    wipe_sensitive_buffer,
)
from src.core.security.panic_mode import PanicMode
from src.core.security.platform_security import (
    delete_secret_from_keychain,
    describe_platform_features,
    keychain_available,
    linux_apparmor_enabled,
    linux_mlock,
    linux_munlock,
    linux_selinux_enabled,
    linux_systemd_available,
    load_secret_from_keychain,
    lock_memory,
    macos_gatekeeper_notarization_status,
    store_secret_in_keychain,
    unlock_memory,
    windows_hello_available,
)
from src.core.state_manager import StateManager
from src.database.db import Database
from src.database import io_storage, models


class TestSprint8DatabaseModels(unittest.TestCase):
    def test_initialize_database_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fresh.db"
            models.initialize_database(path)
            conn = models.get_connection(path)
            try:
                cur = conn.cursor()
                cur.execute("PRAGMA user_version")
                (ver,) = cur.fetchone()
                self.assertEqual(int(ver), models.CURRENT_DB_VERSION)
            finally:
                conn.close()

    def test_initialize_database_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "idem.db"
            models.initialize_database(path)
            models.initialize_database(path)


class TestSprint8IoStorage(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self._tmp.name) / "io.db", use_pool=False)
        self._patch = patch("src.database.io_storage.get_default_database", return_value=self.db)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def test_io_storage_crud(self) -> None:
        sid = io_storage.insert_shared_entry(
            original_entry_id=1,
            encryption_method="password",
            recipient_info="bob@test",
            permissions="read_only",
            expires_at="2099-01-01T00:00:00Z",
        )
        self.assertTrue(sid)
        rows = io_storage.list_shared_entries()
        self.assertGreaterEqual(len(rows), 1)

        io_storage.upsert_contact(
            contact_id="alice",
            contact_name="Alice",
            public_key_pem="pem",
            public_key_hex="ab",
            key_fingerprint="fp1",
            algorithm=ALGO_ECC_P256,
        )
        row = io_storage.get_contact_row("alice")
        self.assertIsNotNone(row)
        io_storage.touch_contact_last_used("alice")
        io_storage.set_contact_fingerprint_verified("alice", "fp1")
        listed = io_storage.list_contact_rows()
        self.assertTrue(any(r.get("contact_id") == "alice" for r in listed))

        hid = io_storage.insert_io_history(
            operation_type=io_storage.OP_EXPORT,
            file_format="json",
            encryption_used="aes",
            entry_count=3,
            file_size=100,
            checksum="abc",
        )
        self.assertGreater(hid, 0)
        hist = io_storage.list_io_history()
        self.assertGreaterEqual(len(hist), 1)

        pkg = {"format": "share", "data": "x"}
        io_storage.save_share_inbox("tok123", pkg, expires_at="2099-01-01T00:00:00Z")
        loaded = io_storage.load_share_inbox_by_token("tok123")
        self.assertIsNotNone(loaded)

        io_storage.revoke_contact_row("alice")
        with self.assertRaises(ValueError):
            io_storage.revoke_contact_row("missing")


class TestSprint8SecurityIntegration(unittest.TestCase):
    def test_io_abort_and_secure_contains(self) -> None:
        set_io_aborted(False)
        self.assertFalse(io_aborted())
        set_io_aborted(True)
        self.assertTrue(io_aborted())
        with self.assertRaises(InterruptedError):
            check_io_aborted()
        set_io_aborted(False)

        self.assertTrue(secure_contains("git", "GitHub login"))
        self.assertFalse(secure_contains("missing", "GitHub"))
        buf = bytearray(b"abc")
        wipe_sensitive_buffer(buf)

        log_security_hardening("test", "action", {"k": "v"})


class TestSprint8PanicDefaults(unittest.TestCase):
    def test_panic_default_handlers(self) -> None:
        clip = MagicMock()
        clip.force_clear = MagicMock()
        clip.current_content = None
        state = MagicMock()
        state.state.locked = False
        panic = PanicMode(
            {
                "clipboard_service": clip,
                "lock_callback": lambda: None,
                "close_windows_callback": lambda: None,
                "hide_window_callback": lambda: None,
                "state_manager": state,
                "stealth_mode": False,
            },
            register_defaults=True,
        )
        panic.activate("test")
        self.assertTrue(panic.activated)
        clip.force_clear.assert_called()
        panic.reset()


class TestSprint8PlatformSecurityExtra(unittest.TestCase):
    def test_platform_helpers(self) -> None:
        self.assertIsInstance(describe_platform_features(), list)
        self.assertIsInstance(keychain_available(), bool)
        self.assertIsInstance(windows_hello_available(), bool)
        self.assertIsInstance(linux_selinux_enabled(), bool)
        self.assertIsInstance(linux_apparmor_enabled(), bool)
        self.assertIsInstance(linux_systemd_available(), bool)
        self.assertIsInstance(macos_gatekeeper_notarization_status(), str)
        buf = bytearray(b"mem-test")
        lock_memory(buf)
        unlock_memory(buf)
        linux_mlock(buf)
        linux_munlock(buf)
        store_secret_in_keychain("test-id", "secret")
        self.assertIsInstance(load_secret_from_keychain("test-id"), (str, type(None)))
        delete_secret_from_keychain("test-id")


class TestSprint8StateManager(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self._tmp.name) / "state.db", use_pool=False)
        self._patches = [
            patch("src.core.state_manager.get_default_database", return_value=self.db),
            patch("src.core.crypto.key_storage.get_default_database", return_value=self.db),
        ]
        for p in self._patches:
            p.start()
        self.mgr = StateManager(env="test_s8")

    def tearDown(self) -> None:
        self.mgr.stop()
        for p in reversed(self._patches):
            p.stop()
        self._tmp.cleanup()

    def test_settings_and_events(self) -> None:
        self.mgr.set_setting("custom_key", "value")
        self.assertEqual(self.mgr.get_setting("custom_key"), "value")
        self.mgr._on_user_logged_in("UserLoggedIn", {})
        self.assertFalse(self.mgr.state.locked)
        self.mgr._on_clipboard_copied("ClipboardCopied", {"timeout": 30})
        self.assertEqual(self.mgr.state.clipboard_seconds_left, 30)
        self.mgr._on_user_activity("UserActivity", {})
        self.mgr._on_clipboard_cleared("ClipboardCleared", {})


class TestSprint8QrAndIoIntegration(unittest.TestCase):
    def test_qr_payload_and_chunks(self) -> None:
        qr = QRCodeService(valid_minutes=30)
        inner = {"type": "cryptosafe_pubkey", "contact_id": "c1", "algorithm": ALGO_ECC_P256}
        wrapped = qr.build_wrapped_payload(PAYLOAD_PUBKEY, inner)
        body = qr.validate_wrapped_payload(wrapped)
        self.assertEqual(body.get("contact_id"), "c1")
        raw = qr.payload_json_bytes(wrapped)
        chunks = qr.generate_qr_code(raw, chunk_size=200)
        self.assertGreater(len(chunks), 0)
        assembled = qr.decode_qr_chunks(chunks)
        self.assertIsNotNone(assembled)
        parsed = qr.parse_scanned_text(json.dumps(wrapped, sort_keys=True))
        self.assertEqual(parsed.get("contact_id"), "c1")

    def test_io_integration_clipboard_and_qr_png(self) -> None:
        link_pkg = {"share_link": {"url_hint": "cryptosafe://share/abc"}}
        self.assertTrue(extract_share_link(link_pkg).startswith("cryptosafe://"))
        adapter = InMemoryClipboardAdapter()
        from src.core.clipboard.clipboard_service import ClipboardService

        svc = ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 5})
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            url = copy_share_link_to_clipboard(svc, link_pkg)
            self.assertIn("cryptosafe://", url)
        msg = format_qr_scan_error(ImportError("pyzbar missing"))
        self.assertIn("pip install", msg.lower())
        qr = QRCodeService()
        wrapped = qr.build_wrapped_payload(PAYLOAD_PUBKEY, {"contact_id": "png"})
        try:
            images = qr.generate_qr_images(wrapped, allow_chunks=True)
            if images:
                scan_qr_from_png_bytes(qr, images[0])
        except RuntimeError:
            pass


class TestSprint8ShareCrypto(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self._tmp.name) / "share.db", use_pool=False)
        self._patch = patch("src.database.io_storage.get_default_database", return_value=self.db)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def test_password_package_roundtrip(self) -> None:
        body = {"entry": {"title": "T", "password": "p"}, "metadata": {"recipient": "r"}}
        enc = encrypt_password_package(body, "SharePass1234!")
        plain = decrypt_password_package(enc, "SharePass1234!")
        out = json.loads(plain.decode("utf-8"))
        self.assertEqual(out["entry"]["title"], "T")
        kx = KeyExchange()
        pair = kx.generate_key_pair("bob", ALGO_ECC_P256)
        kx.save_contact_public_key(pair)
        loaded = kx.contacts.get_contact("bob")
        self.assertIsNotNone(loaded)


class TestSprint8AuditFormatters(unittest.TestCase):
    def test_export_formats(self) -> None:
        rows = [("Login", "2020-01-01T00:00:00", 1, "details", "sig" * 8)]
        cef = format_cef_from_row(rows[0])
        self.assertIn("Login", cef)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            export_json(rows, base / "a.json")
            export_csv(rows, base / "a.csv")
            export_pdf(rows, base / "a.pdf")
            self.assertTrue((base / "a.json").is_file())
            self.assertTrue((base / "a.csv").is_file())
            self.assertTrue((base / "a.pdf").is_file())


class TestSprint8ClipboardMonitor(unittest.TestCase):
    def test_monitor_detects_change(self) -> None:
        adapter = InMemoryClipboardAdapter()
        seen: list[str] = []
        mon = ClipboardMonitor(adapter, seen.append, interval_seconds=0.05)
        mon.start()
        adapter.copy_to_clipboard("changed")
        time.sleep(0.2)
        mon.stop()
        self.assertTrue(any("changed" in s for s in seen))


class TestSprint8PlatformAdapters(unittest.TestCase):
    def test_create_adapters(self) -> None:
        for system, expected in (
            ("Windows", "WindowsClipboardAdapter"),
            ("Darwin", "MacOSClipboardAdapter"),
            ("Linux", "LinuxClipboardAdapter"),
        ):
            with patch("src.core.clipboard.platform_adapter.platform.system", return_value=system):
                self.assertEqual(type(create_platform_adapter()).__name__, expected)
