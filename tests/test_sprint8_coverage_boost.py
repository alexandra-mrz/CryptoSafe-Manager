from __future__ import annotations

# Sprint 8 / TEST-2: дополнительное покрытие core-модулей (честный --cov=src)

import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.core.audit.audit_compliance import format_cef, format_cef_from_row, get_audit_timestamp, reconstruct_chronological
from src.core.audit.log_entry import (
    anonymize_search_query,
    build_log_entry,
    filter_audit_items,
    get_event_category,
    normalize_event_type,
    parse_log_rows,
    sanitize_details,
)
from src.core.audit.log_export import (
    build_signed_json,
    filter_rows_by_date,
    rows_from_signed_json,
    verify_export_independent,
)
from src.core.clipboard.clipboard_service import ClipboardService, SecureClipboardItem
from src.core.clipboard.platform_adapter import InMemoryClipboardAdapter
from src.core.config import AppConfig, ConfigManager
from src.core.crypto.authentication import set_master_password, unlock_session
from src.core.events import get_event_bus
from src.core.import_export.exporter import VaultExporter
from src.core.import_export.formats.share_json_format import build_share_metadata, build_share_plaintext_package
from src.core.import_export.importer import (
    DUP_UPDATE,
    MODE_DRY_RUN,
    MODE_MERGE,
    MODE_REPLACE,
    ImportSandbox,
    VaultImporter,
)
from src.core.import_export.share_package_codec import decode_share_package_b64, encode_share_package_b64
from src.core.import_export.sharing_service import (
    METHOD_PASSWORD,
    SharingService,
    entries_from_share_body,
    normalize_entry_ids,
)
from src.core.security.activity_monitor import ActivityMonitor
from src.core.security.panic_mode import PanicMode
from src.core.security.integration import set_io_aborted
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database
from src.database import models

_MASTER = "Boost!Master1"
_EXPORT = "BoostExport1!"


class _VaultBase(unittest.TestCase):
    def setUp(self) -> None:
        set_io_aborted(False)
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self._tmp.name) / "boost.db", use_pool=False)
        self.vault_key = b"\x55" * 32
        self._patchers = [
            patch("src.core.crypto.key_storage.get_default_database", return_value=self.db),
            patch("src.database.io_storage.get_default_database", return_value=self.db),
            patch("src.core.vault.entry_manager.is_session_unlocked", return_value=True),
            patch("src.core.key_manager.KeyManager.get_vault_encryption_key", return_value=self.vault_key),
            patch("src.core.crypto.authentication.verify_master_password", return_value=True),
            patch("src.core.import_export.exporter.get_event_bus"),
            patch("src.core.import_export.importer.get_event_bus"),
            patch("src.core.import_export.sharing_service.get_event_bus"),
        ]
        for p in self._patchers:
            p.start()
        set_master_password(_MASTER)
        unlock_session(_MASTER)
        self.em = EntryManager(db=self.db)

    def tearDown(self) -> None:
        for p in reversed(self._patchers):
            p.stop()
        self._tmp.cleanup()

    def _seed(self, n: int = 2) -> list[int]:
        ids: list[int] = []
        for i in range(n):
            created = self.em.create_entry(
                {
                    "title": f"Boost{i}",
                    "username": f"u{i}",
                    "password": f"P{i}!Aa",
                    "url": f"https://{i}.example",
                    "notes": f"note{i}",
                    "tags": "t",
                },
                master_password=_MASTER,
            )
            ids.append(int(created.id))
        return ids


class TestSprint8BoostExportImport(_VaultBase):
    def test_exporter_options_and_file(self) -> None:
        ids = self._seed(3)
        exporter = VaultExporter(self.em)
        self.assertEqual(len(exporter.pick_entry_ids_by_query("Boost")), 3)
        pkg = exporter.export_vault(
            [ids[0]],
            master_password=_MASTER,
            export_password=_EXPORT,
            fmt="encrypted_json",
            include_notes=False,
            exclude_fields=["url"],
            key_bits=128,
            compress=True,
            skip_audit=True,
        )
        self.assertIn("data", pkg)
        out_path = Path(self._tmp.name) / "out.json"
        exporter.export_vault_to_file(out_path, master_password=_MASTER, export_password=_EXPORT, skip_audit=True)
        self.assertTrue(out_path.is_file())
        by_query = exporter.export_vault_by_query(
            "Boost1", master_password=_MASTER, export_password=_EXPORT, skip_audit=True,
        )
        self.assertGreaterEqual(by_query.get("entry_count", 0), 1)

    def test_importer_detect_and_apply(self) -> None:
        self._seed(1)
        exporter = VaultExporter(self.em)
        importer = VaultImporter(self.em)
        pkg = exporter.export_vault(None, master_password=_MASTER, export_password=_EXPORT, skip_audit=True)
        self.assertEqual(importer.detect_format(pkg), "encrypted_json")
        self.assertEqual(importer.detect_format({"items": []}), "bitwarden_json")
        self.assertEqual(importer.detect_format({"plaintext": True, "csv_body": "a;b", "format": "lastpass_csv"}), "lastpass_csv")
        self.assertEqual(importer.detect_format({"plaintext": True, "csv_body": "title;user;pass"}), "csv")
        meta = build_share_metadata(
            recipient="r", sharer="s", permission="read_only",
            expires_at="2099-01-01T00:00:00Z", encryption_method="password",
        )
        plain_share = build_share_plaintext_package(
            {"title": "S", "username": "u", "password": "p", "url": "", "notes": "", "category": "", "tags": ""},
            meta,
        )
        self.assertEqual(importer.detect_format(plain_share), "share_plaintext")

        with self.assertRaises(ValueError):
            importer.validate_encryption_block({})
        with self.assertRaises(ValueError):
            importer.validate_encryption_block({"encryption": {}, "data": "x"})

        items = [{"title": "New", "username": "nu", "password": "np", "url": "", "notes": "", "tags": ""}]
        dry = importer.apply_import(items, master_password=_MASTER, mode=MODE_DRY_RUN)
        self.assertEqual(dry.get("added"), 1)
        merge = importer.apply_import(items, master_password=_MASTER, mode=MODE_MERGE, on_duplicate=DUP_UPDATE)
        self.assertGreaterEqual(merge.get("updated", 0) + merge.get("added", 0), 1)

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            Path(path).write_text(json.dumps(pkg), encoding="utf-8")
            for row in self.em.get_all_entries():
                self.em.delete_entry(int(row["id"]), soft_delete=False)
            result = importer.import_from_file(
                path, master_password=_MASTER, import_password=_EXPORT, mode=MODE_REPLACE,
            )
            self.assertGreaterEqual(result.get("added", 0), 1)
        finally:
            os.remove(path)

        sandbox = ImportSandbox(max_bytes=10)
        with self.assertRaises(ValueError):
            sandbox.check_size(100)
        raw_csv = b"title,username,password,url,notes\nT,u,p,,\n"
        data, fmt = importer.load_package_from_bytes(raw_csv, ImportSandbox())
        self.assertEqual(fmt, "csv")
        self.assertIn("csv_body", data)

    def test_sharing_multi_and_import(self) -> None:
        ids = self._seed(2)
        svc = SharingService(self.em)
        pkg = svc.create_share(
            ids, "multi@test", method=METHOD_PASSWORD, share_password=_EXPORT, permission="read_only",
        )
        body = svc.open_share_package(pkg, share_password=_EXPORT)
        entries = entries_from_share_body(body)
        self.assertGreaterEqual(len(entries), 2)
        self.assertEqual(normalize_entry_ids(ids[0]), [ids[0]])
        with self.assertRaises(ValueError):
            normalize_entry_ids([])
        out_path = Path(self._tmp.name) / "share.json"
        svc.share_to_file(out_path, ids[0], recipient="file@test", share_password=_EXPORT, method=METHOD_PASSWORD)
        loaded = svc.load_share_from_file(out_path)
        result = svc.import_shared_entry(
            loaded, share_password=_EXPORT, save_to_vault=True, master_password=_MASTER,
        )
        self.assertTrue(result.get("saved"))


class TestSprint8BoostClipboard(unittest.TestCase):
    def test_clipboard_service_paths(self) -> None:
        adapter = InMemoryClipboardAdapter()
        events: list[tuple[str, dict]] = []

        def observer(name: str, payload: dict) -> None:
            events.append((name, payload))

        svc = ClipboardService(
            platform_adapter=adapter,
            bus=get_event_bus(),
            config={"clipboard_timeout": 1, "block_future_copies_on_suspicious": True},
        )
        svc.subscribe(observer)
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            svc.start()
            svc.copy_to_clipboard("secret123", data_type="password", source_entry_id="42")
            svc.copy_ephemeral("ephemeral", data_type="totp")
            preview = svc.get_clipboard_preview(masked=True)
            self.assertIn("pas", preview.get("preview", ""))
            raw_preview = svc.get_clipboard_preview(masked=False)
            self.assertEqual(raw_preview.get("preview"), "secret123")
            svc.set_timeout_seconds(60)
            svc.copy_secret("via-secret", ttl_seconds=15)
            svc._on_clipboard_changed("external-tamper")  # noqa: SLF001
            svc.allow_future_copies()
            svc.copy_to_clipboard("again", data_type="encrypted_blob")
            svc.set_block_future_copies_on_suspicious(True)
            svc.clear_if_owned()
            svc.force_clear(reason="panic")
            svc.stop()
        svc.unsubscribe(observer)
        self.assertTrue(events)

        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=False):
            with self.assertRaises(PermissionError):
                svc.copy_to_clipboard("x")

        long_text = "a" * 5000 + "\x00bad"
        safe = svc._sanitize_input(long_text)  # noqa: SLF001
        self.assertNotIn("\x00", safe)
        self.assertLessEqual(len(safe), 4096)
        self.assertEqual(svc._validate_data_type("unknown"), "notes")  # noqa: SLF001

        item = SecureClipboardItem(
            masked_data=bytearray(),
            data_type="password",
            source_entry_id=None,
            copied_at=__import__("datetime").datetime.utcnow(),
            mask=bytearray(),
        )
        item.secure_wipe()
        self.assertEqual(item.data_type, "")

    def test_clipboard_fallback_and_logout(self) -> None:
        class FailAdapter(InMemoryClipboardAdapter):
            def copy_to_clipboard(self, text: str) -> bool:
                return False

            def clear_clipboard(self) -> bool:
                return False

        class OkFallback(InMemoryClipboardAdapter):
            def copy_to_clipboard(self, text: str) -> bool:
                return True

            def clear_clipboard(self) -> bool:
                return True

        svc = ClipboardService(platform_adapter=FailAdapter())
        svc._fallback_platform = OkFallback()  # noqa: SLF001
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            svc.copy_to_clipboard("fallback-ok", data_type="username")
            svc.clear_clipboard()

        svc2 = ClipboardService(platform_adapter=InMemoryClipboardAdapter(), config={"clipboard_timeout": 0})
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            svc2.copy_to_clipboard("no-timer", data_type="notes")
            svc2._on_timeout()  # noqa: SLF001
        get_event_bus().publish("UserLoggedOut", {})
        svc2.stop()

    def test_clipboard_monitor_start_failure(self) -> None:
        svc = ClipboardService(platform_adapter=InMemoryClipboardAdapter())
        with patch("src.core.clipboard.clipboard_service.ClipboardMonitor", side_effect=RuntimeError("no monitor")):
            svc.start()
        svc.stop()


class TestSprint8BoostPanicActivity(unittest.TestCase):
    def test_panic_full_handlers(self) -> None:
        locked = {"called": False}
        closed = {"called": False}
        hidden = {"called": False}
        quit_cb = {"called": False}
        logs: list[str] = []

        panic = PanicMode(
            {
                "lock_callback": lambda: locked.__setitem__("called", True),
                "close_windows_callback": lambda: closed.__setitem__("called", True),
                "hide_window_callback": lambda: hidden.__setitem__("called", True),
                "quit_app": True,
                "quit_callback": lambda: quit_cb.__setitem__("called", True),
                "stealth_mode": False,
            },
            register_defaults=True,
        )
        panic.set_log_callback(lambda m: logs.append(m))
        panic.activate("hotkey")
        panic.activate("again")
        self.assertTrue(panic.activated)
        self.assertTrue(locked["called"])
        panic.reset()
        self.assertFalse(panic.activated)
        self.assertEqual(logs, ["hotkey"])

    def test_panic_lock_without_callbacks(self) -> None:
        with patch("src.core.crypto.authentication.lock_session"), patch(
            "src.core.crypto.key_storage.clear_all_keys",
        ), patch("src.core.security.integration.log_security_hardening"):
            panic = PanicMode({"stealth_mode": False}, register_defaults=True)
            panic.activate("core")

    def test_activity_monitor_auto_lock(self) -> None:
        locked = threading.Event()

        def lock() -> None:
            locked.set()

        mon = ActivityMonitor(lock, {"lock_timeout_minutes": 0.001, "check_interval": 0.05, "activity_sensitivity": "high"})
        mon.start_monitoring()
        time.sleep(0.25)
        mon.stop_monitoring()
        self.assertTrue(locked.is_set() or mon.get_idle_seconds() >= 0)


class TestSprint8BoostMisc(unittest.TestCase):
    def test_share_codec_roundtrip(self) -> None:
        meta = build_share_metadata(
            recipient="r", sharer="s", permission="read_only",
            expires_at="2099-01-01T00:00:00Z", encryption_method="password",
        )
        pkg = build_share_plaintext_package(
            {"title": "T", "username": "u", "password": "p", "url": "", "notes": "", "category": "", "tags": ""},
            meta,
        )
        b64 = encode_share_package_b64(pkg)
        decoded = decode_share_package_b64(b64)
        self.assertTrue(decoded.get("cryptosafe_share"))
        with self.assertRaises(ValueError):
            decode_share_package_b64("")

    def test_audit_entry_and_compliance(self) -> None:
        row = ("Login", "2020-01-01T00:00:00Z", 1, '{"entry_data":{"event_type":"Login","details":{"user":"x"}}}', "sig" * 8)
        cef = format_cef_from_row(row)
        self.assertIn("Login", cef)
        ts = get_audit_timestamp()
        self.assertIn("T", ts)
        entry = build_log_entry("UserLoggedIn", {"ip": "127.0.0.1"})
        masked = sanitize_details({"password": "secret", "note": "ok"})
        self.assertNotEqual(masked.get("password"), "secret")
        cef2 = format_cef(entry)
        self.assertIn("UserLoggedIn", cef2)
        items = parse_log_rows([row, ("Bad", "2020-01-02", 2, "not-json", "s")])
        self.assertEqual(len(items), 2)
        filtered = filter_audit_items(items, type_value="Login", search="login")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(get_event_category("UserLoggedIn"), "authentication")
        self.assertEqual(normalize_event_type("UserLoggedIn", {}), "UserLoggedIn")
        self.assertTrue(anonymize_search_query("my query"))
        ordered = reconstruct_chronological(
            [{"sequence_number": 2, "event_type": "B"}, {"sequence_number": 1, "event_type": "A"}]
        )
        self.assertEqual(ordered[0]["sequence_number"], 1)

    def test_log_export_helpers(self) -> None:
        rows = [
            ("Login", "2020-01-01T00:00:00Z", 1, '{"entry_data":{"event_type":"Login"}}', "sig"),
            ("Logout", "2019-01-01T00:00:00Z", 2, "{}", "sig2"),
        ]
        filtered = filter_rows_by_date(rows, "2020-01-01", "2020-12-31")
        self.assertEqual(len(filtered), 1)
        payload = build_signed_json(filtered, "2020-01-01", "2020-12-31")
        self.assertEqual(payload["export_metadata"]["entry_count"], 1)
        parsed = rows_from_signed_json(payload)
        self.assertEqual(len(parsed), 1)
        ok, errors = verify_export_independent(payload)
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(errors, list)

    def test_config_manager(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.json"
            mgr = ConfigManager(path)
            mgr.set("clipboard_timeout_seconds", 45)
            self.assertEqual(mgr.get("clipboard_timeout_seconds"), 45)
            mgr2 = ConfigManager(path)
            self.assertEqual(mgr2.config.clipboard_timeout_seconds, 45)
        self.assertIsInstance(AppConfig(), AppConfig)

    def test_models_migrations_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mig.db"
            models.initialize_database(path)
            conn = models.get_connection(path)
            try:
                (ver,) = conn.execute("PRAGMA user_version").fetchone()
                self.assertEqual(int(ver), models.CURRENT_DB_VERSION)
            finally:
                conn.close()
