from __future__ import annotations

# Sprint 8: расширенные slow-тесты для честного coverage (--cov=src)

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.core.audit.log_storage import apply_log_rotation, get_retention_policy, set_rotation_policy
from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.platform_adapter import InMemoryClipboardAdapter
from src.core.crypto.authentication import set_master_password, unlock_session
from src.core.import_export.exporter import VaultExporter
from src.core.import_export.formats.native_json_format import is_native_export_package
from src.core.import_export.importer import MODE_REPLACE, VaultImporter
from src.core.import_export.sharing_service import METHOD_PASSWORD, SharingService
from src.core.security.panic_mode import PanicMode
from src.core.security.integration import set_io_aborted
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database
from src.database import models

_MASTER = "ExtTest!Master1"
_EXPORT = "ExtExportPass1!"
_SHARE = "ExtSharePass1!"


class _VaultBase(unittest.TestCase):
    def setUp(self) -> None:
        set_io_aborted(False)
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self._tmp.name) / "ext.db", use_pool=False)
        self.vault_key = b"\x88" * 32
        self._patchers = [
            patch("src.core.crypto.key_storage.get_default_database", return_value=self.db),
            patch("src.database.io_storage.get_default_database", return_value=self.db),
            patch("src.core.vault.entry_manager.is_session_unlocked", return_value=True),
            patch("src.core.key_manager.KeyManager.get_vault_encryption_key", return_value=self.vault_key),
            patch("src.core.crypto.authentication.verify_master_password", return_value=True),
            patch("src.core.import_export.exporter.get_event_bus"),
            patch("src.core.import_export.importer.get_event_bus"),
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


class TestSprint8ExtendedExportImport(_VaultBase):
    def test_all_encrypted_formats(self) -> None:
        for i in range(3):
            self.em.create_entry(
                {
                    "title": f"E{i}",
                    "username": f"u{i}",
                    "password": f"P{i}!",
                    "url": "",
                    "notes": "",
                    "tags": "",
                },
                master_password=_MASTER,
            )
        exporter = VaultExporter(self.em)
        importer = VaultImporter(self.em)
        for fmt, pwd in (
            ("encrypted_json", _EXPORT),
            ("csv_encrypted", _EXPORT),
            ("bitwarden_json", _EXPORT),
            ("lastpass_csv_encrypted", _EXPORT),
        ):
            with self.subTest(fmt=fmt):
                pkg = exporter.export_vault(
                    None, master_password=_MASTER, export_password=pwd, fmt=fmt, skip_audit=True,
                )
                fd, path = tempfile.mkstemp(suffix=".json")
                os.close(fd)
                try:
                    Path(path).write_text(json.dumps(pkg), encoding="utf-8")
                    for row in self.em.get_all_entries():
                        self.em.delete_entry(int(row["id"]), soft_delete=False)
                    result = importer.import_from_file(
                        path, master_password=_MASTER, import_password=pwd, mode=MODE_REPLACE,
                    )
                    self.assertGreaterEqual(result.get("added", 0), 3)
                finally:
                    os.remove(path)

    def test_sharing_password_flow(self) -> None:
        self.em.create_entry(
            {"title": "S", "username": "u", "password": "p", "url": "", "notes": "", "tags": ""},
            master_password=_MASTER,
        )
        eid = int(self.em.get_all_entries()[0]["id"])
        svc = SharingService(self.em)
        pkg = svc.create_share(eid, "r@test", method=METHOD_PASSWORD, share_password=_SHARE)
        body = svc.open_share_package(pkg, share_password=_SHARE)
        self.assertEqual(body["entry"]["title"], "S")


class TestSprint8ExtendedAuditStorage(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self._tmp.name) / "audit.db", use_pool=False)
        self._patch = patch("src.core.audit.log_storage.get_default_database", return_value=self.db)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def test_rotation_policy(self) -> None:
        set_rotation_policy(5000, 180)
        policy = get_retention_policy()
        self.assertEqual(policy["max_entries"], 5000)
        self.assertEqual(policy["max_age_days"], 180)
        apply_log_rotation()


class TestSprint8ExtendedModelsMigration(unittest.TestCase):
    def test_migration_step_v9_to_v10(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "migrate.db"
            Database(path)
            conn = sqlite3.connect(path)
            conn.execute("PRAGMA user_version = 9")
            conn.commit()
            conn.close()
            models.initialize_database(path)
            conn = sqlite3.connect(path)
            try:
                (ver,) = conn.execute("PRAGMA user_version").fetchone()
                self.assertEqual(int(ver), models.CURRENT_DB_VERSION)
            finally:
                conn.close()


class TestSprint8ExtendedPanicStealth(unittest.TestCase):
    def test_stealth_mode_fake_error(self) -> None:
        panic = PanicMode(
            {"stealth_mode": True, "stealth_actions": {"show_fake_error": True}},
            register_defaults=False,
        )
        with patch("PyQt6.QtWidgets.QMessageBox") as mb:
            mb.critical = MagicMock()
            panic.activate("stealth")
        self.assertTrue(panic.activated)


class TestSprint8ExtendedClipboard(unittest.TestCase):
    def test_copy_blocked_when_configured(self) -> None:
        adapter = InMemoryClipboardAdapter()
        svc = ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 5})
        svc._copy_blocked = True  # noqa: SLF001
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            with self.assertRaises(PermissionError):
                svc.copy_to_clipboard("x", data_type="password")
