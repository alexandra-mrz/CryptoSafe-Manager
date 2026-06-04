from __future__ import annotations

# Sprint 8 / TEST-1: расширенные import/export + error paths (полный отчёт)

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core.audit.log_signer import cache_audit_signing_key
from src.core.crypto.authentication import set_master_password, unlock_session
from src.core.import_export.exporter import VaultExporter
from src.core.import_export.formats.native_json_format import is_native_export_package
from src.core.import_export.import_errors import FormatDetectionError, RECOVERY_MANUAL_FORMAT
from src.core.import_export.importer import MODE_DRY_RUN, MODE_REPLACE, VaultImporter
from src.core.security.integration import set_io_aborted
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database

_MASTER = "IoTest!Master1"
_EXPORT = "IoExportPass1!"


class _IoVaultBase(unittest.TestCase):
    def setUp(self) -> None:
        set_io_aborted(False)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(Path(self._tmp.name) / "io.db", use_pool=False)
        vault_key = b"\x99" * 32
        self._patchers = [
            patch("src.core.crypto.key_storage.get_default_database", return_value=self.db),
            patch("src.database.io_storage.get_default_database", return_value=self.db),
            patch("src.core.vault.entry_manager.is_session_unlocked", return_value=True),
            patch("src.core.key_manager.KeyManager.get_vault_encryption_key", return_value=vault_key),
            patch("src.core.crypto.authentication.verify_master_password", return_value=True),
            patch("src.core.import_export.exporter.get_event_bus"),
            patch("src.core.import_export.importer.get_event_bus"),
        ]
        for p in self._patchers:
            p.start()
        set_master_password(_MASTER)
        unlock_session(_MASTER)
        cache_audit_signing_key(_MASTER)
        self.em = EntryManager(db=self.db)

    def tearDown(self) -> None:
        for p in reversed(self._patchers):
            p.stop()

    def _seed(self, n: int = 3) -> None:
        for i in range(n):
            self.em.create_entry(
                {
                    "title": f"E{i}",
                    "username": f"u{i}",
                    "password": f"P{i}!Aa",
                    "url": f"https://{i}.example",
                    "notes": "n",
                    "tags": "",
                },
                master_password=_MASTER,
            )

    def _clear(self) -> None:
        for row in self.em.get_all_entries():
            self.em.delete_entry(int(row["id"]), soft_delete=False)


class TestSprint8ImportExportIo(_IoVaultBase):
    def test_all_export_formats_roundtrip(self) -> None:
        self._seed(3)
        expected = sorted(
            (r.get("title", ""), r.get("username", ""), r.get("password", "")) for r in self.em.get_all_entries()
        )
        exporter = VaultExporter(self.em)
        importer = VaultImporter(self.em)
        for fmt, pwd in (
            ("encrypted_json", _EXPORT),
            ("csv_encrypted", _EXPORT),
            ("bitwarden_json", _EXPORT),
            ("csv", ""),
        ):
            with self.subTest(fmt=fmt):
                kwargs = {"master_password": _MASTER, "export_password": pwd, "fmt": fmt}
                if fmt == "csv":
                    kwargs["encrypt_csv"] = False
                pkg = exporter.export_vault(None, **kwargs)
                if fmt == "encrypted_json":
                    assert is_native_export_package(pkg)
                fd, path = tempfile.mkstemp(suffix=f"_{fmt}.json")
                os.close(fd)
                try:
                    Path(path).write_text(json.dumps(pkg), encoding="utf-8")
                    self._clear()
                    result = importer.import_from_file(
                        path, master_password=_MASTER, import_password=pwd, mode=MODE_REPLACE,
                    )
                    assert result.get("added", 0) >= 3
                    got = sorted(
                        (r.get("title", ""), r.get("username", ""), r.get("password", ""))
                        for r in self.em.get_all_entries()
                    )
                    assert got == expected
                finally:
                    os.remove(path)

    def test_import_error_paths(self) -> None:
        bad = Path(self._tmp.name) / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        report = VaultImporter(self.em).import_from_file_safe(bad, master_password=_MASTER, mode=MODE_DRY_RUN)
        assert report.get("error_code") in ("corrupted_file", "import_failed")

        with self.assertRaises(FormatDetectionError):
            VaultImporter(self.em).resolve_import_format({})

        unknown = Path(self._tmp.name) / "unknown.json"
        unknown.write_text('{"foo": 1}', encoding="utf-8")
        report2 = VaultImporter(self.em).import_from_file_safe(
            unknown, master_password=_MASTER, mode=MODE_DRY_RUN,
        )
        assert report2.get("error_code") == "format_detection_failed"
        assert RECOVERY_MANUAL_FORMAT in report2.get("recovery_options", [])

        self._seed(1)
        pkg = VaultExporter(self.em).export_vault(
            None, master_password=_MASTER, export_password=_EXPORT, skip_audit=True,
        )
        enc_path = Path(self._tmp.name) / "enc.json"
        enc_path.write_text(json.dumps(pkg), encoding="utf-8")
        report3 = VaultImporter(self.em).import_from_file_safe(
            enc_path, master_password=_MASTER, import_password="WrongPass1!", mode=MODE_DRY_RUN,
        )
        assert report3.get("error_code") == "encryption_failed"

    def test_bitwarden_export_decrypt(self) -> None:
        self._seed(2)
        pkg = VaultExporter(self.em).export_vault(
            None,
            master_password=_MASTER,
            export_password=_EXPORT,
            fmt="bitwarden_json",
        )
        body = VaultImporter(self.em).decrypt_package(pkg, import_password=_EXPORT)
        assert len(body.get("items", [])) >= 2
