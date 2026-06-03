from __future__ import annotations

# Sprint 8 / TEST-2: дополнительное покрытие core-модулей (быстрые тесты)

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from src.core.clipboard.platform_adapter import InMemoryClipboardAdapter, create_platform_adapter
from src.core.crypto.authentication import set_master_password, unlock_session
from src.core.import_export.formats.csv_format import entries_to_csv_text, parse_csv_text
from src.core.import_export.formats.native_json_format import build_native_export_package, is_native_export_package
from src.core.import_export.importer import MODE_DRY_RUN, VaultImporter
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database

_MASTER = "CovTest!Master1"


@pytest.fixture
def vault_env():
    tmp = tempfile.TemporaryDirectory()
    db = Database(Path(tmp.name) / "cov.db", use_pool=False)
    vault_key = b"\x77" * 32
    patchers = [
        patch("src.core.crypto.key_storage.get_default_database", return_value=db),
        patch("src.database.io_storage.get_default_database", return_value=db),
        patch("src.core.vault.entry_manager.is_session_unlocked", return_value=True),
        patch("src.core.key_manager.KeyManager.get_vault_encryption_key", return_value=vault_key),
        patch("src.core.crypto.authentication.verify_master_password", return_value=True),
        patch("src.core.import_export.exporter.get_event_bus"),
        patch("src.core.import_export.importer.get_event_bus"),
    ]
    for p in patchers:
        p.start()
    set_master_password(_MASTER)
    unlock_session(_MASTER)
    em = EntryManager(db=db)
    yield em, tmp
    for p in reversed(patchers):
        p.stop()
    tmp.cleanup()


class TestSprint8CoverageHelpers:
    def test_platform_adapter_factory(self) -> None:
        with patch("src.core.clipboard.platform_adapter.platform.system", return_value="Windows"):
            assert create_platform_adapter().__class__.__name__ == "WindowsClipboardAdapter"
        adapter = InMemoryClipboardAdapter()
        adapter.copy_to_clipboard("x")
        assert adapter.get_clipboard_content() == "x"

    def test_csv_format_roundtrip(self) -> None:
        rows = [{"title": "A", "username": "u", "password": "p", "url": "", "notes": "", "tags": ""}]
        text = entries_to_csv_text(rows)
        parsed = parse_csv_text(text)
        assert parsed[0]["title"] == "A"

    def test_native_export_package(self) -> None:
        enc = {
            "encryption": {"algorithm": "AES-256-GCM", "salt": "aa", "nonce": "bb"},
            "data": "ccc",
            "integrity": {"hash": "h", "signature": "sig123"},
        }
        pkg = build_native_export_package(enc)
        assert is_native_export_package(pkg)
        assert pkg["integrity"]["signature"] == "sig123"

    def test_importer_dry_run_csv(self, vault_env) -> None:
        em, tmp = vault_env
        csv_path = Path(tmp.name) / "in.csv"
        csv_path.write_text(
            "title,username,password,url,notes,tags\nSite,u,P!1,https://x.com,n,t\n",
            encoding="utf-8",
        )
        report = VaultImporter(em).import_from_file_safe(
            csv_path,
            master_password=_MASTER,
            mode=MODE_DRY_RUN,
            fmt="csv",
        )
        assert report.get("success") is True
        assert len(em.get_all_entries()) == 0
