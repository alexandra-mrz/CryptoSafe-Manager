from __future__ import annotations

# Sprint 8 / TEST-1: pytest-сьют — crypto, vault, clipboard, import/export

import json
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from src.bootstrap import initialize_application
from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.platform_adapter import InMemoryClipboardAdapter
from src.core.crypto.authentication import (
    get_encryption_key,
    is_password_strong,
    set_master_password,
    unlock_session,
    verify_master_password,
)
from src.core.crypto.key_derivation import derive_key_argon2, derive_key_pbkdf2
from src.core.import_export.exporter import VaultExporter
from src.core.import_export.importer import MODE_MERGE, VaultImporter
from src.core.import_export.io_integration import extract_share_link, format_qr_scan_error
from src.core.import_export.import_security import keys_differ, scan_import_text, wipe_sensitive
from src.core.import_export.share_package_codec import decode_share_package_b64, encode_share_package_b64
from src.core.vault.encryption_service import VaultEncryptionService
from src.core.vault.entry_manager import EntryManager
from src.core.vault.search_index import build_search_text
from src.database.db import Database

_MASTER = "Sprint8!Master1"
_EXPORT = "Sprint8Export1!"


@pytest.fixture
def vault_key() -> bytes:
    return b"\x42" * 32


@pytest.fixture
def entry_manager(vault_key: bytes) -> EntryManager:
    tmp = tempfile.TemporaryDirectory()
    db = Database(Path(tmp.name) / "s8.db", use_pool=False)
    patchers = [
        patch("src.core.crypto.key_storage.get_default_database", return_value=db),
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
    mgr = EntryManager(db=db)
    mgr._tmp = tmp  # noqa: SLF001 — удержать temp dir
    mgr._patchers = patchers  # noqa: SLF001
    yield mgr
    for p in reversed(patchers):
        p.stop()
    tmp.cleanup()


# --- Crypto (encryption, decryption, key derivation) ---


class TestSprint8Crypto:
    def test_pbkdf2_deterministic(self) -> None:
        salt = b"sprint8-salt-16b"
        k1 = derive_key_pbkdf2("pass", salt, iterations=10_000)
        k2 = derive_key_pbkdf2("pass", salt, iterations=10_000)
        assert k1 == k2
        assert len(k1) == 32

    def test_argon2_produces_32_byte_key(self) -> None:
        key = derive_key_argon2("pass", b"1234567890123456", time_cost=1, memory_cost=8192, parallelism=1)
        assert len(key) == 32

    def test_argon2_param_limits(self) -> None:
        key = derive_key_argon2("pass", b"1234567890123456", time_cost=99, memory_cost=999999, parallelism=99)
        assert len(key) == 32

    def test_master_password_strength_and_verify(self) -> None:
        assert is_password_strong("weak") is False
        pw = "Verify8!TestPass"
        assert is_password_strong(pw) is True
        set_master_password(pw)
        assert verify_master_password(pw) is True
        assert verify_master_password("wrong") is False
        unlock_session(pw)
        enc_key = get_encryption_key(pw)
        assert enc_key is not None
        assert len(enc_key) == 32

    def test_vault_encryption_roundtrip(self, vault_key: bytes) -> None:
        svc = VaultEncryptionService()
        entry = {
            "title": "Bank",
            "username": "user@test.com",
            "password": "Secret!99",
            "url": "https://bank.example",
            "notes": "note",
            "category": "Finance",
            "version": 1,
        }
        blob = svc.encrypt_entry(entry, vault_key)
        assert b"Secret" not in blob
        restored = svc.decrypt_entry(bytes(blob), vault_key)["data"]
        assert restored["title"] == "Bank"
        assert restored["password"] == "Secret!99"


# --- Vault (add, edit, delete, search) ---


class TestSprint8Vault:
    def test_crud_and_search(self, entry_manager: EntryManager) -> None:
        created = entry_manager.create_entry(
            {
                "title": "GitHub",
                "username": "dev",
                "password": "Gh!Pass123",
                "url": "https://github.com",
                "notes": "work account",
                "tags": "dev",
            },
            master_password=_MASTER,
        )
        eid = int(created.id or 0)
        assert eid > 0

        entry_manager.update_entry(eid, {"title": "GitHub Pro", "version": 1})
        items = entry_manager.get_all_entries()
        assert any(it.get("title") == "GitHub Pro" for it in items)

        found = entry_manager.find_entries_by_query("github")
        assert len(found) == 1
        assert build_search_text(found[0]).lower().find("github") >= 0

        entry_manager.delete_entry(eid, soft_delete=False)
        assert len(entry_manager.get_all_entries()) == 0

    def test_soft_delete(self, entry_manager: EntryManager) -> None:
        created = entry_manager.create_entry(
            {
                "title": "Soft",
                "username": "u",
                "password": "P!1",
                "url": "",
                "notes": "",
                "tags": "",
            },
            master_password=_MASTER,
        )
        eid = int(created.id or 0)
        entry_manager.delete_entry(eid, soft_delete=True)
        assert len(entry_manager.get_all_entries()) == 0


# --- Clipboard ---


class TestSprint8Clipboard:
    def test_copy_and_auto_clear(self) -> None:
        adapter = InMemoryClipboardAdapter()
        svc = ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 1})
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            svc.copy_to_clipboard("ClipPass!1", data_type="password", source_entry_id="1")
            assert svc.get_clipboard_status().get("active") is True
            clip_val = adapter.get_clipboard_content() or ""
            assert clip_val != "ClipPass!1"
            assert len(clip_val) > 0
            svc.clear_clipboard()
            assert svc.get_clipboard_status().get("active") is False
            assert adapter.get_clipboard_content() in ("", None)

    def test_rapid_copy_and_stop(self) -> None:
        adapter = InMemoryClipboardAdapter()
        svc = ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 5})
        errors: list[str] = []

        def worker(prefix: str) -> None:
            try:
                for i in range(10):
                    svc.copy_to_clipboard(f"{prefix}-{i}", data_type="password")
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))

        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            threads = [threading.Thread(target=worker, args=(f"t{n}",)) for n in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert errors == []
            svc.stop()
            assert adapter.get_clipboard_content() == ""
            assert svc.get_clipboard_status().get("active") is False

    def test_ephemeral_copy(self) -> None:
        adapter = InMemoryClipboardAdapter()
        svc = ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 5})
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            svc.copy_ephemeral("Ephemeral!1", data_type="password")
            assert adapter.get_clipboard_content() in ("", None)


# --- Import / export ---


class TestSprint8ImportExport:
    def test_encrypted_export_import_roundtrip(self, entry_manager: EntryManager) -> None:
        entry_manager.create_entry(
            {
                "title": "ExportMe",
                "username": "u",
                "password": "P@ssw0rd1!",
                "url": "",
                "notes": "",
                "tags": "",
            },
            master_password=_MASTER,
        )
        exporter = VaultExporter(entry_manager)
        pkg = exporter.export_vault(
            None,
            master_password=_MASTER,
            export_password=_EXPORT,
            fmt="encrypted_json",
            skip_audit=True,
        )
        assert isinstance(pkg, dict)

        for row in entry_manager.get_all_entries():
            entry_manager.delete_entry(int(row["id"]), soft_delete=False)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vault.json"
            path.write_text(json.dumps(pkg), encoding="utf-8")
            report = VaultImporter(entry_manager).import_from_file_safe(
                path,
                master_password=_MASTER,
                import_password=_EXPORT,
                mode=MODE_MERGE,
            )
        assert report.get("success") is True
        items = entry_manager.get_all_entries()
        assert len(items) == 1
        assert items[0].get("title") == "ExportMe"

    def test_share_package_codec_roundtrip(self) -> None:
        pkg = {"format": "cryptosafe_share", "version": 1, "entry": {"title": "T"}}
        encoded = encode_share_package_b64(pkg)
        decoded = decode_share_package_b64(encoded)
        assert decoded["entry"]["title"] == "T"

    def test_io_integration_helpers(self) -> None:
        link = extract_share_link({"share_link": {"url_hint": "cryptosafe://share/abc"}})
        assert link.startswith("cryptosafe://")
        msg = format_qr_scan_error(ImportError("no pyzbar"))
        assert "pyzbar" in msg.lower() or "pip install" in msg.lower()

    def test_import_security_helpers(self) -> None:
        scan_import_text("safe,data")
        for payload in (
            "<script>x</script>",
            "javascript:alert(1)",
            "vbscript:run",
            "onerror=1",
            "<?php echo 1; ?>",
            "exec('rm')",
            "eval('1')",
            "powershell -enc abc",
            "cmd.exe /c",
        ):
            with pytest.raises(ValueError):
                scan_import_text(payload)
        assert keys_differ(b"\x01" * 32, b"\x02" * 32) is True
        assert keys_differ(b"\x01" * 32, b"\x01" * 16) is True
        buf = bytearray(b"secret")
        wipe_sensitive(buf)
        assert buf == b"\x00" * 6


class TestSprint8Bootstrap:
    def test_initialize_application_idempotent(self) -> None:
        initialize_application()
        initialize_application()
