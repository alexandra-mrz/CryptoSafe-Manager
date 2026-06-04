from __future__ import annotations

# Sprint 8 / TEST-2: точечное покрытие entry_manager, log_integrity, state_manager

from pathlib import Path
from unittest.mock import patch

import pytest

from src.core.audit import log_integrity
from src.core.audit.audit_logger import AuditLogger
from src.core.audit.log_signer import cache_audit_signing_key
from src.core.crypto.authentication import set_master_password, unlock_session
from src.core.state_manager import StateManager
from src.core.vault.entry_manager import EntryManager, _coerce_encrypted_blob
from src.database.db import Database

from tests.sprint8_fixtures import MASTER_PASSWORD, entry_manager, patched_io_db, temp_database  # noqa: F401

pytestmark = pytest.mark.usefixtures("patched_io_db")


class TestEntryManagerGaps:
    def test_coerce_encrypted_blob_variants(self) -> None:
        assert _coerce_encrypted_blob(None) == b""
        assert _coerce_encrypted_blob(b"raw") == b"raw"
        mv = memoryview(b"ab")
        assert _coerce_encrypted_blob(mv) == b"ab"
        assert _coerce_encrypted_blob("deadbeef") == bytes.fromhex("deadbeef")
        assert _coerce_encrypted_blob("not-hex") == b"not-hex"

    def test_encrypted_list_and_list_entries(self, entry_manager: EntryManager) -> None:
        created = entry_manager.create_entry(
            {
                "title": "EncList",
                "username": "u",
                "password": "P!1Aa",
                "url": "",
                "notes": "",
                "tags": "x",
            },
            master_password=MASTER_PASSWORD,
        )
        eid = int(created.id or 0)
        enc_rows = entry_manager.get_all_entries_encrypted()
        assert any(r["id"] == eid for r in enc_rows)
        listed = entry_manager.list_entries()
        assert any(t[1] == "EncList" for t in listed)
        one = entry_manager.get_entry(eid)
        assert one["title"] == "EncList"

        with pytest.raises(ValueError):
            entry_manager.get_entry(99999)

    def test_skip_invalid_and_corrupt_blob(self, entry_manager: EntryManager, temp_database: Database) -> None:
        conn = temp_database.create_connection()
        try:
            conn.execute(
                "INSERT INTO vault_entries (encrypted_data, created_at, updated_at, tags) VALUES (?, ?, ?, ?)",
                (b"short", "2020-01-01", "2020-01-01", ""),
            )
            conn.commit()
        finally:
            conn.close()
        assert entry_manager.get_all_entries(skip_invalid=True) == []
        with pytest.raises(ValueError):
            entry_manager.get_all_entries(skip_invalid=False)


class TestLogIntegrityGaps:
    def test_verify_and_settings(self, temp_database: Database) -> None:
        with patch("src.core.audit.log_integrity.get_default_database", return_value=temp_database), patch(
            "src.core.audit.audit_logger.get_default_database", return_value=temp_database
        ), patch("src.core.crypto.key_storage.get_default_database", return_value=temp_database):
            conn = temp_database.create_connection()
            try:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO settings (setting_key, setting_value, encrypted) VALUES (?, ?, 0)",
                    (log_integrity.SETTING_INTERVAL_HOURS, "12"),
                )
                conn.commit()
            finally:
                conn.close()

            set_master_password(MASTER_PASSWORD)
            unlock_session(MASTER_PASSWORD)
            cache_audit_signing_key(MASTER_PASSWORD)

            assert log_integrity.check_audit_table_exists() is True
            assert log_integrity.get_verify_interval_hours() == 12
            assert log_integrity.should_lock_on_tamper() is False

            result = log_integrity.verify_on_startup()
            assert result["ok"] is True
            assert log_integrity.get_integrity_status() == log_integrity.STATUS_OK

            report_path = Path(temp_database._db_path).parent / "audit_report.txt"
            log_integrity.export_report_to_file(report_path)
            assert report_path.is_file()

            AuditLogger().log_event("TestEvent", {"detail": "x"})
            periodic = log_integrity.verify_periodic()
            assert periodic["mode"] == "periodic"

            with patch("src.core.audit.log_integrity.fetch_all_rows", side_effect=RuntimeError("db")):
                safe = log_integrity.safe_verify_manual_full()
            assert safe["ok"] is False


class TestStateManagerGaps:
    def test_settings_and_events(self, temp_database: Database) -> None:
        with patch("src.core.state_manager.get_default_database", return_value=temp_database):
            sm = StateManager(env="pytest")
            sm.set_setting("clipboard_timeout_seconds", 42, encrypted=True)
            assert sm.get_setting("clipboard_timeout_seconds") == "42"
            # Прямые вызовы обработчиков — без EventBus, чтобы не гонять audit в фоне.
            sm._on_user_logged_in("UserLoggedIn", {})
            assert sm.state.locked is False
            sm._on_clipboard_copied("ClipboardCopied", {"timeout": 30})
            assert sm.state.clipboard_seconds_left == 30
            sm._on_clipboard_cleared("ClipboardCleared", {})
            assert sm.state.clipboard_seconds_left == 0
            sm._on_user_activity("UserActivity", {})
            sm._on_user_logged_out("UserLoggedOut", {})
            assert sm.state.locked is True
            sm.stop()
