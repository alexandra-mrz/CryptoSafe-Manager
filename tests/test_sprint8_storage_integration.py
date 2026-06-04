from __future__ import annotations

# Sprint 8 / TEST-2: целевое покрытие io_storage, io_integration, key_exchange
# (модули в scope .coveragerc; не дублирует TEST-1 в test_sprint8.py)

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.platform_adapter import InMemoryClipboardAdapter
from src.core.import_export.io_integration import (
    copy_share_link_to_clipboard,
    extract_share_link,
    extract_share_package_from_qr_body,
    format_qr_import_result,
    format_qr_scan_error,
    import_pubkey_contact_from_body,
    load_share_package_from_file,
    parse_share_token,
    process_scanned_qr_body,
    resolve_share_package_from_link,
    scan_qr_from_camera_with_hint,
    scan_qr_from_png_bytes,
)
from src.core.import_export.key_exchange import ALGO_ECC_P256, ALGO_RSA2048, ContactRecord, KeyExchange
from src.core.import_export.share_package_codec import encode_share_package_b64
from src.database import io_storage
from tests.sprint8_fixtures import MASTER_PASSWORD, patched_io_db  # noqa: F401 — fixture re-export

pytestmark = pytest.mark.usefixtures("patched_io_db")


# --- io_storage (DB Sprint 6) ---


class TestIoStorage:
    def test_shared_entry_and_history(self) -> None:
        sid = io_storage.insert_shared_entry(
            original_entry_id=1,
            encryption_method="password",
            recipient_info="alice@test",
            permissions="read_only",
            expires_at="2099-01-01T00:00:00Z",
            shared_id="share-fixed-id",
        )
        assert sid == "share-fixed-id"
        rows = io_storage.list_shared_entries(limit=10)
        assert rows[0]["shared_id"] == "share-fixed-id"

        row_id = io_storage.insert_io_history(
            operation_type=io_storage.OP_EXPORT,
            file_format="encrypted_json",
            encryption_used="aes256-gcm",
            entry_count=3,
            file_size=1024,
            checksum="abc",
            verification_status=io_storage.VERIFY_OK,
        )
        assert row_id > 0
        history = io_storage.list_io_history()
        assert history[0]["operation_type"] == io_storage.OP_EXPORT

    def test_contacts_crud_and_fingerprint(self) -> None:
        io_storage.upsert_contact(
            contact_id="bob",
            contact_name="Bob",
            public_key_pem="-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
            public_key_hex="ab" * 32,
            key_fingerprint="fp-bob-12345678",
            algorithm=ALGO_ECC_P256,
            fingerprint_verified=False,
        )
        row = io_storage.get_contact_row("bob")
        assert row is not None
        assert row["contact_name"] == "Bob"

        io_storage.touch_contact_last_used("bob")
        assert io_storage.set_contact_fingerprint_verified("bob", "wrong") is False
        assert io_storage.set_contact_fingerprint_verified("bob", "fp-bob-12345678") is True

        listed = io_storage.list_contact_rows(include_revoked=False)
        assert len(listed) == 1
        io_storage.revoke_contact_row("bob")
        assert io_storage.list_contact_rows(include_revoked=False) == []
        assert len(io_storage.list_contact_rows(include_revoked=True)) == 1

        with pytest.raises(ValueError):
            io_storage.revoke_contact_row("missing")

    def test_share_inbox_roundtrip_and_expiry(self) -> None:
        pkg = {"cryptosafe_share": True, "format": "cryptosafe_share", "entry": {"title": "Inbox"}}
        io_storage.save_share_inbox("tok123", pkg, expires_at="2099-06-01T12:00:00Z")
        loaded = io_storage.load_share_inbox_by_token("tok123")
        assert loaded["entry"]["title"] == "Inbox"

        io_storage.save_share_inbox("tok123", {"entry": {"title": "Updated"}}, expires_at="2099-06-01T12:00:00Z")
        assert io_storage.load_share_inbox_by_token("tok123")["entry"]["title"] == "Updated"

        past = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        io_storage.save_share_inbox("expired", pkg, expires_at=past)
        assert io_storage.load_share_inbox_by_token("expired") is None

        with pytest.raises(ValueError):
            io_storage.save_share_inbox("", pkg, expires_at="2099-01-01T00:00:00Z")
        assert io_storage.load_share_inbox_by_token("") is None
        assert io_storage.get_contact_row("nope") is None


# --- key_exchange ---


class TestKeyExchange:
    def test_rsa_and_ecc_key_lifecycle(self) -> None:
        kx = KeyExchange()
        rsa_pair = kx.generate_key_pair("rsa-contact", algorithm=ALGO_RSA2048)
        assert rsa_pair.algorithm == ALGO_RSA2048
        saved = kx.save_contact_public_key(rsa_pair)
        assert saved.contact_id == "rsa-contact"

        ecc_pair = kx.generate_key_pair("ecc-contact", algorithm=ALGO_ECC_P256)
        kx.save_contact_public_key(ecc_pair)
        contacts = kx.contacts.list_contacts()
        assert len(contacts) == 2

        rotated = kx.rotate_contact_keys("rsa-contact", algorithm=ALGO_ECC_P256)
        assert rotated.contact_id == "rsa-contact"
        revoked = [c for c in kx.contacts.list_contacts(include_revoked=True) if c.revoked]
        assert len(revoked) >= 1

        assert kx.contacts.verify_fingerprint("ecc-contact", ecc_pair.fingerprint) is True
        kx.contacts.revoke_contact("ecc-contact")
        assert kx.contacts.get_contact("ecc-contact").revoked is True

        with pytest.raises(ValueError):
            kx.generate_key_pair("bad", algorithm="unknown")

    def test_qr_payloads_and_import(self) -> None:
        kx = KeyExchange()
        pair = kx.generate_key_pair("qr-user", algorithm=ALGO_ECC_P256)
        pubkey_qr = kx.public_key_qr_payload(pair)
        assert pubkey_qr["body"]["type"] == "cryptosafe_pubkey"

        pkg = {"format": "cryptosafe_share", "entry": {"title": "QR"}}
        link = {"token": "abc", "url_hint": "cryptosafe://share/abc", "expires_at": "2099-01-01T00:00:00Z"}
        wrapped = kx.share_link_qr_payload(link, package=pkg)
        assert wrapped["body"]["package_b64"]

        enc_wrapped = kx.encrypted_entry_qr_payload(pkg)
        assert enc_wrapped["body"]["type"] == "cryptosafe_share_package"

        link_only = kx.share_link_qr_payload(link)
        assert link_only["body"]["type"] == "cryptosafe_share_link"

        images = kx.generate_qr_images(pubkey_qr)
        assert isinstance(images, list)

        with patch.object(kx._qr, "parse_scanned_text", return_value=pubkey_qr["body"]):
            imported = kx.import_pubkey_from_qr("wrapped-payload")
        assert imported.contact_id == "qr-user"

        with pytest.raises(ValueError):
            kx.parse_public_key_qr_payload(json.dumps({"type": "other"}))


# --- io_integration ---


class TestIoIntegration:
    def test_share_link_clipboard_and_parsers(self) -> None:
        pkg = {
            "cryptosafe_share": True,
            "share_link": {"url_hint": "cryptosafe://share/my-token"},
            "format": "cryptosafe_share",
        }
        assert extract_share_link(pkg) == "cryptosafe://share/my-token"
        assert parse_share_token("cryptosafe://share/my-token") == "my-token"
        assert parse_share_token("bare-token") == "bare-token"

        io_storage.save_share_inbox("my-token", {"entry": {"title": "Link"}}, expires_at="2099-01-01T00:00:00Z")
        resolved = resolve_share_package_from_link("cryptosafe://share/my-token")
        assert resolved["entry"]["title"] == "Link"

        adapter = InMemoryClipboardAdapter()
        clip = ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 30})
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            link = copy_share_link_to_clipboard(clip, pkg, source_entry_id=7)
        assert link.startswith("cryptosafe://")
        assert clip.get_clipboard_status().get("active") is True
        stored = adapter.get_clipboard_content() or ""
        assert stored != link
        assert len(stored) > 0

        with pytest.raises(ValueError):
            copy_share_link_to_clipboard(clip, {"no": "link"})

    def test_qr_body_and_file_helpers(self, tmp_path: Path) -> None:
        pkg = {"cryptosafe_share": True, "format": "cryptosafe_share", "entry": {"title": "File"}}
        b64 = encode_share_package_b64(pkg)
        from_body = extract_share_package_from_qr_body({"package_b64": b64})
        assert from_body["entry"]["title"] == "File"

        io_storage.save_share_inbox("qr-tok", pkg, expires_at="2099-01-01T00:00:00Z")
        from_token = extract_share_package_from_qr_body(
            {"type": "cryptosafe_share_link", "token": "qr-tok"}
        )
        assert from_token["entry"]["title"] == "File"

        share_path = tmp_path / "share.json"
        share_path.write_text(json.dumps(pkg), encoding="utf-8")
        loaded = load_share_package_from_file(share_path)
        assert loaded["entry"]["title"] == "File"

        bad_path = tmp_path / "bad.json"
        bad_path.write_text("{}", encoding="utf-8")
        with pytest.raises(ValueError):
            load_share_package_from_file(bad_path)

    def test_pubkey_import_and_process_scanned(self) -> None:
        kx = KeyExchange()
        body = {
            "type": "cryptosafe_pubkey",
            "contact_id": "scan-me",
            "algorithm": ALGO_ECC_P256,
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----",
            "public_key_hex": "aa" * 16,
            "fingerprint": "fp-scan",
        }
        contact = import_pubkey_contact_from_body(kx, body)
        assert isinstance(contact, ContactRecord)
        msg = process_scanned_qr_body(kx, body)
        assert "scan-me" in msg

        share_body = {"type": "cryptosafe_share_link", "token": "missing"}
        hint = format_qr_import_result(share_body)
        assert "share" in hint.lower() or "QR" in hint

        with pytest.raises(ValueError):
            import_pubkey_contact_from_body(kx, {"type": "other"})
        with pytest.raises(ValueError):
            process_scanned_qr_body(kx, {"type": "unknown"})

    def test_qr_scan_helpers(self) -> None:
        assert "pip install" in format_qr_scan_error(ImportError("no pyzbar")).lower()
        assert "30 минут" in format_qr_scan_error(RuntimeError("срок истёк"))

        mock_qr = MagicMock()
        mock_qr.scan_from_image_file.return_value = {"type": "cryptosafe_pubkey", "contact_id": "x"}
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
        body = scan_qr_from_png_bytes(mock_qr, png)
        assert body["contact_id"] == "x"

        with pytest.raises(ValueError):
            scan_qr_from_png_bytes(mock_qr, b"")

        mock_qr.scan_from_camera.return_value = {"ok": True}
        assert scan_qr_from_camera_with_hint(mock_qr, parent=None, timeout_sec=0.1) == {"ok": True}

        mock_qr.scan_from_camera.side_effect = RuntimeError("camera")
        with pytest.raises(RuntimeError):
            scan_qr_from_camera_with_hint(mock_qr, parent=None, timeout_sec=0.1)
