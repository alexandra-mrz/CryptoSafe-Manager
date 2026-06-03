from __future__ import annotations

# Sprint 8: io_integration + sharing (coverage)

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.core.crypto.authentication import set_master_password, unlock_session
from src.core.import_export.formats.share_json_format import build_share_plaintext_package, build_share_metadata
from src.core.import_export.io_integration import (
    extract_share_package_from_qr_body,
    format_qr_import_result,
    format_qr_scan_error,
    import_pubkey_contact_from_body,
    load_share_package_from_file,
    parse_share_token,
    process_scanned_qr_body,
    resolve_share_package_from_link,
    scan_qr_from_camera,
)
from src.core.import_export.key_exchange import ALGO_ECC_P256, KeyExchange
from src.core.import_export.share_package_codec import encode_share_package_b64
from src.core.import_export.sharing_service import METHOD_LINK, METHOD_PUBLIC_KEY, SharingService
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database
from src.database import io_storage

_MASTER = "IoInt!Master1"
_SHARE = "SharePass1234!"


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self._tmp.name) / "io.db", use_pool=False)
        self.vault_key = b"\x77" * 32
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


class TestSprint8IoIntegrationFull(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self._tmp.name) / "io_int.db", use_pool=False)
        self._patch = patch("src.database.io_storage.get_default_database", return_value=self.db)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def test_parse_and_resolve_share_link(self) -> None:
        self.assertEqual(parse_share_token("cryptosafe://share/abc123"), "abc123")
        self.assertEqual(parse_share_token("  deadbeef  "), "deadbeef")

        meta = build_share_metadata(
            recipient="r",
            sharer="s",
            permission="read_only",
            expires_at="2099-01-01T00:00:00Z",
            encryption_method="password",
        )
        pkg = build_share_plaintext_package({"title": "T", "username": "u", "password": "p"}, meta)
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            Path(path).write_text(json.dumps(pkg), encoding="utf-8")
            loaded = load_share_package_from_file(path)
            self.assertTrue(loaded.get("cryptosafe_share"))
        finally:
            os.remove(path)

        io_storage.save_share_inbox("tok999", pkg, expires_at="2099-01-01T00:00:00Z")
        resolved = resolve_share_package_from_link("cryptosafe://share/tok999")
        self.assertIsNotNone(resolved)
        self.assertIsNone(resolve_share_package_from_link("not-a-link"))

    def test_qr_body_helpers(self) -> None:
        meta = build_share_metadata(
            recipient="r",
            sharer="s",
            permission="read_only",
            expires_at="2099-01-01T00:00:00Z",
            encryption_method="password",
        )
        share_pkg = build_share_plaintext_package({"title": "T", "username": "u", "password": "p"}, meta)
        b64 = encode_share_package_b64(share_pkg)
        body = {"type": "cryptosafe_share_package", "package_b64": b64}
        pkg = extract_share_package_from_qr_body(body)
        self.assertIsNotNone(pkg)

        io_storage.save_share_inbox("qr_tok", share_pkg, expires_at="2099-01-01T00:00:00Z")
        link_body = {"type": "cryptosafe_share_link", "token": "qr_tok"}
        self.assertIsNotNone(extract_share_package_from_qr_body(link_body))

        kx = KeyExchange()
        pair = kx.generate_key_pair("c1", ALGO_ECC_P256)
        wrapped = kx.public_key_qr_payload(pair)
        pubkey_body = wrapped.get("body", wrapped)
        contact = import_pubkey_contact_from_body(kx, pubkey_body)
        msg = format_qr_import_result(pubkey_body, contact=contact)
        self.assertIn("c1", msg)
        out = process_scanned_qr_body(kx, pubkey_body)
        self.assertIn("c1", out)

        share_msg = format_qr_import_result(link_body)
        self.assertIn("share", share_msg.lower())

        err = format_qr_scan_error(RuntimeError("установите pyzbar"))
        self.assertIn("pip install", err.lower())

    def test_scan_qr_from_camera_mock(self) -> None:
        qr = MagicMock()
        qr.scan_from_camera.return_value = {"type": "cryptosafe_pubkey", "contact_id": "cam"}
        result = scan_qr_from_camera(qr, timeout_sec=1.0)
        self.assertEqual(result.get("contact_id"), "cam")


class TestSprint8SharingFull(_Base):
    def test_share_public_key_and_link(self) -> None:
        self.em.create_entry(
            {"title": "Sh", "username": "u", "password": "p", "url": "", "notes": "", "tags": ""},
            master_password=_MASTER,
        )
        eid = int(self.em.get_all_entries()[0]["id"])
        kx = KeyExchange()
        pair = kx.generate_key_pair("bob", ALGO_ECC_P256)
        kx.save_contact_public_key(pair)
        svc = SharingService(self.em)
        pkg_pk = svc.create_share(
            eid, "bob", method=METHOD_PUBLIC_KEY, recipient_public_key_pem=pair.public_key_pem, share_password=_SHARE,
        )
        svc.open_share_package(pkg_pk, recipient_private_key_pem=pair.private_key_pem, share_password=_SHARE)
        pkg_link = svc.create_share(
            eid, "link@test", method=METHOD_LINK, share_password=_SHARE, include_link=True,
        )
        self.assertIn("share_link", pkg_link)
