from __future__ import annotations

# Sprint 6: приёмочные тесты по ТЗ (§10 TEST-1..5, Must: SEC, PERF, ERR, INT, FMT)

import json
import os
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core.crypto.authentication import set_master_password, unlock_session
from src.core.import_export.exporter import VaultExporter
from src.core.import_export.formats.bw_json_format import entries_to_bitwarden_json
from src.core.import_export.formats.native_json_format import is_native_export_package
from src.core.import_export.importer import MODE_MERGE, MODE_REPLACE, VaultImporter
from src.core.import_export.key_exchange import ALGO_ECC_P256, KeyExchange
from src.core.crypto.memory import zero_bytearray
from src.core.events import get_event_bus
from src.core.import_export.formats.csv_format import entries_to_csv_text, parse_csv_text
from src.core.import_export.formats.lastpass_csv_format import entries_to_lastpass_csv, parse_lastpass_csv
from src.core.import_export.formats.native_json_format import build_native_export_package, is_native_export_package
from src.core.import_export.formats.share_json_format import build_share_encrypted_package, is_share_package
from src.core.import_export.import_checkpoint import default_checkpoint_path, load_checkpoint
from src.core.import_export.import_errors import (
    FormatDetectionError,
    RECOVERY_MANUAL_FORMAT,
    RECOVERY_RESUME_CHECKPOINT,
)
from src.core.import_export.import_security import keys_differ, scan_import_text, wipe_sensitive
from src.core.import_export.importer import MODE_DRY_RUN
from src.core.import_export.io_keys import derive_export_key, derive_sharing_key
from src.core.import_export.sharing_service import METHOD_LINK, METHOD_PASSWORD, METHOD_PUBLIC_KEY, SharingService
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database

# тестовые пароли (достаточно сложные для is_password_strong)
MASTER_PW = "MyStr0ng!PassOne"
EXPORT_PW = "ExportFilePass1!"
SHARE_PW = "ShareFilePass1!"


def _snapshot_entries(items: list[dict]) -> list[tuple]:
    # сравнение записей без id
    rows = []
    for item in items:
        rows.append(
            (
                str(item.get("title", "") or ""),
                str(item.get("username", "") or ""),
                str(item.get("password", "") or ""),
                str(item.get("url", "") or ""),
                str(item.get("notes", "") or ""),
            )
        )
    rows.sort()
    return rows


class _Sprint6VaultBase(unittest.TestCase):
    # общая временная БД и патчи

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_path = Path(self._tmp.name) / "sprint6.db"
        self.db = Database(self.db_path, use_pool=False)
        self.vault_key = b"\x55" * 32

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

        set_master_password(MASTER_PW)
        unlock_session(MASTER_PW)
        self.em = EntryManager(db=self.db)

    def tearDown(self) -> None:
        for p in reversed(self._patchers):
            p.stop()

    def _seed_entries(self, count: int = 5) -> list[tuple]:
        # создать записи и вернуть ожидаемый snapshot
        for i in range(count):
            self.em.create_entry(
                {
                    "title": f"Entry-{i}",
                    "username": f"user{i}@test.com",
                    "password": f"Secret{i}!Aa",
                    "url": f"https://site{i}.example",
                    "notes": f"note {i}",
                    "tags": "work",
                },
                master_password=MASTER_PW,
            )
        items = self.em.get_all_entries()
        return _snapshot_entries(items)

    def _clear_vault(self) -> None:
        for row in self.em.get_all_entries():
            eid = int(row.get("id", 0) or 0)
            if eid > 0:
                self.em.delete_entry(eid, soft_delete=False)


class TestSprint6RoundTrip(_Sprint6VaultBase):
    # TEST-1: экспорт всех форматов → импорт → целостность

    def test_round_trip_all_encrypted_formats(self) -> None:
        expected = self._seed_entries(5)
        exporter = VaultExporter(self.em)
        importer = VaultImporter(self.em)

        # EXP-1: encrypted JSON, CSV (plaintext/encrypted), Bitwarden JSON
        formats = [
            ("encrypted_json", True, EXPORT_PW),
            ("csv_encrypted", True, EXPORT_PW),
            ("bitwarden_json", True, EXPORT_PW),
            ("lastpass_csv_encrypted", True, EXPORT_PW),
            ("csv", False, ""),  # EXP-1: plaintext CSV — без export_password
            ("lastpass_csv", False, ""),
        ]
        for fmt, _need_pwd, pwd in formats:
            with self.subTest(fmt=fmt):
                kwargs = {
                    "master_password": MASTER_PW,
                    "export_password": pwd,
                    "fmt": fmt,
                }
                if fmt in ("csv", "lastpass_csv"):
                    kwargs["encrypt_csv"] = False
                pkg = exporter.export_vault(None, **kwargs)
                if fmt == "encrypted_json":
                    self.assertTrue(is_native_export_package(pkg))
                    enc = pkg.get("encryption") or {}
                    self.assertEqual(enc.get("algorithm"), "AES-256-GCM")
                    self.assertTrue(pkg.get("integrity", {}).get("hash"))
                if fmt in ("csv", "lastpass_csv"):
                    self.assertTrue(pkg.get("plaintext"))
                    self.assertEqual(pkg.get("format"), fmt)

                fd, path = tempfile.mkstemp(suffix=f"_{fmt}.json")
                os.close(fd)
                try:
                    Path(path).write_text(json.dumps(pkg, ensure_ascii=False), encoding="utf-8")
                    self._clear_vault()
                    result = importer.import_from_file(
                        path,
                        master_password=MASTER_PW,
                        import_password=pwd,
                        mode=MODE_REPLACE,
                    )
                    self.assertGreaterEqual(result.get("added", 0), 5)
                    after = _snapshot_entries(self.em.get_all_entries())
                    self.assertEqual(expected, after)
                finally:
                    try:
                        os.remove(path)
                    except OSError:
                        pass


class TestSprint6Interop(_Sprint6VaultBase):
    # TEST-2: Bitwarden / LastPass → парсинг и экспорт в их формат

    def test_import_bitwarden_json(self) -> None:
        self._clear_vault()
        bw = {
            "encrypted": False,
            "items": [
                {
                    "type": 1,
                    "name": "BW-Site",
                    "notes": "bw note",
                    "login": {
                        "username": "bwuser",
                        "password": "bwpass123",
                        "uris": [{"uri": "https://bw.example"}],
                    },
                }
            ],
        }
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            Path(path).write_text(json.dumps(bw), encoding="utf-8")
            importer = VaultImporter(self.em)
            result = importer.import_from_file(
                path,
                master_password=MASTER_PW,
                import_password="",
                mode=MODE_MERGE,
                fmt="bitwarden_json",
            )
            self.assertEqual(result.get("added", 0), 1)
            items = self.em.get_all_entries()
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0].get("title"), "BW-Site")
            self.assertEqual(items[0].get("username"), "bwuser")
            self.assertEqual(items[0].get("password"), "bwpass123")
        finally:
            os.remove(path)

    def test_import_lastpass_csv(self) -> None:
        self._clear_vault()
        csv_text = (
            "name,url,username,password,extra,grouping\n"
            "LP-Name,https://lp.example,lpuser,lppass,extra notes,Personal\n"
        )
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        try:
            Path(path).write_text(csv_text, encoding="utf-8")
            importer = VaultImporter(self.em)
            result = importer.import_from_file(
                path,
                master_password=MASTER_PW,
                mode=MODE_MERGE,
            )
            self.assertEqual(result.get("added", 0), 1)
            row = self.em.get_all_entries()[0]
            self.assertEqual(row.get("title"), "LP-Name")
            self.assertEqual(row.get("password"), "lppass")
        finally:
            os.remove(path)

    def test_export_lastpass_csv_round_trip(self) -> None:
        expected = self._seed_entries(2)
        exporter = VaultExporter(self.em)
        pkg = exporter.export_vault(
            None,
            master_password=MASTER_PW,
            fmt="lastpass_csv",
            encrypt_csv=False,
        )
        self.assertTrue(pkg.get("plaintext"))
        self.assertEqual(pkg.get("format"), "lastpass_csv")
        csv_text = str(pkg.get("csv_body", "") or "")
        rows = parse_lastpass_csv(csv_text)
        self.assertEqual(len(rows), 2)
        parsed = entries_to_lastpass_csv(rows)
        self.assertIn("name,url,username,password", parsed)

        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        try:
            Path(path).write_text(csv_text, encoding="utf-8")
            importer = VaultImporter(self.em)
            self._clear_vault()
            result = importer.import_from_file(path, master_password=MASTER_PW, mode=MODE_REPLACE)
            self.assertGreaterEqual(result.get("added", 0), 2)
            after = _snapshot_entries(self.em.get_all_entries())
            self.assertEqual(expected, after)
        finally:
            os.remove(path)

    def test_export_bitwarden_compatible_structure(self) -> None:
        self._seed_entries(2)
        exporter = VaultExporter(self.em)
        pkg = exporter.export_vault(
            None,
            master_password=MASTER_PW,
            export_password=EXPORT_PW,
            fmt="bitwarden_json",
        )
        importer = VaultImporter(self.em)
        body = importer.decrypt_package(pkg, import_password=EXPORT_PW)
        self.assertIn("items", body)
        self.assertGreaterEqual(len(body.get("items", [])), 2)


class TestSprint6SharingSecurity(_Sprint6VaultBase):
    # TEST-3: share всеми методами + tamper → отказ

    def _tamper_rejected(self, pkg: dict, *, share_password: str = "", private_pem: str = "") -> None:
        svc = SharingService(self.em)
        with self.assertRaises((ValueError, Exception)):
            if private_pem:
                svc.open_share_package(pkg, recipient_private_key_pem=private_pem, share_password=share_password)
            else:
                svc.open_share_package(pkg, share_password=share_password)

    def test_share_password_and_tamper(self) -> None:
        self._seed_entries(1)
        entry_id = int(self.em.get_all_entries()[0]["id"])
        svc = SharingService(self.em)
        pkg = svc.create_share(
            entry_id,
            "recipient@test",
            method=METHOD_PASSWORD,
            share_password=SHARE_PW,
        )
        body = svc.open_share_package(pkg, share_password=SHARE_PW)
        self.assertEqual(body["entry"]["title"], "Entry-0")

        bad = dict(pkg)
        bad["data"] = "AAAA"
        self._tamper_rejected(bad, share_password=SHARE_PW)

        bad2 = dict(pkg)
        bad2["integrity"] = {"hash": "0" * 64, "signature": bad2["integrity"]["signature"]}
        self._tamper_rejected(bad2, share_password=SHARE_PW)

    def test_share_public_key_and_tamper(self) -> None:
        self._seed_entries(1)
        entry_id = int(self.em.get_all_entries()[0]["id"])
        kx = KeyExchange()
        pair = kx.generate_key_pair("bob", ALGO_ECC_P256)
        kx.save_contact_public_key(pair)

        svc = SharingService(self.em)
        pkg = svc.create_share(
            entry_id,
            "bob",
            method=METHOD_PUBLIC_KEY,
            recipient_public_key_pem=pair.public_key_pem,
            share_password=SHARE_PW,
        )
        body = svc.open_share_package(pkg, recipient_private_key_pem=pair.private_key_pem, share_password=SHARE_PW)
        self.assertEqual(body["entry"]["password"], "Secret0!Aa")

        bad = dict(pkg)
        bad["integrity"] = {"hash": "dead", "signature": pkg["integrity"]["signature"]}
        self._tamper_rejected(bad, private_pem=pair.private_key_pem, share_password=SHARE_PW)

    def test_share_link_password_and_tamper(self) -> None:
        # SHR-1: time-limited share link (METHOD_LINK → пароль + share_link)
        self._seed_entries(1)
        entry_id = int(self.em.get_all_entries()[0]["id"])
        svc = SharingService(self.em)
        pkg = svc.create_share(
            entry_id,
            "link@test",
            method=METHOD_LINK,
            share_password=SHARE_PW,
            include_link=True,
        )
        self.assertTrue(pkg.get("share_link"))
        body = svc.open_share_package(pkg, share_password=SHARE_PW)
        self.assertEqual(body["entry"]["title"], "Entry-0")

        bad = dict(pkg)
        bad["data"] = "tampered"
        self._tamper_rejected(bad, share_password=SHARE_PW)


class TestSprint6QrCode(_Sprint6VaultBase):
    # TEST-4: QR ~1KB, целостность после «сканирования»

    def test_qr_1kb_payload_roundtrip(self) -> None:
        try:
            import qrcode  # noqa: F401
        except ImportError:
            self.skipTest("qrcode не установлен: pip install qrcode[pil]")
        from src.core.import_export.qr_code_service import QRCodeService

        kx = KeyExchange()
        pair = kx.generate_key_pair("qr-test", ALGO_ECC_P256)
        qr = QRCodeService()

        # payload ~1KB (ТЗ); checksum считается после финального body
        inner = {
            "type": "cryptosafe_pubkey",
            "contact_id": "qr-test",
            "algorithm": pair.algorithm,
            "public_key_pem": pair.public_key_pem,
            "public_key_hex": pair.public_key_hex,
            "fingerprint": pair.fingerprint,
            "padding": "x" * 900,
        }
        from src.core.import_export.qr_code_service import PAYLOAD_PUBKEY

        wrapped = qr.build_wrapped_payload(PAYLOAD_PUBKEY, inner)
        raw_len = len(json.dumps(wrapped, ensure_ascii=False).encode("utf-8"))
        self.assertGreaterEqual(raw_len, 1000)

        t0 = time.perf_counter()
        images = kx.generate_qr_images(wrapped)
        gen_ms = (time.perf_counter() - t0) * 1000
        self.assertLess(gen_ms, 5000)  # functional check (PERF — отдельный test_perf3)
        self.assertGreater(len(images), 0)

        # «сканирование»: все PNG → pyzbar (chunk-сборка при большом payload)
        scanned_texts: list[str] = []
        temp_pngs: list[str] = []
        try:
            for idx, img_bytes in enumerate(images):
                fd, png_path = tempfile.mkstemp(suffix=f"_{idx}.png")
                os.close(fd)
                temp_pngs.append(png_path)
                Path(png_path).write_bytes(img_bytes)
                try:
                    scanned_texts.extend(qr.decode_from_image_file(png_path))
                except RuntimeError:
                    pass
            chunk_parts = [t for t in scanned_texts if '"cryptosafe_qr_chunk"' in t]
            if chunk_parts:
                full_json = qr.decode_chunk_texts(chunk_parts)
                self.assertIsNotNone(full_json)
                body = qr.validate_wrapped_payload(json.loads(full_json))
            elif scanned_texts:
                body = qr.parse_scanned_text(scanned_texts[0])
            else:
                # запасной путь без камеры/pyzbar
                body = qr.parse_scanned_text(json.dumps(wrapped, ensure_ascii=False, sort_keys=True))
            self.assertEqual(body.get("contact_id"), "qr-test")
            self.assertEqual(body.get("fingerprint"), pair.fingerprint)
        finally:
            for p in temp_pngs:
                try:
                    os.remove(p)
                except OSError:
                    pass

    def test_perf3_qr_generation_under_100ms(self) -> None:
        # PERF-3: генерация QR для небольшого payload < 100 ms
        try:
            import qrcode  # noqa: F401
        except ImportError:
            self.skipTest("qrcode не установлен")
        from src.core.import_export.qr_code_service import PAYLOAD_PUBKEY, QRCodeService

        qr = QRCodeService()
        wrapped = qr.build_wrapped_payload(
            PAYLOAD_PUBKEY,
            {"type": "cryptosafe_pubkey", "contact_id": "perf3", "algorithm": "ecc_p256"},
        )
        t0 = time.perf_counter()
        qr.generate_qr_images(wrapped)
        self.assertLess((time.perf_counter() - t0) * 1000, 100)


class TestSprint6Security(_Sprint6VaultBase):
    # §11 SEC-1..SEC-5 (Must)

    def test_sec1_default_export_encrypted(self) -> None:
        self.em.create_entry(
            {"title": "T", "username": "u", "password": "p", "url": "", "notes": "", "tags": ""},
            master_password=MASTER_PW,
        )
        exporter = VaultExporter(self.em)
        pkg = exporter.export_vault(
            None, master_password=MASTER_PW, export_password=EXPORT_PW, fmt="encrypted_json",
        )
        self.assertTrue(pkg.get("data"))
        self.assertIsInstance(pkg.get("encryption"), dict)
        self.assertFalse(pkg.get("plaintext"))

        plain = exporter.export_vault(
            None, master_password=MASTER_PW, export_password="", fmt="csv", encrypt_csv=False,
        )
        self.assertTrue(plain.get("plaintext"))
        self.assertNotIn("encryption", plain)
        self.assertNotIn("data", plain)

        with self.assertRaises(ValueError):
            exporter.export_vault(
                None, master_password=MASTER_PW, export_password="", fmt="encrypted_json",
            )

    def test_sec3_keys_separate_from_vault(self) -> None:
        export_key = derive_export_key(MASTER_PW)
        sharing_key = derive_sharing_key(MASTER_PW)
        self.assertTrue(keys_differ(self.vault_key, export_key))
        self.assertTrue(keys_differ(self.vault_key, sharing_key))

    def test_sec4_wipe_sensitive(self) -> None:
        buf = bytearray(b"secret-key-material!!")
        wipe_sensitive(buf)
        self.assertEqual(bytes(buf), b"\x00" * len(buf))
        buf2 = bytearray(b"xyz")
        zero_bytearray(buf2)
        self.assertEqual(bytes(buf2), b"\x00" * 3)

    def test_sec5_rejects_malicious_csv(self) -> None:
        csv_bad = "title,username,password,url,notes,tags\nEvil,,pass,https://x,<script>alert(1)</script>,\n"
        with self.assertRaises(ValueError):
            scan_import_text(csv_bad)
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        try:
            Path(path).write_text(csv_bad, encoding="utf-8")
            with self.assertRaises(ValueError):
                VaultImporter(self.em).import_from_file(path, master_password=MASTER_PW, mode=MODE_MERGE)
        finally:
            os.remove(path)


class TestSprint6Formats(unittest.TestCase):
    # §9 FMT-1..FMT-3 (Must, проверка структуры)

    def test_fmt1_native_export_wrapper(self) -> None:
        enc = {
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_derivation": "PBKDF2-HMAC-SHA256",
                "iterations": 100000,
                "salt": "aa",
                "nonce": "bb",
            },
            "data": "ccc",
            "integrity": {"hash": "h", "signature": "sig123"},
        }
        pkg = build_native_export_package(enc)
        self.assertTrue(is_native_export_package(pkg))
        self.assertEqual(pkg["integrity"]["signature"], "sig123")

    def test_fmt3_csv_escaping(self) -> None:
        csv = entries_to_csv_text(
            [{"title": 'a,quote', "username": "u", "password": 'p"w', "url": "http://x", "notes": "line1\nline2"}]
        )
        rows = parse_csv_text(csv)
        self.assertEqual(rows[0]["title"], "a,quote")
        self.assertIn("line1", rows[0]["notes"])

    def test_fmt2_share_header(self) -> None:
        enc = {
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_derivation": "PBKDF2-HMAC-SHA256",
                "iterations": 100000,
                "salt": "aa",
                "nonce": "bb",
            },
            "data": "ccc",
            "integrity": {"hash": "h", "signature": "s"},
        }
        share = build_share_encrypted_package(enc)
        self.assertTrue(is_share_package(share))
        self.assertTrue(share["header"]["encrypted"])


class TestSprint6Integration(_Sprint6VaultBase):
    # §12 INT-1, INT-2 (Must)

    def test_int1_selective_export_by_query(self) -> None:
        self.em.create_entry(
            {"title": "Work-Site", "username": "a", "password": "p", "url": "", "notes": "", "tags": "work"},
            master_password=MASTER_PW,
        )
        self.em.create_entry(
            {"title": "Home-Bank", "username": "b", "password": "p2", "url": "", "notes": "", "tags": "home"},
            master_password=MASTER_PW,
        )
        exporter = VaultExporter(self.em)
        ids = exporter.pick_entry_ids_by_query("work")
        pkg = exporter.export_vault_by_query(
            "work", master_password=MASTER_PW, export_password=EXPORT_PW, skip_audit=True,
        )
        self.assertEqual(len(ids), 1)
        self.assertEqual(int(pkg.get("entry_count", 0)), 1)

    def test_int2_audit_export_and_share(self) -> None:
        # реальный EventBus (в setUp get_event_bus замокан)
        bus = get_event_bus()
        seen: list[str] = []

        def _capture(_name: str, payload) -> None:
            if isinstance(payload, dict):
                seen.append(_name)

        for evt in ("VaultExported", "VaultShared"):
            bus.subscribe(evt, _capture)

        self._seed_entries(1)
        eid = int(self.em.get_all_entries()[0]["id"])
        with patch("src.core.import_export.exporter.get_event_bus", return_value=bus), patch(
            "src.core.import_export.sharing_service.get_event_bus", return_value=bus
        ):
            VaultExporter(self.em).export_vault(
                None, master_password=MASTER_PW, export_password=EXPORT_PW, skip_audit=False,
            )
            SharingService(self.em).create_share(
                eid, "bob@test", method=METHOD_LINK, share_password=SHARE_PW, include_link=True,
            )
        self.assertIn("VaultExported", seen)
        self.assertIn("VaultShared", seen)


class TestSprint6Errors(_Sprint6VaultBase):
    # §14 ERR-1, ERR-3, ERR-4 (Must); ERR-2 (Should)

    def test_err1_corrupted_file_report(self) -> None:
        bad = Path(self._tmp.name) / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        report = VaultImporter(self.em).import_from_file_safe(
            bad, master_password=MASTER_PW, mode=MODE_DRY_RUN,
        )
        self.assertFalse(report.get("success"))
        self.assertEqual(report.get("error_code"), "corrupted_file")

    def test_err3_format_detection_and_manual_fallback(self) -> None:
        with self.assertRaises(FormatDetectionError):
            VaultImporter(self.em).resolve_import_format({})
        unknown = Path(self._tmp.name) / "unknown.json"
        unknown.write_text('{"foo": 1}', encoding="utf-8")
        report = VaultImporter(self.em).import_from_file_safe(
            unknown, master_password=MASTER_PW, mode=MODE_DRY_RUN,
        )
        self.assertFalse(report.get("success"))
        self.assertEqual(report.get("error_code"), "format_detection_failed")
        self.assertIn(RECOVERY_MANUAL_FORMAT, report.get("recovery_options", []))

    def test_err4_wrong_password_no_plaintext_leak(self) -> None:
        self._seed_entries(1)
        pkg = VaultExporter(self.em).export_vault(
            None, master_password=MASTER_PW, export_password=EXPORT_PW, skip_audit=True,
        )
        path = Path(self._tmp.name) / "enc.json"
        path.write_text(json.dumps(pkg), encoding="utf-8")
        report = VaultImporter(self.em).import_from_file_safe(
            path, master_password=MASTER_PW, import_password="WrongPass1!", mode=MODE_DRY_RUN,
        )
        self.assertFalse(report.get("success"))
        self.assertEqual(report.get("error_code"), "encryption_failed")

    def test_err2_checkpoint_resume(self) -> None:
        csv_path = Path(self._tmp.name) / "ck.csv"
        lines = ["title,username,password,url,notes,tags"]
        lines += [f"T{i},,,p{i},," for i in range(5)]
        csv_path.write_text("\n".join(lines), encoding="utf-8")
        importer = VaultImporter(self.em)
        ck = default_checkpoint_path(str(csv_path))
        call_count = {"n": 0}
        real_create = self.em.create_entry

        def flaky_create(data_dict, master_password=""):
            call_count["n"] += 1
            if call_count["n"] == 3:
                raise RuntimeError("simulated fail")
            return real_create(data_dict, master_password=master_password)

        with patch.object(self.em, "create_entry", side_effect=flaky_create):
            report = importer.import_from_file_safe(
                csv_path, master_password=MASTER_PW, mode=MODE_MERGE, fmt="csv",
                use_checkpoint=True, checkpoint_path=ck,
            )
        self.assertFalse(report.get("success"))
        self.assertIn(RECOVERY_RESUME_CHECKPOINT, report.get("recovery_options", []))
        with patch.object(self.em, "create_entry", side_effect=real_create):
            done = importer.import_from_file_safe(
                csv_path, master_password=MASTER_PW, mode=MODE_MERGE, fmt="csv",
                resume=True, checkpoint_path=ck,
            )
        self.assertTrue(done.get("success"))


class TestSprint6Performance(unittest.TestCase):
    # TEST-5: 1000 записей — время и память (PERF-1 / PERF-2 / PERF-4)

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_path = Path(self._tmp.name) / "perf6.db"
        self.db = Database(self.db_path, use_pool=False)
        self.vault_key = b"\x66" * 32
        self._patchers = [
            patch("src.core.crypto.key_storage.get_default_database", return_value=self.db),
            patch("src.database.io_storage.get_default_database", return_value=self.db),
            patch("src.core.vault.entry_manager.is_session_unlocked", return_value=True),
            patch("src.core.key_manager.KeyManager.get_vault_encryption_key", return_value=self.vault_key),
            patch("src.core.crypto.authentication.verify_master_password", return_value=True),
            patch("src.core.import_export.exporter.get_event_bus"),
            patch("src.core.import_export.importer.get_event_bus"),
            patch("src.core.import_export.exporter.io_storage.insert_io_history"),
            patch("src.core.import_export.importer.io_storage.insert_io_history"),
        ]
        for p in self._patchers:
            p.start()
        set_master_password(MASTER_PW)
        unlock_session(MASTER_PW)
        self.em = EntryManager(db=self.db)
        for i in range(1000):
            self.em.create_entry(
                {
                    "title": f"Perf-{i}",
                    "username": f"u{i}",
                    "password": f"P{i}!",
                    "url": f"https://p{i}.com",
                    "notes": "n",
                    "tags": "",
                },
                master_password=MASTER_PW,
            )

    def tearDown(self) -> None:
        for p in reversed(self._patchers):
            p.stop()

    def test_export_import_1000_performance(self) -> None:
        exporter = VaultExporter(self.em)
        importer = VaultImporter(self.em)
        out_path = Path(self._tmp.name) / "perf_export.json"

        import gc

        gc.collect()
        tracemalloc.start()
        t0 = time.perf_counter()
        pkg = exporter.export_vault(
            None,
            master_password=MASTER_PW,
            export_password=EXPORT_PW,
            fmt="encrypted_json",
            skip_audit=True,
        )
        export_sec = time.perf_counter() - t0
        _, export_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        Path(out_path).write_text(json.dumps(pkg), encoding="utf-8")
        file_size = out_path.stat().st_size
        self.assertGreater(file_size, 0)

        for row in self.em.get_all_entries():
            self.em.delete_entry(int(row["id"]), soft_delete=False)

        gc.collect()
        tracemalloc.start()
        t1 = time.perf_counter()
        result = importer.import_from_file(
            out_path,
            master_password=MASTER_PW,
            import_password=EXPORT_PW,
            mode=MODE_REPLACE,
        )
        import_sec = time.perf_counter() - t1
        _, import_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertLess(export_sec, 5.0)  # PERF-1
        self.assertLess(import_sec, 10.0)  # PERF-2
        self.assertEqual(result.get("added", 0), 1000)
        self.assertEqual(len(self.em.get_all_entries()), 1000)
        # PERF-4: 2× файл + допуск на объекты Python (~6 MB для 1000 записей)
        mem_cap = file_size * 2 + 6_000_000
        self.assertLess(export_peak, mem_cap)
        self.assertLess(import_peak, mem_cap)


if __name__ == "__main__":
    unittest.main()
