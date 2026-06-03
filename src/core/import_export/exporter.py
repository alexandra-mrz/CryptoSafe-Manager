from __future__ import annotations

# Sprint 6: экспорт vault (EXP-1..EXP-4 — форматы, шифрование, аудит)

import base64
import gzip
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.crypto.authentication import is_session_unlocked, verify_master_password
from src.core.events import get_event_bus
from src.core.import_export.formats.bw_json_format import entries_to_bitwarden_json
from src.core.import_export.formats.csv_format import entries_to_csv_text
from src.core.import_export.formats.lastpass_csv_format import entries_to_lastpass_csv
from src.core.import_export.formats.json_format import _utc_now_iso, entries_to_json_dict
from src.core.import_export.formats.native_json_format import build_native_export_package
from src.core.import_export.import_security import keys_differ, wipe_sensitive
from src.core.security.integration import check_io_aborted
from src.core.import_export.io_keys import derive_export_key, derive_file_key_from_salt
from src.core.key_manager import KeyManager
from src.core.vault.entry_manager import EntryManager
from src.database import io_storage

_SOURCE_APP = "CryptoSafe Manager"
_PACKAGE_VERSION = "1.0"


class VaultExporter:
    # экспорт записей vault (структура как в примере преподавателя)

    """Публичный класс VaultExporter."""
    def __init__(
        self,
        entry_manager: Optional[EntryManager] = None,
        key_manager: Optional[KeyManager] = None,
    ) -> None:
        # entry_manager — записи, key_manager — ключи vault (только чтение)
        self._entries = entry_manager or EntryManager()
        self._keys = key_manager or KeyManager()

    @property
    def entry_manager(self) -> EntryManager:
        # доступ к менеджеру записей
        """Entry manager."""
        return self._entries

    @property
    def key_manager(self) -> KeyManager:
        # доступ к менеджеру ключей
        """Key manager."""
        return self._keys

    def _get_entries_for_export(self, entry_ids: Optional[list[int]]) -> list[dict]:
        # как в примере: entry_ids=None → все записи
        all_items = self._entries.get_all_entries()
        if entry_ids is None:
            return all_items
        wanted = {int(x) for x in entry_ids}
        return [item for item in all_items if int(item.get("id", -1)) in wanted]

    def _pick_entries(self, entry_ids: Optional[list[int]]) -> list[dict]:
        # совместимость с INT-1 / тестами
        return self._get_entries_for_export(entry_ids)

    def _prepare_export_data(self, entries: list[dict]) -> dict[str, Any]:
        # как в примере: version, exported_at, entry_count, entries
        return entries_to_json_dict(entries, source_app=_SOURCE_APP)

    def _derive_export_key(self, password: str, salt: bytes) -> bytes:
        # PBKDF2 от пароля файла (соль уникальна на каждый экспорт)
        return derive_file_key_from_salt(password, salt)

    def pick_entry_ids_by_query(self, query: str) -> list[int]:
        # INT-1: id записей по поисковому запросу vault
        """Pick entry ids by query."""
        rows = self._entries.find_entries_by_query(query)
        return [int(row.get("id", 0) or 0) for row in rows if int(row.get("id", 0) or 0) > 0]

    def _apply_field_options(
        self,
        entries: list[dict],
        *,
        include_notes: bool = True,
        exclude_fields: Optional[list[str]] = None,
    ) -> list[dict]:
        # EXP-3: убрать notes и другие поля по запросу
        skip = set(exclude_fields or [])
        if not include_notes:
            skip.add("notes")
        if not skip:
            return entries
        cleaned = []
        for item in entries:
            row = dict(item)
            for name in skip:
                if name in row:
                    row[name] = ""
            cleaned.append(row)
        return cleaned

    def _build_body(
        self,
        entries: list[dict],
        fmt: str,
    ) -> dict[str, Any]:
        # EXP-1: тело пакета до шифрования
        if fmt == "csv":
            # FMT-3: CSV с метаданными в комментариях
            return {
                "format": "csv",
                "csv_body": entries_to_csv_text(
                    entries,
                    include_metadata_header=True,
                    exported_at=_utc_now_iso(),
                    source_app=_SOURCE_APP,
                ),
                "entry_count": len(entries),
            }
        if fmt == "bitwarden_json":
            bw = entries_to_bitwarden_json(entries)
            bw["format"] = "bitwarden_json"
            bw["entry_count"] = len(entries)
            return bw
        if fmt == "lastpass_csv":
            return {
                "format": "lastpass_csv",
                "csv_body": entries_to_lastpass_csv(entries),
                "entry_count": len(entries),
            }
        payload = entries_to_json_dict(entries, source_app=_SOURCE_APP)
        payload["format"] = "encrypted_json"
        return payload

    def _plain_bytes(self, package: dict[str, Any], *, compress: bool) -> tuple[bytes, dict[str, str]]:
        # EXP-3: опционально GZIP перед шифрованием
        plain = json.dumps(package, ensure_ascii=False, sort_keys=True).encode("utf-8")
        extra: dict[str, str] = {"compression": "none"}
        if compress:
            plain = gzip.compress(plain)
            extra["compression"] = "gzip"
        return plain, extra

    def _file_key(self, password_or_pubkey: str, file_salt: bytes, key_bits: int) -> bytes:
        # EXP-3: 128 или 256 бит (AES-GCM)
        raw = derive_file_key_from_salt(password_or_pubkey, file_salt)
        if key_bits == 128:
            return raw[:16]
        return raw[:32]

    def _sign_plaintext(self, plain: bytes, export_password: str) -> str:
        # EXP-2: подпись HMAC (отдельный контекст vault-export)
        sign_key = derive_export_key(export_password)
        try:
            return hmac.new(sign_key, plain, hashlib.sha256).hexdigest()
        finally:
            wipe_sensitive(sign_key)

    def _encrypt_with_password(
        self,
        data: dict[str, Any],
        password: str,
        *,
        export_password: str = "",
        key_bits: int = 256,
        compression_meta: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        # как в примере: AES-256-GCM + PBKDF2
        if not password:
            raise ValueError("Either password or public key must be provided")
        sign_pwd = export_password or password
        plain, comp = self._plain_bytes(data, compress=(compression_meta or {}).get("compression") == "gzip")
        meta = compression_meta or comp
        return self._encrypt_plain(
            plain,
            password_or_pubkey=password,
            export_password=sign_pwd,
            encryption_mode="password",
            key_bits=key_bits,
            compression_meta=meta,
        )

    def _encrypt_with_public_key(
        self,
        data: dict[str, Any],
        public_key: bytes,
        *,
        export_password: str = "",
        key_bits: int = 256,
    ) -> dict[str, Any]:
        # как в примере: RSA-OAEP + AES-256-GCM (hybrid)
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        if not public_key:
            raise ValueError("Either password or public key must be provided")
        pub = serialization.load_pem_public_key(public_key)
        sym_key = os.urandom(32)
        if key_bits == 128:
            sym_key = sym_key[:16]
        nonce = os.urandom(12)
        plain = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
        plain_buf = bytearray(plain)
        try:
            cipher = AESGCM(sym_key).encrypt(nonce, bytes(plain_buf), None)
            encrypted_sym = pub.encrypt(
                sym_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            integrity = hashlib.sha256(plain_buf).hexdigest()
            sign_hex = self._sign_plaintext(bytes(plain_buf), export_password)
        finally:
            wipe_sensitive(sym_key)
            wipe_sensitive(plain_buf)
        return {
            "encryption": {
                "algorithm": "RSA-OAEP/AES-256-GCM",
                "mode": "public_key",
                "key_size": 2048,
                "nonce": base64.b64encode(nonce).decode("ascii"),
            },
            "encrypted_key": base64.b64encode(encrypted_sym).decode("ascii"),
            "data": base64.b64encode(cipher).decode("ascii"),
            "integrity": {
                "hash": integrity,
                "hash_algorithm": "SHA256",
                "signature": sign_hex,
            },
        }

    def _encrypt_plain(
        self,
        plain: bytes,
        *,
        password_or_pubkey: str,
        export_password: str,
        encryption_mode: str,
        key_bits: int,
        compression_meta: dict[str, str],
    ) -> dict[str, Any]:
        # внутренний шаг: шифрование уже подготовленных байт
        file_salt = os.urandom(16)
        nonce = os.urandom(12)
        file_key = self._file_key(password_or_pubkey, file_salt, key_bits)
        plain_buf = bytearray(plain)
        try:
            cipher = AESGCM(file_key).encrypt(nonce, bytes(plain_buf), None)
            integrity = hashlib.sha256(plain_buf).hexdigest()
            sign_hex = self._sign_plaintext(bytes(plain_buf), export_password)
        finally:
            wipe_sensitive(file_key)
            wipe_sensitive(plain_buf)
        algo = "AES-128-GCM" if key_bits == 128 else "AES-256-GCM"
        block: dict[str, Any] = {
            "encryption": {
                "algorithm": algo,
                "key_derivation": "PBKDF2-HMAC-SHA256",
                "context_key": "vault-export",
                "mode": encryption_mode,
                "iterations": 100_000,
                "salt": base64.b64encode(file_salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "key_bits": key_bits,
            },
            "data": base64.b64encode(cipher).decode("ascii"),
            "integrity": {
                "hash": integrity,
                "hash_algorithm": "SHA256",
                "signature": sign_hex,
            },
        }
        block["encryption"].update(compression_meta)
        return block

    def _encrypt_hybrid_public_key(
        self,
        plain: bytes,
        *,
        recipient_public_key_hex: str,
        export_password: str,
        key_bits: int,
        compression_meta: dict[str, str],
    ) -> dict[str, Any]:
        # EXP-2: гибрид — случайный AES-ключ, обёртка через PBKDF2 от публичного ключа
        file_salt = os.urandom(16)
        nonce = os.urandom(12)
        sym_key = os.urandom(32)
        if key_bits == 128:
            sym_key = sym_key[:16]
        wrap_salt = os.urandom(16)
        wrap_nonce = os.urandom(12)
        plain_buf = bytearray(plain)
        wrap_key = b""
        try:
            cipher = AESGCM(sym_key).encrypt(nonce, bytes(plain_buf), None)
            wrap_key = self._file_key(recipient_public_key_hex, wrap_salt, key_bits)
            wrapped_sym = AESGCM(wrap_key).encrypt(wrap_nonce, sym_key, None)
            integrity = hashlib.sha256(plain_buf).hexdigest()
            sign_hex = self._sign_plaintext(bytes(plain_buf), export_password)
        finally:
            wipe_sensitive(sym_key)
            if wrap_key:
                wipe_sensitive(wrap_key)
            wipe_sensitive(plain_buf)
        algo = "AES-128-GCM" if key_bits == 128 else "AES-256-GCM"
        return {
            "encryption": {
                "algorithm": f"PBKDF2-wrap/{algo}",
                "mode": "public_key",
                "recipient_public_key": recipient_public_key_hex,
                "wrap_salt": base64.b64encode(wrap_salt).decode("ascii"),
                "wrap_nonce": base64.b64encode(wrap_nonce).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "key_bits": key_bits,
            },
            "encrypted_key": base64.b64encode(wrapped_sym).decode("ascii"),
            "data": base64.b64encode(cipher).decode("ascii"),
            "integrity": {
                "hash": integrity,
                "hash_algorithm": "SHA256",
                "signature": sign_hex,
            },
            **compression_meta,
        }

    def _wrap_result(
        self,
        encrypted: dict[str, Any],
        *,
        fmt: str,
        entry_ids: Optional[list[int]],
        entry_count: int,
        export_mode_label: str,
    ) -> dict[str, Any]:
        # FMT-1: нативная обёртка cryptosafe_export
        out = build_native_export_package(encrypted)
        out["format"] = fmt
        out["export_mode"] = export_mode_label
        out["entry_count"] = entry_count
        if entry_ids is not None:
            out["entry_ids"] = [int(x) for x in entry_ids]
        return out

    def _log_export(
        self,
        *,
        fmt: str,
        entry_count: int,
        export_mode: str,
        file_path: str = "",
        package: Optional[dict[str, Any]] = None,
    ) -> None:
        # EXP-4: аудит + DB-2
        details = {
            "format": fmt,
            "entry_count": entry_count,
            "export_mode": export_mode,
            "file_path": file_path,
        }
        get_event_bus().publish("VaultExported", details)
        checksum = ""
        encryption_used = "plaintext" if fmt in ("csv", "lastpass_csv") else "encrypted"
        if package:
            block = package.get("integrity") or {}
            checksum = str(block.get("hash", "") or package.get("tamper_evidence", "") or "")
            enc = package.get("encryption") or {}
            if isinstance(enc, dict) and enc.get("algorithm"):
                encryption_used = str(enc.get("algorithm"))
        file_size = 0
        if file_path:
            try:
                file_size = Path(file_path).stat().st_size
            except OSError:
                file_size = 0
        io_storage.insert_io_history(
            operation_type=io_storage.OP_EXPORT,
            file_format=fmt,
            encryption_used=encryption_used,
            entry_count=entry_count,
            file_size=file_size,
            checksum=checksum or "n/a",
            verification_status=io_storage.VERIFY_OK,
        )

    def export_vault(
        self,
        entry_ids: Optional[list[int]] = None,
        *,
        master_password: str,
        export_password: str = "",
        recipient_public_key_hex: str = "",
        fmt: str = "encrypted_json",
        include_notes: bool = True,
        exclude_fields: Optional[list[str]] = None,
        key_bits: int = 256,
        compress: bool = False,
        encrypt_csv: bool = True,
        skip_audit: bool = False,
    ) -> dict[str, Any]:
        # главный метод экспорта
        """Export vault."""
        check_io_aborted()
        if not is_session_unlocked():
            raise PermissionError("сессия заблокирована")
        if not verify_master_password(master_password):
            raise ValueError("неверный мастер-пароль")

        # ARC-2: ключ vault только для чтения записей, не для шифрования файла
        vault_key = self._keys.get_vault_encryption_key(master_password=master_password)
        export_ctx_key = derive_export_key(master_password)
        # SEC-3: отдельный контекст HKDF vault-export
        if not keys_differ(vault_key, export_ctx_key):
            raise ValueError("ключ экспорта не должен совпадать с ключом vault")
        wipe_sensitive(export_ctx_key)

        if key_bits not in (128, 256):
            raise ValueError("key_bits должен быть 128 или 256")

        entries = self._get_entries_for_export(entry_ids)
        entries = self._apply_field_options(
            entries,
            include_notes=include_notes,
            exclude_fields=exclude_fields,
        )
        export_mode_label = "full" if entry_ids is None else "selective"

        # EXP-1 / SEC-1: plaintext CSV / LastPass для миграции — только master_password (EXP-4)
        if fmt in ("csv", "lastpass_csv") and not encrypt_csv:
            body_fmt = "lastpass_csv" if fmt == "lastpass_csv" else "csv"
            body = self._build_body(entries, body_fmt)
            result = {
                "package_version": _PACKAGE_VERSION,
                "format": body_fmt,
                "plaintext": True,
                "metadata": {
                    "source_application": _SOURCE_APP,
                    "export_mode": export_mode_label,
                    "entry_count": len(entries),
                },
                "csv_body": body["csv_body"],
                "entry_count": len(entries),
                "export_mode": export_mode_label,
            }
            if not skip_audit:
                self._log_export(
                    fmt=body_fmt,
                    entry_count=len(entries),
                    export_mode=export_mode_label,
                    package=result,
                )
            return result

        # SEC-1: зашифрованный экспорт — пароль файла или публичный ключ (EXP-2)
        use_public = bool(recipient_public_key_hex.strip())
        if use_public and not export_password:
            export_password = master_password
        if not use_public and not export_password:
            raise ValueError("нужен export_password или recipient_public_key_hex")

        body_fmt = fmt
        if fmt == "csv_encrypted":
            body_fmt = "csv"
        if fmt == "lastpass_csv_encrypted":
            body_fmt = "lastpass_csv"
        if fmt in ("encrypted_json",):
            export_data = self._prepare_export_data(entries)
        else:
            export_data = self._build_body(entries, body_fmt)
        compression_meta = {"compression": "gzip" if compress else "none"}

        if use_public:
            if recipient_public_key_hex.strip().startswith("-----BEGIN"):
                encrypted = self._encrypt_with_public_key(
                    export_data,
                    recipient_public_key_hex.strip().encode("utf-8"),
                    export_password=export_password,
                    key_bits=key_bits,
                )
            else:
                plain, compression_meta = self._plain_bytes(export_data, compress=compress)
                encrypted = self._encrypt_hybrid_public_key(
                    plain,
                    recipient_public_key_hex=recipient_public_key_hex.strip(),
                    export_password=export_password,
                    key_bits=key_bits,
                    compression_meta=compression_meta,
                )
        else:
            encrypted = self._encrypt_with_password(
                export_data,
                export_password,
                export_password=export_password,
                key_bits=key_bits,
                compression_meta=compression_meta if compress else None,
            )

        out_fmt = fmt
        if fmt == "csv_encrypted":
            out_fmt = "csv_encrypted"
        if fmt == "lastpass_csv_encrypted":
            out_fmt = "lastpass_csv_encrypted"
        result = self._wrap_result(
            encrypted,
            fmt=out_fmt,
            entry_ids=entry_ids,
            entry_count=len(entries),
            export_mode_label=export_mode_label,
        )
        if not skip_audit:
            self._log_export(
                fmt=out_fmt,
                entry_count=len(entries),
                export_mode=export_mode_label,
                package=result,
            )
        return result

    def export_vault_by_query(
        self,
        query: str,
        *,
        master_password: str,
        export_password: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        # INT-1: выборочный экспорт по поисковому запросу vault
        """Export vault by query."""
        ids = self.pick_entry_ids_by_query(query)
        return self.export_vault(
            ids,
            master_password=master_password,
            export_password=export_password,
            **kwargs,
        )

    def export_vault_to_file(
        self,
        file_path: str | Path,
        entry_ids: Optional[list[int]] = None,
        **kwargs: Any,
    ) -> Path:
        # EXP-4: запись через временный файл, затем удаление temp
        """Export vault to file."""
        path = Path(file_path)
        temp_path: Optional[Path] = None
        try:
            fd, temp_name = tempfile.mkstemp(suffix=".export.tmp", prefix="cryptosafe_")
            os.close(fd)
            temp_path = Path(temp_name)
            call_kwargs = dict(kwargs)
            call_kwargs["skip_audit"] = True
            package = self.export_vault(entry_ids, **call_kwargs)
            temp_path.write_text(
                json.dumps(package, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(temp_path.read_text(encoding="utf-8"), encoding="utf-8")
            self._log_export(
                fmt=str(kwargs.get("fmt", "encrypted_json")),
                entry_count=int(package.get("entry_count", 0)),
                export_mode=str(package.get("export_mode", "")),
                file_path=str(path),
                package=package,
            )
            return path
        finally:
            if temp_path is not None and temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
