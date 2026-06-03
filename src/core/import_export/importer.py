from __future__ import annotations

# Sprint 6: импорт vault (IMP-1..IMP-4 — форматы, санитизация, merge/replace)

import base64
import gzip
import hashlib
import hmac
import json
import re
import time
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.crypto.authentication import is_session_unlocked, verify_master_password
from src.core.events import get_event_bus
from src.core.import_export.formats.bw_json_format import parse_bitwarden_json
from src.core.import_export.formats.csv_format import parse_csv_text_multi_dialect
from src.core.import_export.formats.json_format import parse_json_dict
from src.core.import_export.formats.native_json_format import get_signature_from_package, is_native_export_package
from src.core.import_export.formats.share_json_format import is_share_package, parse_share_plaintext
from src.core.import_export.formats.lastpass_csv_format import parse_lastpass_csv
from src.core.import_export.import_checkpoint import (
    default_checkpoint_path,
    delete_checkpoint,
    load_checkpoint,
    save_checkpoint,
)
from src.core.import_export.import_errors import (
    CorruptedImportError,
    EncryptionDecryptError,
    FormatDetectionError,
    PartialImportError,
    RECOVERY_MANUAL_FORMAT,
    RECOVERY_RESUME_CHECKPOINT,
    build_error_report,
)
from src.core.security.side_channel_protection import constant_time_compare
from src.core.import_export.import_security import scan_import_text, wipe_sensitive
from src.core.security.integration import check_io_aborted
from src.core.import_export.io_keys import derive_export_key, derive_file_key_from_salt
from src.core.vault.entry_manager import EntryManager
from src.database import io_storage

# IMP-4: лимиты по умолчанию
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
DEFAULT_IMPORT_TIMEOUT_SEC = 30

# IMP-3: режимы импорта
MODE_MERGE = "merge"
MODE_REPLACE = "replace"
MODE_DRY_RUN = "dry_run"

# IMP-2: обработка дубликатов
DUP_SKIP = "skip"
DUP_UPDATE = "update"
DUP_ALLOW = "allow"

_SCRIPT_PATTERN = re.compile(r"<\s*script", re.IGNORECASE)


def sanitize_text(value: str, *, max_len: int = 4096) -> str:
    # IMP-2: убрать управляющие символы и обрезать длину
    """Sanitize text."""
    if not value:
        return ""
    cleaned = value.replace("\x00", "")
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", cleaned)
    if _SCRIPT_PATTERN.search(cleaned):
        cleaned = _SCRIPT_PATTERN.sub("", cleaned)
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len]
    return cleaned


def sanitize_entry(item: dict[str, Any]) -> dict[str, str]:
    # одна запись для импорта
    """Sanitize entry."""
    return {
        "title": sanitize_text(str(item.get("title", "") or ""), max_len=256),
        "username": sanitize_text(str(item.get("username", "") or "")),
        "password": sanitize_text(str(item.get("password", "") or "")),
        "url": sanitize_text(str(item.get("url", "") or ""), max_len=2048),
        "notes": sanitize_text(str(item.get("notes", "") or ""), max_len=8192),
        "category": sanitize_text(str(item.get("category", "") or ""), max_len=256),
        "tags": sanitize_text(str(item.get("tags", "") or ""), max_len=512),
    }


class ImportSandbox:
    # IMP-4: «песочница» — только чтение/разбор, лимит времени и размера

    """Публичный класс ImportSandbox."""
    def __init__(
        self,
        *,
        max_bytes: int = DEFAULT_MAX_FILE_BYTES,
        timeout_sec: float = DEFAULT_IMPORT_TIMEOUT_SEC,
    ) -> None:
        # лимиты размера файла и времени разбора
        self._max_bytes = max_bytes
        self._timeout_sec = timeout_sec
        self._start = time.monotonic()

    def check_time(self) -> None:
        # IMP-4: не дольше 30 с на импорт
        """Check time."""
        if time.monotonic() - self._start > self._timeout_sec:
            raise TimeoutError("импорт прерван по таймауту 30 с")

    def check_size(self, size_bytes: int) -> None:
        # IMP-4: лимит размера файла
        """Check size."""
        if size_bytes > self._max_bytes:
            raise ValueError("файл слишком большой")


class VaultImporter:
    # импорт внешних данных (IMP-1..IMP-4)

    """Публичный класс VaultImporter."""
    def __init__(self, entry_manager: Optional[EntryManager] = None) -> None:
        # EntryManager — запись в vault после разбора
        self._entries = entry_manager or EntryManager()

    def validate_file_size(self, size_bytes: int, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> None:
        # IMP-4: лимит размера
        """Validate file size."""
        if size_bytes > max_bytes:
            raise ValueError("файл слишком большой")

    def detect_format(self, data: dict[str, Any], *, raw_text: str = "") -> str:
        # IMP-1 / ERR-3: автоопределение формата
        """Detect format."""
        if data.get("plaintext") and data.get("csv_body"):
            if str(data.get("format", "") or "") == "lastpass_csv":
                return "lastpass_csv"
            return "csv"
        if is_share_package(data):
            header = data.get("header") or {}
            if header.get("encrypted") is False:
                return "share_plaintext"
            return "share_encrypted"
        if is_native_export_package(data):
            return "encrypted_json"
        enc = data.get("encryption")
        if isinstance(enc, dict) and data.get("data"):
            return "encrypted_json"
        if isinstance(data.get("items"), list):
            return "bitwarden_json"
        body = str(data.get("csv_body", "") or "")
        if body:
            return "csv"
        if raw_text.strip():
            text_head = raw_text.strip()
            # JSON без маркеров — не считать CSV (ERR-3)
            if text_head.startswith("{"):
                return ""
            head = text_head.splitlines()[0].lower()
            if "name" in head and "password" in head and ("url" in head or "username" in head):
                if "extra" in head or "grouping" in head:
                    return "lastpass_csv"
            if ";" in head and "," not in head:
                return "csv_semicolon"
            return "csv"
        if data.get("entries"):
            return "encrypted_json"
        return ""  # ERR-3: неизвестный формат — нужен ручной выбор

    def resolve_import_format(
        self,
        data: dict[str, Any],
        *,
        raw_text: str = "",
        manual_fmt: str = "",
    ) -> str:
        # ERR-3: ручной формат или автоопределение
        """Resolve import format."""
        manual = (manual_fmt or "").strip()
        if manual:
            return manual
        fmt = self.detect_format(data, raw_text=raw_text)
        if not fmt:
            raise FormatDetectionError(
                "не удалось определить формат файла",
            )
        return fmt

    def validate_encryption_block(self, package: dict[str, Any]) -> None:
        # IMP-4: проверить метаданные шифрования до decrypt
        """Validate encryption block."""
        enc = package.get("encryption")
        if not isinstance(enc, dict):
            raise ValueError("нет блока encryption")
        if not enc.get("algorithm"):
            raise ValueError("не указан algorithm")
        mode = str(enc.get("mode", "password") or "password")
        if mode == "public_key":
            if not package.get("encrypted_key"):
                raise ValueError("нет encrypted_key для public_key")
            if not enc.get("recipient_public_key"):
                raise ValueError("нет recipient_public_key")
        else:
            if not enc.get("salt") or not enc.get("nonce"):
                raise ValueError("нет salt или nonce")
        if not package.get("data"):
            raise ValueError("нет зашифрованных data")

    def _file_key(self, password_or_pubkey: str, file_salt: bytes, key_bits: int) -> bytes:
        # ключ AES 128/256 бит из пароля файла
        raw = derive_file_key_from_salt(password_or_pubkey, file_salt)
        if key_bits == 128:
            return raw[:16]
        return raw[:32]

    def _verify_integrity(self, plain: bytes, package: dict[str, Any]) -> None:
        # IMP-2: SHA-256
        block = package.get("integrity") or {}
        expected = str(block.get("hash", "") or "")
        if not expected:
            raise ValueError("нет integrity hash")
        actual = hashlib.sha256(plain).hexdigest()
        if not constant_time_compare(actual, expected):
            raise ValueError("нарушена целостность файла")

    def _verify_signature(self, plain: bytes, package: dict[str, Any], import_password: str) -> None:
        # IMP-2 / FMT-1: подпись в integrity.signature или в signature.value
        expected = get_signature_from_package(package)
        if not expected:
            raise ValueError("нет подписи")
        sign_key = derive_export_key(import_password)
        try:
            actual = hmac.new(sign_key, plain, hashlib.sha256).hexdigest()
            if not constant_time_compare(actual, expected):
                raise ValueError("неверная подпись")
        finally:
            wipe_sensitive(sign_key)

    def _decrypt_password_mode(
        self,
        package: dict[str, Any],
        import_password: str,
        sandbox: ImportSandbox,
    ) -> bytes:
        enc = package["encryption"]
        file_salt = base64.b64decode(str(enc["salt"]))
        nonce = base64.b64decode(str(enc["nonce"]))
        key_bits = int(enc.get("key_bits", 256) or 256)
        file_key = self._file_key(import_password, file_salt, key_bits)
        try:
            cipher = base64.b64decode(str(package["data"]))
            sandbox.check_time()
            plain = AESGCM(file_key).decrypt(nonce, cipher, None)
            compression = str(enc.get("compression", "none") or "none")
            if compression == "gzip":
                plain = gzip.decompress(plain)
            return plain
        finally:
            wipe_sensitive(file_key)

    def _decrypt_public_key_mode(
        self,
        package: dict[str, Any],
        sandbox: ImportSandbox,
    ) -> bytes:
        # расшифровка гибридного пакета (как при экспорте — ключ от pubkey в metadata)
        enc = package["encryption"]
        pub_hex = str(enc.get("recipient_public_key", "") or "")
        if not pub_hex:
            raise ValueError("нет recipient_public_key")
        wrap_salt = base64.b64decode(str(enc["wrap_salt"]))
        wrap_nonce = base64.b64decode(str(enc["wrap_nonce"]))
        nonce = base64.b64decode(str(enc["nonce"]))
        key_bits = int(enc.get("key_bits", 256) or 256)
        wrap_key = self._file_key(pub_hex, wrap_salt, key_bits)
        sym_key = b""
        try:
            wrapped = base64.b64decode(str(package["encrypted_key"]))
            sandbox.check_time()
            sym_key = AESGCM(wrap_key).decrypt(wrap_nonce, wrapped, None)
            cipher = base64.b64decode(str(package["data"]))
            plain = AESGCM(sym_key).decrypt(nonce, cipher, None)
            compression = str(enc.get("compression", "none") or "none")
            if compression == "gzip":
                plain = gzip.decompress(plain)
            return plain
        finally:
            wipe_sensitive(wrap_key)
            if sym_key:
                wipe_sensitive(sym_key)

    def decrypt_package(
        self,
        package: dict[str, Any],
        *,
        import_password: str = "",
        sandbox: Optional[ImportSandbox] = None,
    ) -> dict[str, Any]:
        # IMP-2 / ERR-4: расшифровка; при ошибке plaintext обнуляется, тело не возвращается
        """Decrypt package."""
        box = sandbox or ImportSandbox()
        plain_buf = bytearray()
        try:
            self.validate_encryption_block(package)
            enc = package["encryption"]
            mode = str(enc.get("mode", "password") or "password")
            if mode == "public_key":
                plain = self._decrypt_public_key_mode(package, box)
                if import_password:
                    self._verify_signature(plain, package, import_password)
                    self._verify_integrity(plain, package)
            else:
                if not import_password:
                    raise ValueError("нужен import_password")
                plain = self._decrypt_password_mode(package, import_password, box)
                self._verify_integrity(plain, package)
                self._verify_signature(plain, package, import_password)
            box.check_time()
            plain_buf = bytearray(plain)
            text = plain_buf.decode("utf-8")
            scan_import_text(text)
            body = json.loads(text)
            if not isinstance(body, dict):
                raise ValueError("тело пакета не объект JSON")
            return body
        except EncryptionDecryptError:
            raise
        except Exception as exc:
            raise EncryptionDecryptError(
                f"расшифровка не удалась: {exc}",
                cause=type(exc).__name__,
            ) from exc
        finally:
            if plain_buf:
                wipe_sensitive(plain_buf)

    def parse_entries_from_body(self, body: dict[str, Any], fmt: str) -> list[dict]:
        # IMP-1: разбор форматов в единый список
        """Parse entries from body."""
        if fmt == "csv" or body.get("format") == "csv":
            text = str(body.get("csv_body", "") or "")
            raw = parse_csv_text_multi_dialect(text)
        elif fmt == "bitwarden_json" or isinstance(body.get("items"), list):
            raw = parse_bitwarden_json(body)
        elif fmt == "lastpass_csv":
            raw = parse_lastpass_csv(str(body.get("_raw_csv", "") or body.get("csv_body", "")))
        else:
            raw = parse_json_dict(body)
        return [sanitize_entry(item) for item in raw]

    def validate_entry_constraints(self, item: dict[str, str]) -> None:
        # IMP-2: типы и ограничения
        """Validate entry constraints."""
        for key in ("title", "username", "password", "url", "notes", "tags"):
            if key not in item:
                raise ValueError(f"нет поля {key}")
            if not isinstance(item[key], str):
                raise ValueError(f"поле {key} должно быть строкой")

    def _entry_key(self, item: dict[str, str]) -> tuple[str, str]:
        # ключ для поиска дубликата
        return (item["title"].strip().lower(), item["username"].strip().lower())

    def _build_existing_map(self) -> dict[tuple[str, str], int]:
        # title+username → id для merge и дубликатов
        mapping: dict[tuple[str, str], int] = {}
        for row in self._entries.get_all_entries():
            key = (
                str(row.get("title", "") or "").strip().lower(),
                str(row.get("username", "") or "").strip().lower(),
            )
            entry_id = int(row.get("id", 0) or 0)
            if entry_id > 0:
                mapping[key] = entry_id
        return mapping

    def _clear_all_entries(self) -> int:
        # IMP-3 replace: удалить все записи
        items = self._entries.get_all_entries()
        removed = 0
        for row in items:
            entry_id = int(row.get("id", 0) or 0)
            if entry_id > 0:
                self._entries.delete_entry(entry_id, soft_delete=False)
                removed += 1
        return removed

    def apply_import(
        self,
        items: list[dict[str, str]],
        *,
        master_password: str,
        mode: str = MODE_MERGE,
        on_duplicate: str = DUP_SKIP,
        checkpoint_path: str = "",
        resume: bool = False,
        source_file: str = "",
        source_fmt: str = "",
    ) -> dict[str, Any]:
        # IMP-3: merge / replace / dry_run
        """Apply import."""
        check_io_aborted()
        if not is_session_unlocked():
            raise PermissionError("сессия заблокирована")
        if not verify_master_password(master_password):
            raise ValueError("неверный мастер-пароль")
        if mode not in (MODE_MERGE, MODE_REPLACE, MODE_DRY_RUN):
            raise ValueError("неизвестный режим импорта")
        if on_duplicate not in (DUP_SKIP, DUP_UPDATE, DUP_ALLOW):
            raise ValueError("неизвестная политика дубликатов")

        for item in items:
            self.validate_entry_constraints(item)

        result: dict[str, Any] = {
            "mode": mode,
            "dry_run": mode == MODE_DRY_RUN,
            "added": 0,
            "updated": 0,
            "skipped": 0,
            "removed": 0,
            "preview": [],
        }

        if mode == MODE_DRY_RUN:
            existing = self._build_existing_map()
            for item in items:
                key = self._entry_key(item)
                if key in existing:
                    if on_duplicate == DUP_UPDATE:
                        result["updated"] += 1
                        result["preview"].append({"action": "update", **item})
                    else:
                        result["skipped"] += 1
                        result["preview"].append({"action": "skip", **item})
                else:
                    result["added"] += 1
                    result["preview"].append({"action": "add", **item})
            return result

        if mode == MODE_REPLACE:
            result["removed"] = self._clear_all_entries()

        start_index = 0
        ck_path = (checkpoint_path or "").strip()
        if resume and ck_path:
            ck = load_checkpoint(ck_path)
            start_index = int(ck.get("next_index", 0) or 0)
            prev = ck.get("result") or {}
            if isinstance(prev, dict):
                result["added"] = int(prev.get("added", 0))
                result["updated"] = int(prev.get("updated", 0))
                result["skipped"] = int(prev.get("skipped", 0))
                result["removed"] = int(prev.get("removed", result["removed"]))

        existing = self._build_existing_map()
        try:
            for index in range(start_index, len(items)):
                check_io_aborted()
                item = items[index]
                key = self._entry_key(item)
                payload = {
                    "title": item["title"],
                    "username": item["username"],
                    "password": item["password"],
                    "url": item["url"],
                    "notes": item["notes"],
                    "tags": item.get("tags", ""),
                }
                if key in existing and mode == MODE_MERGE:
                    if on_duplicate == DUP_SKIP:
                        result["skipped"] += 1
                    elif on_duplicate == DUP_UPDATE:
                        self._entries.update_entry(
                            existing[key],
                            payload,
                            master_password=master_password,
                        )
                        result["updated"] += 1
                    else:
                        self._entries.create_entry(payload, master_password=master_password)
                        result["added"] += 1
                        existing[key] = -1
                else:
                    self._entries.create_entry(payload, master_password=master_password)
                    result["added"] += 1
                    if mode == MODE_MERGE:
                        existing[key] = -1

                if ck_path:
                    save_checkpoint(
                        ck_path,
                        file_path=source_file,
                        fmt=source_fmt,
                        mode=mode,
                        next_index=index + 1,
                        result=result,
                    )
        except Exception as exc:
            if ck_path:
                save_checkpoint(
                    ck_path,
                    file_path=source_file,
                    fmt=source_fmt,
                    mode=mode,
                    next_index=index,
                    result=result,
                    failed=True,
                )
            raise PartialImportError(
                f"импорт прерван на записи {start_index + 1}: {exc}",
                checkpoint_path=ck_path,
                applied=result["added"] + result["updated"],
            ) from exc

        if ck_path:
            delete_checkpoint(ck_path)
        return result

    def _log_import(self, details: dict[str, Any], *, file_path: str = "") -> None:
        # IMP-4: аудит + DB-2
        get_event_bus().publish("VaultImported", details)
        file_size = 0
        if file_path:
            try:
                file_size = Path(file_path).stat().st_size
            except OSError:
                file_size = 0
        io_storage.insert_io_history(
            operation_type=io_storage.OP_IMPORT,
            file_format=str(details.get("format", "")),
            encryption_used=str(details.get("encryption_used", "unknown")),
            entry_count=int(details.get("added", 0)) + int(details.get("updated", 0)),
            file_size=file_size,
            checksum=str(details.get("checksum", "n/a")),
            verification_status=io_storage.VERIFY_OK,
        )

    def load_package_from_bytes(
        self,
        raw: bytes,
        sandbox: ImportSandbox,
    ) -> tuple[dict[str, Any], str]:
        # прочитать JSON или CSV текст в песочнице
        """Load package from bytes."""
        sandbox.check_size(len(raw))
        sandbox.check_time()
        text = raw.decode("utf-8")
        stripped = text.strip()
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise CorruptedImportError("повреждённый JSON в файле", stage="json_parse") from exc
            if not isinstance(data, dict):
                raise CorruptedImportError("корень файла должен быть JSON-объектом", stage="json_root")
            # SEC-5: зашифрованный пакет проверяем после decrypt; сырой base64 даёт ложные срабатывания
            enc = data.get("encryption")
            if not (data.get("data") and isinstance(enc, dict)):
                scan_import_text(text)
            fmt = self.detect_format(data, raw_text=text)
            return data, fmt
        scan_import_text(text)  # SEC-5: CSV / LastPass до разбора
        # сырой CSV / LastPass
        fmt = self.detect_format({}, raw_text=text)
        if fmt == "lastpass_csv":
            return {"_raw_csv": text, "format": "lastpass_csv"}, fmt
        return {"csv_body": text, "format": "csv"}, fmt

    def import_from_file(
        self,
        file_path: str | Path,
        *,
        master_password: str,
        import_password: str = "",
        mode: str = MODE_MERGE,
        on_duplicate: str = DUP_SKIP,
        fmt: str = "",
        max_bytes: int = DEFAULT_MAX_FILE_BYTES,
        timeout_sec: float = DEFAULT_IMPORT_TIMEOUT_SEC,
        use_checkpoint: bool = True,
        resume: bool = False,
        checkpoint_path: str = "",
    ) -> dict[str, Any]:
        # главный вход: файл → разбор → импорт
        """Import from file."""
        check_io_aborted()
        path = Path(file_path)
        raw = path.read_bytes()
        sandbox = ImportSandbox(max_bytes=max_bytes, timeout_sec=timeout_sec)
        package, detected_fmt = self.load_package_from_bytes(raw, sandbox)
        use_fmt = self.resolve_import_format(
            package,
            raw_text=raw.decode("utf-8", errors="replace"),
            manual_fmt=fmt,
        )
        ck_path = checkpoint_path.strip()
        if use_checkpoint and mode != MODE_DRY_RUN and not ck_path:
            ck_path = default_checkpoint_path(str(path))

        body = package
        if use_fmt == "share_plaintext":
            body = parse_share_plaintext(package)
            scan_import_text(json.dumps(body.get("entry") or {}, ensure_ascii=False))
            items = [sanitize_entry(body.get("entry") or {})]
            sandbox.check_time()
            apply_result = self.apply_import(
                items,
                master_password=master_password,
                mode=mode,
                on_duplicate=on_duplicate,
                checkpoint_path=ck_path,
                resume=resume,
                source_file=str(path),
                source_fmt=use_fmt,
            )
            apply_result["format"] = use_fmt
            apply_result["file_path"] = str(path)
            return apply_result

        if use_fmt == "share_encrypted" or is_share_package(package):
            body = self.decrypt_package(
                package,
                import_password=import_password,
                sandbox=sandbox,
            )
            use_fmt = "share_encrypted"
            items = [sanitize_entry((body.get("entry") or {}))]
            sandbox.check_time()
            apply_result = self.apply_import(
                items,
                master_password=master_password,
                mode=mode,
                on_duplicate=on_duplicate,
                checkpoint_path=ck_path,
                resume=resume,
                source_file=str(path),
                source_fmt=use_fmt,
            )
            apply_result["format"] = use_fmt
            apply_result["file_path"] = str(path)
            return apply_result

        if use_fmt == "encrypted_json" or (package.get("data") and package.get("encryption")):
            body = self.decrypt_package(
                package,
                import_password=import_password,
                sandbox=sandbox,
            )
            use_fmt = self.detect_format(body)
            body_fmt = str(body.get("format", "") or "")
            if body_fmt == "csv":
                use_fmt = "csv"
            elif body_fmt == "lastpass_csv":
                use_fmt = "lastpass_csv"

        if use_fmt == "csv_semicolon":
            use_fmt = "csv"

        if package.get("plaintext") and package.get("csv_body"):
            body = package
            use_fmt = str(package.get("format", "csv") or "csv")

        sandbox.check_time()
        items = self.parse_entries_from_body(body, use_fmt)
        sandbox.check_time()

        apply_result = self.apply_import(
            items,
            master_password=master_password,
            mode=mode,
            on_duplicate=on_duplicate,
            checkpoint_path=ck_path,
            resume=resume,
            source_file=str(path),
            source_fmt=use_fmt,
        )
        apply_result["format"] = use_fmt
        apply_result["file_path"] = str(path)
        apply_result["entry_count"] = len(items)

        if mode != MODE_DRY_RUN:
            enc_block = package.get("encryption") if isinstance(package.get("encryption"), dict) else {}
            integrity = package.get("integrity") if isinstance(package.get("integrity"), dict) else {}
            self._log_import(
                {
                    "format": use_fmt,
                    "mode": mode,
                    "added": apply_result.get("added", 0),
                    "updated": apply_result.get("updated", 0),
                    "skipped": apply_result.get("skipped", 0),
                    "encryption_used": str(enc_block.get("algorithm", "plaintext")),
                    "checksum": str(integrity.get("hash", "n/a")),
                },
                file_path=str(path),
            )
        return apply_result

    def import_from_file_safe(
        self,
        file_path: str | Path,
        **kwargs: Any,
    ) -> dict[str, Any]:
        # ERR-1: импорт с отчётом вместо «голого» исключения (для GUI)
        """Import from file safe."""
        ck = str(kwargs.get("checkpoint_path", "") or "")
        try:
            result = self.import_from_file(file_path, **kwargs)
            out = dict(result)
            out["success"] = True
            return out
        except Exception as exc:
            report = build_error_report(exc, checkpoint_path=ck)
            out = report.to_dict()
            if RECOVERY_RESUME_CHECKPOINT in out.get("recovery_options", []) and not out.get("checkpoint_path"):
                out["checkpoint_path"] = default_checkpoint_path(str(file_path))
            return out

    def import_package(
        self,
        package: dict[str, Any],
        *,
        master_password: str,
        import_password: str = "",
        mode: str = MODE_MERGE,
        on_duplicate: str = DUP_SKIP,
        fmt: str = "",
    ) -> dict[str, Any]:
        # импорт из уже загруженного dict (без файла)
        """Import package."""
        sandbox = ImportSandbox()
        detected = self.resolve_import_format(package, manual_fmt=fmt)
        body = package
        if detected == "encrypted_json" or (package.get("data") and package.get("encryption")):
            body = self.decrypt_package(
                package,
                import_password=import_password,
                sandbox=sandbox,
            )
            detected = self.detect_format(body)
        if package.get("plaintext") and package.get("csv_body"):
            body = package
            detected = "csv"
        items = self.parse_entries_from_body(body, detected)
        result = self.apply_import(
            items,
            master_password=master_password,
            mode=mode,
            on_duplicate=on_duplicate,
        )
        result["format"] = detected
        result["entry_count"] = len(items)
        if mode != MODE_DRY_RUN:
            self._log_import(
                {
                    "format": detected,
                    "mode": mode,
                    "added": result.get("added", 0),
                    "updated": result.get("updated", 0),
                    "skipped": result.get("skipped", 0),
                }
            )
        return result
