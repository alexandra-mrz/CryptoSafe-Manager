from __future__ import annotations

# EXP-1..EXP-3: экспорт журнала аудита

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.core.audit.audit_logger import AuditLogger, fetch_all_rows
from src.core.audit.audit_security import require_audit_read_access
from src.core.audit.log_formatters import export_csv, export_pdf
from src.core.audit.log_signer import _get_master_salt
from src.core.crypto.authentication import verify_master_password
from src.core.crypto.key_derivation import derive_key_pbkdf2
from src.database.db import get_default_database

_EXPORT_HKDF_INFO = b"export-enc"


def _utc_now_iso() -> str:
    # время в метаданных экспорта
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def derive_export_key(password: str) -> bytes:
    # EXP-3: отдельный ключ шифрования экспорта
    """Derive export key."""
    salt = _get_master_salt()
    base = derive_key_pbkdf2(password, salt, length=32, iterations=100_000)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=_EXPORT_HKDF_INFO)
    return hkdf.derive(base)


def _encrypt_bytes(data: bytes, password: str) -> bytes:
    # EXP-3: AES-256-GCM
    key = derive_export_key(password)
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, data, None)
    return nonce + encrypted


def _decrypt_bytes(data: bytes, password: str) -> bytes:
    # расшифровать файл .enc
    key = derive_export_key(password)
    nonce = data[:12]
    body = data[12:]
    return AESGCM(key).decrypt(nonce, body, None)


def load_signed_json_export(file_path: str | Path, password: str) -> dict[str, Any]:
    # TEST-3: чтение экспорта (в т.ч. .enc)
    """Load signed json export."""
    path = Path(file_path)
    raw = path.read_bytes()
    if str(path).endswith(".enc"):
        raw = _decrypt_bytes(raw, password)
    return json.loads(raw.decode("utf-8"))


def rows_from_signed_json(data: dict[str, Any]) -> list[tuple]:
    # TEST-3: строки для проверки целостности после импорта
    """Rows from signed json."""
    rows = []
    for entry in data.get("entries", []):
        stored = entry.get("entry_data", {})
        details_text = json.dumps(stored, ensure_ascii=False, sort_keys=True)
        rows.append(
            (
                str(entry.get("event_type", "")),
                str(entry.get("timestamp", "")),
                entry.get("entry_id"),
                details_text,
                str(entry.get("signature", "")),
            )
        )
    return rows


def verify_export_independent(data: dict[str, Any], signing_key: bytes | None = None) -> tuple[bool, list[str]]:
    # TEST-3: проверка подписей без записи в БД
    """Verify export independent."""
    from src.core.audit.log_signer import verify_bytes
    from src.core.audit.log_verifier import build_signed_payload_bytes, verify_single_row

    errors = []
    rows = rows_from_signed_json(data)
    for index, row in enumerate(rows):
        ok, msg = verify_single_row(row[0], row[1], row[2], row[3], row[4])
        if not ok and signing_key is not None:
            try:
                stored = json.loads(row[3])
                payload = build_signed_payload_bytes(stored)
                if verify_bytes(payload, row[4]):
                    ok = True
            except Exception:
                pass
        if not ok:
            errors.append(f"запись {index + 1}: {msg}")
    if errors:
        return False, errors
    return True, []


def _load_public_key() -> dict[str, str] | None:
    # публичный ключ Ed25519 для проверки экспорта (EXP-2)
    db = get_default_database()
    conn = db.create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT algorithm, public_key FROM audit_public_keys ORDER BY id ASC LIMIT 1"
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {"algorithm": str(row[0]), "public_key_hex": str(row[1])}
    finally:
        conn.close()


def filter_rows_by_date(
    rows: list[tuple],
    date_from: str = "",
    date_to: str = "",
) -> list[tuple]:
    # EXP-4: фильтр по диапазону дат
    """Filter rows by date."""
    if not date_from and not date_to:
        return rows
    result = []
    for row in rows:
        timestamp = str(row[1])
        day = timestamp[:10]
        if date_from and day < date_from:
            continue
        if date_to and day > date_to:
            continue
        result.append(row)
    return result


def build_signed_json(rows: list[tuple], date_from: str, date_to: str) -> dict[str, Any]:
    # EXP-2: подписанный JSON с метаданными и публичным ключом
    """Build signed json."""
    entries = []
    for event_type, timestamp, entry_id, details_text, signature in rows:
        try:
            stored = json.loads(details_text)
        except json.JSONDecodeError:
            stored = {"raw": details_text}
        entries.append(
            {
                "event_type": event_type,
                "timestamp": timestamp,
                "entry_id": entry_id,
                "signature": signature,
                "entry_data": stored,
            }
        )

    range_info = {"from": date_from or None, "to": date_to or None}
    if entries:
        range_info["first_timestamp"] = entries[0]["timestamp"]
        range_info["last_timestamp"] = entries[-1]["timestamp"]

    return {
        "export_metadata": {
            "timestamp": _utc_now_iso(),
            "exporter": "local",
            "range": range_info,
            "entry_count": len(entries),
        },
        "public_key": _load_public_key(),
        "entries": entries,
    }


def _write_file(path: Path, data: bytes, password: str, encrypt: bool) -> Path:
    # записать файл, при необходимости добавить .enc
    out = path
    if encrypt:
        data = _encrypt_bytes(data, password)
        if not str(path).endswith(".enc"):
            out = Path(str(path) + ".enc")
    out.write_bytes(data)
    return out


def log_export_operation(fmt: str, path: str, count: int) -> None:
    # EXP-3: записать экспорт в audit log
    """Log export operation."""
    logger = AuditLogger()
    logger.log_event(
        "AuditExported",
        {
            "source": "log_export",
            "format": fmt,
            "path": path,
            "entry_count": count,
        },
    )


def export_audit_log(
    fmt: str,
    file_path: str | Path,
    master_password: str,
    date_from: str = "",
    date_to: str = "",
    encrypt: bool = True,
) -> str:
    # EXP-1/EXP-3: экспорт после проверки мастер-пароля
    """Export audit log."""
    if not verify_master_password(master_password):
        raise ValueError("неверный мастер-пароль")
    require_audit_read_access()

    rows = filter_rows_by_date(fetch_all_rows(), date_from, date_to)
    path = Path(file_path)

    if fmt == "json":
        payload = build_signed_json(rows, date_from, date_to)
        raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        out_path = str(_write_file(path, raw, master_password, encrypt))
    elif fmt == "csv":
        temp = path.with_suffix(".tmp")
        export_csv(rows, temp)
        raw = temp.read_bytes()
        temp.unlink(missing_ok=True)
        out_path = str(_write_file(path, raw, master_password, encrypt))
    elif fmt == "pdf":
        temp = path.with_suffix(".tmp")
        export_pdf(rows, temp)
        raw = temp.read_bytes()
        temp.unlink(missing_ok=True)
        out_path = str(_write_file(path, raw, master_password, encrypt))
    else:
        raise ValueError("неизвестный формат")

    log_export_operation(fmt, out_path, len(rows))
    return out_path
