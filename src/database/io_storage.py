from __future__ import annotations

# Sprint 6: таблицы import/export (DB-1..DB-3 — share, история, контакты)

import json
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

from src.database.db import get_default_database

OP_EXPORT = "export"
OP_IMPORT = "import"
VERIFY_OK = "ok"
VERIFY_PENDING = "pending"
VERIFY_FAILED = "failed"


def _utc_now_iso() -> str:
    # время UTC для полей created_at / shared_at
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def insert_shared_entry(
    *,
    original_entry_id: int,
    encryption_method: str,
    recipient_info: str,
    permissions: str,
    expires_at: str,
    shared_id: str = "",
) -> str:
    # DB-1: записать факт share
    """Insert shared entry."""
    sid = shared_id or secrets.token_hex(16)
    now = _utc_now_iso()
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO shared_entries (
                shared_id, original_entry_id, encryption_method,
                recipient_info, permissions, shared_at, expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sid,
                int(original_entry_id),
                str(encryption_method),
                str(recipient_info),
                str(permissions),
                now,
                str(expires_at),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return sid


def insert_io_history(
    *,
    operation_type: str,
    file_format: str,
    encryption_used: str,
    entry_count: int,
    file_size: int,
    checksum: str,
    verification_status: str = VERIFY_OK,
) -> int:
    # DB-2: история import или export
    """Insert io history."""
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO import_export_history (
                operation_type, file_format, encryption_used,
                entry_count, file_size, checksum, verification_status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(operation_type),
                str(file_format),
                str(encryption_used),
                int(entry_count),
                int(file_size),
                str(checksum),
                str(verification_status),
                _utc_now_iso(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def upsert_contact(
    *,
    contact_id: str,
    contact_name: str,
    public_key_pem: str,
    public_key_hex: str,
    key_fingerprint: str,
    algorithm: str,
    fingerprint_verified: bool = False,
) -> None:
    # DB-3: сохранить или обновить контакт
    """Upsert contact."""
    now = _utc_now_iso()
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO contacts (
                contact_id, contact_name, public_key_pem, public_key_hex,
                key_fingerprint, algorithm, revoked, fingerprint_verified,
                last_used_at, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
            ON CONFLICT(contact_id) DO UPDATE SET
                contact_name = excluded.contact_name,
                public_key_pem = excluded.public_key_pem,
                public_key_hex = excluded.public_key_hex,
                key_fingerprint = excluded.key_fingerprint,
                algorithm = excluded.algorithm,
                fingerprint_verified = excluded.fingerprint_verified
            """,
            (
                str(contact_id),
                str(contact_name),
                str(public_key_pem),
                str(public_key_hex),
                str(key_fingerprint),
                str(algorithm),
                1 if fingerprint_verified else 0,
                now,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def touch_contact_last_used(contact_id: str) -> None:
    # DB-3: отметить последнее использование контакта
    """Touch contact last used."""
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE contacts SET last_used_at = ? WHERE contact_id = ?",
            (_utc_now_iso(), str(contact_id)),
        )
        conn.commit()
    finally:
        conn.close()


def get_contact_row(contact_id: str) -> Optional[dict[str, Any]]:
    # DB-3: одна строка contacts по id
    """Get contact row."""
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT contact_id, contact_name, public_key_pem, public_key_hex,
                   key_fingerprint, algorithm, revoked, fingerprint_verified, last_used_at
            FROM contacts
            WHERE contact_id = ?
            """,
            (str(contact_id),),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {
            "contact_id": row[0],
            "contact_name": row[1],
            "public_key_pem": row[2],
            "public_key_hex": row[3],
            "key_fingerprint": row[4],
            "algorithm": row[5],
            "revoked": bool(row[6]),
            "fingerprint_verified": bool(row[7]),
            "last_used_at": row[8] or "",
        }
    finally:
        conn.close()


def list_contact_rows(*, include_revoked: bool = False) -> list[dict[str, Any]]:
    # DB-3: все контакты (опционально с отозванными)
    """List contact rows."""
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        if include_revoked:
            cur.execute(
                """
                SELECT contact_id, contact_name, public_key_pem, public_key_hex,
                       key_fingerprint, algorithm, revoked, fingerprint_verified, last_used_at
                FROM contacts
                ORDER BY contact_id ASC
                """
            )
        else:
            cur.execute(
                """
                SELECT contact_id, contact_name, public_key_pem, public_key_hex,
                       key_fingerprint, algorithm, revoked, fingerprint_verified, last_used_at
                FROM contacts
                WHERE revoked = 0
                ORDER BY contact_id ASC
                """
            )
        result: list[dict[str, Any]] = []
        for row in cur.fetchall():
            result.append(
                {
                    "contact_id": row[0],
                    "contact_name": row[1],
                    "public_key_pem": row[2],
                    "public_key_hex": row[3],
                    "key_fingerprint": row[4],
                    "algorithm": row[5],
                    "revoked": bool(row[6]),
                    "fingerprint_verified": bool(row[7]),
                    "last_used_at": row[8] or "",
                }
            )
        return result
    finally:
        conn.close()


def revoke_contact_row(contact_id: str) -> None:
    # DB-3: revoked = 1
    """Revoke contact row."""
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE contacts SET revoked = 1 WHERE contact_id = ?",
            (str(contact_id),),
        )
        if cur.rowcount == 0:
            raise ValueError("контакт не найден")
        conn.commit()
    finally:
        conn.close()


def set_contact_fingerprint_verified(contact_id: str, fingerprint: str) -> bool:
    # DB-3: отметить, что отпечаток проверен пользователем
    """Set contact fingerprint verified."""
    row = get_contact_row(contact_id)
    if row is None:
        return False
    if str(row.get("key_fingerprint", "")) != str(fingerprint).strip():
        return False
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE contacts SET fingerprint_verified = 1 WHERE contact_id = ?",
            (str(contact_id),),
        )
        conn.commit()
    finally:
        conn.close()
    return True


def save_share_inbox(token: str, package: dict[str, Any], *, expires_at: str) -> None:
    # локальный inbox по token (импорт по ссылке на этом ПК)
    """Save share inbox."""
    tok = str(token or "").strip()
    if not tok:
        raise ValueError("пустой token")
    payload = json.dumps(package, ensure_ascii=False)
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO share_inbox (token, package_json, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(token) DO UPDATE SET
                package_json = excluded.package_json,
                expires_at = excluded.expires_at,
                created_at = excluded.created_at
            """,
            (tok, payload, str(expires_at or ""), _utc_now_iso()),
        )
        conn.commit()
    finally:
        conn.close()


def load_share_inbox_by_token(token: str) -> Optional[dict[str, Any]]:
    """Load share inbox by token."""
    tok = str(token or "").strip()
    if not tok:
        return None
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT package_json, expires_at FROM share_inbox WHERE token = ?",
            (tok,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        expires_at = str(row[1] or "")
        if expires_at:
            try:
                exp_dt = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc
                )
                if datetime.now(timezone.utc) > exp_dt:
                    cur.execute("DELETE FROM share_inbox WHERE token = ?", (tok,))
                    conn.commit()
                    return None
            except ValueError:
                pass
        data = json.loads(str(row[0] or "{}"))
        return data if isinstance(data, dict) else None
    finally:
        conn.close()


def list_shared_entries(limit: int = 50) -> list[dict[str, Any]]:
    # DB-1: история share для UI-3
    """List shared entries."""
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT shared_id, original_entry_id, encryption_method, recipient_info,
                   permissions, shared_at, expires_at
            FROM shared_entries
            ORDER BY shared_at DESC
            LIMIT ?
            """,
            (int(limit),),
        )
        rows = []
        for row in cur.fetchall():
            rows.append(
                {
                    "shared_id": row[0],
                    "original_entry_id": row[1],
                    "encryption_method": row[2],
                    "recipient_info": row[3],
                    "permissions": row[4],
                    "shared_at": row[5],
                    "expires_at": row[6],
                }
            )
        return rows
    finally:
        conn.close()


def list_io_history(limit: int = 50) -> list[dict[str, Any]]:
    # DB-2: журнал операций import/export
    """List io history."""
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, operation_type, file_format, encryption_used,
                   entry_count, file_size, checksum, verification_status, created_at
            FROM import_export_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        )
        rows = []
        for row in cur.fetchall():
            rows.append(
                {
                    "id": row[0],
                    "operation_type": row[1],
                    "file_format": row[2],
                    "encryption_used": row[3],
                    "entry_count": row[4],
                    "file_size": row[5],
                    "checksum": row[6],
                    "verification_status": row[7],
                    "created_at": row[8],
                }
            )
        return rows
    finally:
        conn.close()
