from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from src.core.crypto.authentication import is_session_unlocked
from src.core.events import get_event_bus
from src.core.key_manager import KeyManager
from src.core.vault.encryption_service import VaultEncryptionService
from src.core.vault.search_index import build_search_text
from src.core.security.integration import secure_contains
from src.database.db import Database


def _coerce_encrypted_blob(raw) -> bytes:
    # SQLite BLOB / memoryview / legacy TEXT → bytes
    if raw is None:
        return b""
    if isinstance(raw, memoryview):
        return raw.tobytes()
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return b""
        try:
            return bytes.fromhex(text)
        except ValueError:
            return text.encode("utf-8", errors="replace")
    return bytes(raw)


@dataclass
class VaultEntry:
    """Публичный класс VaultEntry."""
    id: Optional[int]
    title: str
    username: str
    password: str
    url: str
    notes: str
    tags: str
    created_at: str
    updated_at: str


class EntryManager:
    # Контроллер CRUD для vault_entries.

    """Публичный класс EntryManager."""
    def __init__(self, db: Optional[Database] = None) -> None:
        """Создать менеджер записей."""
        self._db = db or Database()
        self._crypto = VaultEncryptionService()
        self._keys = KeyManager()
        self._bus = get_event_bus()

    def get_all_entries_encrypted(self) -> list[dict]:
        """Вернуть записи без расшифровки."""
        conn = self._db.create_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, encrypted_data, created_at, updated_at, tags FROM vault_entries ORDER BY id DESC"
            )
            rows = cur.fetchall()
            result: list[dict] = []
            for r in rows:
                result.append(
                    {
                        "id": int(r[0]),
                        "encrypted_data": _coerce_encrypted_blob(r[1]),
                        "created_at": r[2] or "",
                        "updated_at": r[3] or "",
                        "tags": r[4] or "",
                    }
                )
            return result
        finally:
            conn.close()

    def get_all_entries(self, *, skip_invalid: bool = True) -> list[dict]:
        """Вернуть все записи как dict с расшифровкой."""
        if not is_session_unlocked():
            raise PermissionError("сессия заблокирована")

        key = self._keys.get_vault_encryption_key()

        conn = self._db.create_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, encrypted_data, created_at, updated_at, tags FROM vault_entries ORDER BY id DESC")
            rows = cur.fetchall()
            result: list[dict] = []
            for r in rows:
                entry_id = int(r[0])
                blob = _coerce_encrypted_blob(r[1])
                if len(blob) < 13:
                    if skip_invalid:
                        continue
                    raise ValueError(f"запись {entry_id}: повреждённые данные (слишком короткий BLOB)")
                try:
                    payload = self._crypto.decrypt_entry(blob, key)
                except Exception as exc:
                    if skip_invalid:
                        continue
                    raise ValueError(f"запись {entry_id}: не удалось расшифровать") from exc
                data = payload.get("data") or {}
                if not isinstance(data, dict):
                    data = {}
                item = {
                    "id": entry_id,
                    "created_at": r[2] or payload.get("created_at", ""),
                    "updated_at": r[3] or "",
                    "tags": r[4] or data.get("tags", ""),
                }
                item.update(data)
                result.append(item)
            return result
        finally:
            conn.close()

    def list_entries(self) -> list[tuple[int, str, str, str]]:
        """Вернуть список для старой таблицы GUI."""
        items = self.get_all_entries()
        result: list[tuple[int, str, str, str]] = []
        for it in items:
            result.append(
                (
                    int(it.get("id", 0)),
                    str(it.get("title", "") or ""),
                    str(it.get("username", "") or ""),
                    str(it.get("url", "") or ""),
                )
            )
        return result

    def get_entry(self, entry_id: int) -> dict:
        """Вернуть одну запись по id."""
        if not is_session_unlocked():
            raise PermissionError("сессия заблокирована")

        key = self._keys.get_vault_encryption_key()

        conn = self._db.create_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, encrypted_data, created_at, updated_at, tags FROM vault_entries WHERE id = ?",
                (int(entry_id),),
            )
            row = cur.fetchone()
            if row is None:
                raise ValueError("операция не выполнена")
            blob = _coerce_encrypted_blob(row[1])
            if len(blob) < 13:
                raise ValueError(f"запись {entry_id}: повреждённые данные (слишком короткий BLOB)")
            try:
                payload = self._crypto.decrypt_entry(blob, key)
            except Exception as exc:
                raise ValueError(f"запись {entry_id}: не удалось расшифровать") from exc
            data = payload.get("data") or {}
            if not isinstance(data, dict):
                data = {}
            item = {
                "id": int(row[0]),
                "created_at": row[2] or payload.get("created_at", ""),
                "updated_at": row[3] or "",
                "tags": row[4] or data.get("tags", ""),
            }
            item.update(data)
            self._bus.publish("EntryRead", {"entry_id": int(entry_id), "source": "vault"})
            return item
        finally:
            conn.close()

    def create_entry(self, data_dict: dict, master_password: str = "") -> VaultEntry:
        """Создать новую запись."""
        if not is_session_unlocked():
            raise PermissionError("сессия заблокирована")

        key = self._keys.get_vault_encryption_key(master_password=master_password)

        payload = dict(data_dict or {})
        payload.setdefault("title", "")
        payload.setdefault("username", "")
        payload.setdefault("password", "")
        payload.setdefault("url", "")
        payload.setdefault("notes", "")
        payload.setdefault("category", "")
        payload.setdefault("version", 1)
        payload.setdefault("totp_secret", "")
        payload.setdefault("sharing_metadata", {})
        tags = str(payload.get("tags", "") or "")

        now = datetime.utcnow().isoformat()
        enc_blob = self._crypto.encrypt_entry(payload, key, created_at=now, version=int(payload.get("version", 1) or 1))

        conn = self._db.create_connection()
        try:
            cur = conn.cursor()
            try:
                cur.execute("BEGIN")
                cur.execute(
                    """
                    INSERT INTO vault_entries
                        (encrypted_data, created_at, updated_at, tags)
                    VALUES (?, ?, ?, ?)
                    """,
                    (enc_blob, now, now, tags),
                )
                new_id = int(cur.lastrowid)
                conn.commit()
            except Exception:
                conn.rollback()
                raise

            entry = VaultEntry(
                id=new_id,
                title=str(payload.get("title", "") or ""),
                username=str(payload.get("username", "") or ""),
                password=str(payload.get("password", "") or ""),
                url=str(payload.get("url", "") or ""),
                notes=str(payload.get("notes", "") or ""),
                tags=tags,
                created_at=now,
                updated_at=now,
            )

            self._bus.publish("EntryCreated", {"entry_id": new_id})
            self._bus.publish("EntryAdded", {"entry_id": new_id})

            return entry
        finally:
            conn.close()

    def update_entry(self, entry_id: int, data_dict: dict, master_password: str = "") -> VaultEntry:
        """Обновить существующую запись."""
        if not is_session_unlocked():
            raise PermissionError("сессия заблокирована")

        current = self.get_entry(int(entry_id))
        created_at = str(current.get("created_at", "") or "")

        key = self._keys.get_vault_encryption_key(master_password=master_password)

        payload = dict(data_dict or {})
        payload.setdefault("title", current.get("title", ""))
        payload.setdefault("username", current.get("username", ""))
        payload.setdefault("password", current.get("password", ""))
        payload.setdefault("url", current.get("url", ""))
        payload.setdefault("notes", current.get("notes", ""))
        payload.setdefault("category", current.get("category", ""))
        payload.setdefault("version", current.get("version", 1))
        payload.setdefault("totp_secret", current.get("totp_secret", ""))
        payload.setdefault("sharing_metadata", current.get("sharing_metadata", {}))
        tags = str(payload.get("tags", current.get("tags", "") or "") or "")

        updated_at = datetime.utcnow().isoformat()
        enc_blob = self._crypto.encrypt_entry(
            payload,
            key,
            created_at=created_at or updated_at,
            version=int(payload.get("version", 1) or 1),
        )

        conn = self._db.create_connection()
        try:
            cur = conn.cursor()
            try:
                cur.execute("BEGIN")
                cur.execute(
                    """
                    UPDATE vault_entries
                    SET encrypted_data = ?, updated_at = ?, tags = ?
                    WHERE id = ?
                    """,
                    (enc_blob, updated_at, tags, int(entry_id)),
                )
                if cur.rowcount == 0:
                    raise ValueError("операция не выполнена")
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        finally:
            conn.close()

        entry = VaultEntry(
            id=int(entry_id),
            title=str(payload.get("title", "") or ""),
            username=str(payload.get("username", "") or ""),
            password=str(payload.get("password", "") or ""),
            url=str(payload.get("url", "") or ""),
            notes=str(payload.get("notes", "") or ""),
            tags=tags,
            created_at=created_at or "",
            updated_at=updated_at,
        )

        self._bus.publish("EntryUpdated", {"entry_id": int(entry_id)})
        return entry

    def delete_entry(self, entry_id: int, soft_delete: bool = True) -> None:
        """Удалить запись (с soft delete по умолчанию)."""
        if not is_session_unlocked():
            raise PermissionError("сессия заблокирована")

        conn = self._db.create_connection()
        try:
            cur = conn.cursor()
            try:
                cur.execute("BEGIN")
                cur.execute(
                    "SELECT encrypted_data, tags FROM vault_entries WHERE id = ?",
                    (int(entry_id),),
                )
                row = cur.fetchone()
                if row is None:
                    raise ValueError("операция не выполнена")
                enc_blob = row[0] or b""
                tags = row[1] or ""

                if soft_delete:
                    deleted_at = datetime.utcnow().isoformat()
                    expires_at = (datetime.utcnow().timestamp() + 30 * 24 * 3600)
                    expires_iso = datetime.utcfromtimestamp(expires_at).isoformat()
                    cur.execute(
                        """
                        INSERT OR REPLACE INTO deleted_entries
                            (id, encrypted_data, deleted_at, expires_at, tags)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (int(entry_id), enc_blob, deleted_at, expires_iso, tags),
                    )

                cur.execute("DELETE FROM vault_entries WHERE id = ?", (int(entry_id),))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        finally:
            conn.close()

        self._bus.publish("EntryDeleted", {"entry_id": int(entry_id), "soft_delete": bool(soft_delete)})

    def find_entries_by_query(self, query: str) -> list[dict]:
        # INT-1: выборка записей по подстроке (как поиск в GUI)
        """Find entries by query."""
        needle = (query or "").strip().lower()
        items = self.get_all_entries()
        if not needle:
            return items
        matched: list[dict] = []
        for entry in items:
            if secure_contains(needle, build_search_text(entry)):
                matched.append(entry)
        return matched

