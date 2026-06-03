from __future__ import annotations

# Sprint 6: обмен одной записью (SHR — пакет share, аудит, БД)

import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Union

EntryIdsArg = Union[int, list[int]]

from src.core.crypto.authentication import is_session_unlocked, verify_master_password
from src.core.events import get_event_bus
from src.core.import_export import share_crypto
from src.core.import_export.import_security import wipe_sensitive
from src.core.import_export.importer import sanitize_entry
from src.core.vault.entry_manager import EntryManager
from src.database import io_storage
from src.core.import_export.formats.share_json_format import (
    build_share_encrypted_package,
    build_share_entry_only,
)

PERMISSION_READ_ONLY = "read_only"
PERMISSION_EDITABLE = "editable"

METHOD_PASSWORD = "password"
METHOD_PUBLIC_KEY = "public_key"
METHOD_LINK = "link"

MIN_EXPIRE_DAYS = 1
MAX_EXPIRE_DAYS = 30

_PACKAGE_FORMAT = "cryptosafe_share"
_LINK_PREFIX = "cryptosafe://share/"


def _utc_now_iso() -> str:
    # метка времени UTC для share
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def entries_from_share_body(body: dict[str, Any]) -> list[dict[str, Any]]:
    # одна запись (entry) или несколько (entries)
    """Entries from share body."""
    multi = body.get("entries")
    if isinstance(multi, list) and multi:
        result: list[dict[str, Any]] = []
        for item in multi:
            if isinstance(item, dict):
                result.append(sanitize_entry(item))
        if result:
            return result
    single = body.get("entry")
    if isinstance(single, dict):
        return [sanitize_entry(single)]
    return []


def normalize_entry_ids(entry_id: EntryIdsArg) -> list[int]:
    """Normalize entry ids."""
    if isinstance(entry_id, int):
        ids = [int(entry_id)]
    else:
        ids = [int(x) for x in entry_id]
    ids = [i for i in ids if i > 0]
    if not ids:
        raise ValueError("не выбраны записи")
    return ids


class SharingService:
    # как в примере: entry_manager + шифрование через share_crypto

    """Публичный класс SharingService."""
    def __init__(self, entry_manager: Optional[EntryManager] = None) -> None:
        # entry_manager — чтение записи для share
        self._entries = entry_manager or EntryManager()

    @property
    def entry_manager(self) -> EntryManager:
        # доступ к менеджеру записей
        """Entry manager."""
        return self._entries

    def _get_entry(self, entry_id: str | int) -> dict[str, Any]:
        # запись vault по id
        return self._entries.get_entry(int(entry_id))

    def _filter_entry_for_sharing(self, entry: dict[str, Any], permissions: dict[str, Any]) -> dict[str, str]:
        # как в примере: только поля, разрешённые для share
        filtered = build_share_entry_only(entry)
        if isinstance(permissions, dict) and permissions.get("include_notes") is False:
            filtered["notes"] = ""
        return filtered

    def _clamp_expire_days(self, expire_days: int) -> int:
        # срок share от 1 до 30 дней
        days = int(expire_days)
        if days < MIN_EXPIRE_DAYS:
            days = MIN_EXPIRE_DAYS
        if days > MAX_EXPIRE_DAYS:
            days = MAX_EXPIRE_DAYS
        return days

    def _entry_payload(self, entry_id: int) -> dict[str, str]:
        entry = self._entries.get_entry(int(entry_id))
        # FMT-2: только нужные поля
        return build_share_entry_only(entry)

    def _build_metadata(
        self,
        *,
        entry_id: int,
        recipient: str,
        sharer: str,
        permission: str,
        expire_days: int,
        method: str,
        sender_public_key_pem: str = "",
    ) -> dict[str, Any]:
        expire_at = datetime.now(timezone.utc) + timedelta(days=expire_days)
        meta = {
            "version": "1.0",
            "format": _PACKAGE_FORMAT,
            "entry_id": int(entry_id),
            "recipient": str(recipient),
            "sharer": str(sharer),
            "permission": permission,
            "encryption_method": method,
            "created_at": _utc_now_iso(),
            "expires_at": expire_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if sender_public_key_pem:
            meta["sender_public_key_pem"] = sender_public_key_pem
        return meta

    def _attach_share_link(self, package: dict[str, Any], expire_at: str) -> dict[str, Any]:
        # токен и подсказка URL для доставки по ссылке
        token = secrets.token_hex(16)
        package["share_link"] = {
            "type": "cryptosafe_share_link",
            "token": token,
            "url_hint": _LINK_PREFIX + token,
            "expires_at": expire_at,
        }
        return package

    def _merge_package(self, body: dict[str, Any], encrypted: dict[str, Any], entry_id: int, recipient: str, permission: str) -> dict[str, Any]:
        # собрать финальный JSON пакета share
        package = {
            "package_version": "1.0",
            "format": _PACKAGE_FORMAT,
            "entry_id": int(entry_id),
            "recipient": str(recipient),
            "permission": permission,
        }
        for key in ("encryption", "data", "integrity", "signature", "encrypted_key", "tamper_evidence"):
            if key in encrypted:
                package[key] = encrypted[key]
        return package

    def share_entry(
        self,
        entry_id: str | int,
        recipient: str,
        permissions: dict[str, Any],
        expires_in: int = 7,
        *,
        share_password: str = "",
        method: str = METHOD_PASSWORD,
        recipient_public_key_pem: str = "",
        include_link: bool = False,
    ) -> dict[str, Any]:
        # как в примере: share_id, package, expires_at, permissions
        """Share entry."""
        share_id = secrets.token_hex(16)
        if isinstance(permissions, dict) and permissions.get("editable"):
            permission = PERMISSION_EDITABLE
        else:
            permission = str(permissions.get("permission", PERMISSION_READ_ONLY) or PERMISSION_READ_ONLY)

        package = self._create_share_package(
            int(entry_id),
            recipient,
            permissions,
            expires_in=expires_in,
            share_id=share_id,
            method=method,
            share_password=share_password,
            recipient_public_key_pem=recipient_public_key_pem,
            permission=permission,
            include_link=include_link,
        )
        expires_at = str(package.get("expires_at", "") or "")
        return {
            "share_id": share_id,
            "package": package,
            "expires_at": expires_at,
            "permissions": permissions,
        }

    def _create_share_package(
        self,
        entry_id: int,
        recipient: str,
        permissions: dict[str, Any],
        *,
        expires_in: int = 7,
        share_id: str = "",
        method: str = METHOD_PASSWORD,
        share_password: str = "",
        recipient_public_key_pem: str = "",
        permission: str = PERMISSION_READ_ONLY,
        include_link: bool = False,
    ) -> dict[str, Any]:
        # обёртка share_entry → create_share
        entry = self._get_entry(entry_id)
        filtered = self._filter_entry_for_sharing(entry, permissions)
        package = self.create_share(
            entry_id,
            recipient,
            method=method,
            share_password=share_password,
            recipient_public_key_pem=recipient_public_key_pem,
            expire_days=expires_in,
            permission=permission,
            include_link=include_link,
            share_id=share_id,
        )
        package["share_id"] = share_id or package.get("share_id", "")
        package["permissions"] = permissions
        package["entry"] = filtered
        return package

    def create_share(
        self,
        entry_id: EntryIdsArg,
        recipient: str,
        *,
        method: str = METHOD_PASSWORD,
        share_password: str = "",
        recipient_public_key_pem: str = "",
        recipient_public_key_hex: str = "",
        sender_public_key_pem: str = "",
        sharer: str = "local",
        expire_days: int = 7,
        permission: str = PERMISSION_READ_ONLY,
        include_link: bool = False,
        share_id: str = "",
    ) -> dict[str, Any]:
        # SHR: одна или несколько записей в одном пакете
        """Create share."""
        if not is_session_unlocked():
            raise PermissionError("сессия заблокирована")
        if permission not in (PERMISSION_READ_ONLY, PERMISSION_EDITABLE):
            raise ValueError("permission: read_only или editable")
        if method not in (METHOD_PASSWORD, METHOD_PUBLIC_KEY, METHOD_LINK):
            raise ValueError("неизвестный method")

        entry_ids = normalize_entry_ids(entry_id)
        primary_id = entry_ids[0]

        days = self._clamp_expire_days(expire_days)
        use_method = method
        if use_method == METHOD_LINK:
            use_method = METHOD_PASSWORD
            include_link = True

        body = self._build_metadata(
            entry_id=primary_id,
            recipient=recipient,
            sharer=sharer,
            permission=permission,
            expire_days=days,
            method=use_method,
            sender_public_key_pem=sender_public_key_pem,
        )
        if len(entry_ids) == 1:
            body["entry"] = self._entry_payload(entry_ids[0])
        else:
            body["entries"] = [self._entry_payload(eid) for eid in entry_ids]
            body["entry_ids"] = entry_ids
        sid = share_id.strip() or secrets.token_hex(16)

        recipient_key = recipient_public_key_pem.strip() or recipient_public_key_hex.strip()

        if use_method == METHOD_PUBLIC_KEY:
            if not recipient_key:
                raise ValueError("нужен recipient_public_key_pem")
            encrypted = share_crypto.encrypt_public_key_package(
                body,
                recipient_key,
                sender_public_key_pem=sender_public_key_pem,
                share_password=share_password,
            )
        else:
            if not share_password:
                raise ValueError("нужен share_password")
            encrypted = share_crypto.encrypt_password_package(body, share_password)

        # FMT-2: обёртка cryptosafe_share
        package = build_share_encrypted_package(encrypted)
        package["entry_id"] = int(primary_id)
        if len(entry_ids) > 1:
            package["entry_ids"] = list(entry_ids)
        package["recipient"] = str(recipient)
        package["permission"] = permission
        package["share_id"] = sid
        package["expires_at"] = str(body["expires_at"])
        if include_link:
            package = self._attach_share_link(package, body["expires_at"])
            link_block = package.get("share_link")
            if isinstance(link_block, dict):
                io_storage.save_share_inbox(
                    token=str(link_block.get("token", "") or ""),
                    package=package,
                    expires_at=str(
                        link_block.get("expires_at") or package.get("expires_at", "") or ""
                    ),
                )

        # DB-1: факт share для каждой записи
        for eid in entry_ids:
            io_storage.insert_shared_entry(
                original_entry_id=int(eid),
                encryption_method=use_method,
                recipient_info=str(recipient),
                permissions=str(permission),
                expires_at=str(body["expires_at"]),
            )
        self._log_share_event(
            entry_id=int(primary_id),
            entry_ids=entry_ids,
            recipient=str(recipient),
            method=use_method,
            permission=str(permission),
            expires_at=str(body["expires_at"]),
            has_share_link=bool(package.get("share_link")),
        )
        return package

    def _log_share_event(
        self,
        *,
        entry_id: int,
        entry_ids: list[int],
        recipient: str,
        method: str,
        permission: str,
        expires_at: str,
        has_share_link: bool,
    ) -> None:
        # INT-2: аудит sharing с данными получателя
        get_event_bus().publish(
            "VaultShared",
            {
                "entry_id": int(entry_id),
                "entry_ids": list(entry_ids),
                "entry_count": len(entry_ids),
                "recipient": str(recipient),
                "encryption_method": str(method),
                "permission": str(permission),
                "expires_at": str(expires_at),
                "has_share_link": bool(has_share_link),
            },
        )

    def build_share_package(
        self,
        entry_id: int,
        *,
        share_password: str,
        sharer: str = "local",
        expire_days: int = 7,
        permission: str = PERMISSION_READ_ONLY,
    ) -> dict[str, Any]:
        # удобная обёртка: share только по паролю
        """Build share package."""
        return self.create_share(
            entry_id,
            recipient="local",
            method=METHOD_PASSWORD,
            share_password=share_password,
            sharer=sharer,
            expire_days=expire_days,
            permission=permission,
        )

    def share_to_file(self, file_path: str | Path, entry_id: int, **kwargs: Any) -> Path:
        # сохранить пакет share в JSON-файл
        """Share to file."""
        path = Path(file_path)
        package = self.create_share(entry_id, **kwargs)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(package, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _check_expired(self, meta: dict[str, Any]) -> None:
        # отклонить просроченный share
        expires = str(meta.get("expires_at", "") or "")
        if not expires:
            return
        try:
            exp_dt = datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            return
        if datetime.now(timezone.utc) > exp_dt:
            raise ValueError("срок действия share истёк")

    def open_share_package(
        self,
        package: dict[str, Any],
        *,
        share_password: str = "",
        recipient_private_key_pem: str = "",
    ) -> dict[str, Any]:
        # расшифровать пакет share (пароль или приватный ключ)
        """Open share package."""
        enc = package.get("encryption")
        if not isinstance(enc, dict):
            raise ValueError("нет encryption")
        mode = str(enc.get("mode", METHOD_PASSWORD) or METHOD_PASSWORD)

        if mode == METHOD_PUBLIC_KEY:
            if not recipient_private_key_pem:
                raise ValueError("нужен recipient_private_key_pem")
            plain = share_crypto.decrypt_public_key_package(
                package,
                recipient_private_key_pem,
                share_password=share_password,
            )
        else:
            if not share_password:
                raise ValueError("нужен share_password")
            plain = share_crypto.decrypt_password_package(package, share_password)

        plain_buf = bytearray(plain)
        try:
            body = json.loads(plain_buf.decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError("некорректное тело share")
            self._check_expired(body)
            return body
        finally:
            wipe_sensitive(plain_buf)  # SEC-4

    def load_share_from_file(self, file_path: str | Path) -> dict[str, Any]:
        # прочитать JSON share с диска
        """Load share from file."""
        path = Path(file_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("файл share должен быть JSON-объектом")
        return data

    def import_shared_entry(
        self,
        package: dict[str, Any],
        *,
        share_password: str = "",
        recipient_private_key_pem: str = "",
        save_to_vault: bool = True,
        master_password: str = "",
    ) -> dict[str, Any]:
        # импорт записи из share в vault (или только просмотр)
        """Import shared entry."""
        body = self.open_share_package(
            package,
            share_password=share_password,
            recipient_private_key_pem=recipient_private_key_pem,
        )
        entries = entries_from_share_body(body)
        if not entries:
            raise ValueError("нет записей в пакете share")
        permission = str(body.get("permission", PERMISSION_READ_ONLY) or PERMISSION_READ_ONLY)

        result: dict[str, Any] = {
            "saved": False,
            "temporary": True,
            "entry": entries[0],
            "entries": entries,
            "entry_count": len(entries),
            "permission": permission,
            "recipient": body.get("recipient", ""),
            "sharer": body.get("sharer", ""),
            "expires_at": body.get("expires_at", ""),
            "sender_public_key_pem": body.get("sender_public_key_pem", ""),
        }

        if not save_to_vault:
            return result

        if not is_session_unlocked():
            raise PermissionError("сессия заблокирована")
        if not verify_master_password(master_password):
            raise ValueError("неверный мастер-пароль")

        created_ids: list[int] = []
        for entry in entries:
            created = self._entries.create_entry(
                {
                    "title": entry["title"],
                    "username": entry["username"],
                    "password": entry["password"],
                    "url": entry["url"],
                    "notes": entry["notes"],
                    "category": entry.get("category", ""),
                    "tags": entry.get("tags", ""),
                },
                master_password=master_password,
            )
            created_ids.append(int(created.id))
        result["saved"] = True
        result["temporary"] = False
        result["entry_id"] = created_ids[0]
        result["entry_ids"] = created_ids
        return result
