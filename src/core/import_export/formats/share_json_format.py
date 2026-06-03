from __future__ import annotations

# Sprint 6: формат cryptosafe_share (FMT-2)

from datetime import datetime, timezone
from typing import Any

SHARE_VERSION = "1.0"
SHARE_ENTRY_FIELDS = ["title", "username", "password", "url", "notes", "category", "tags"]


def _utc_now_iso() -> str:
    # created_at / expires_at в метаданных share
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_share_entry_only(entry: dict[str, Any]) -> dict[str, str]:
    # FMT-2: только нужные поля записи
    """Build share entry only."""
    return {
        "title": str(entry.get("title", "") or ""),
        "username": str(entry.get("username", "") or ""),
        "password": str(entry.get("password", "") or ""),
        "url": str(entry.get("url", "") or ""),
        "notes": str(entry.get("notes", "") or ""),
        "category": str(entry.get("category", "") or ""),
        "tags": str(entry.get("tags", "") or ""),
    }


def build_share_metadata(
    *,
    recipient: str,
    sharer: str,
    permission: str,
    expires_at: str,
    encryption_method: str,
) -> dict[str, str]:
    # FMT-2: короткие метаданные share
    """Build share metadata."""
    return {
        "recipient": str(recipient),
        "sharer": str(sharer),
        "permission": str(permission),
        "expires_at": str(expires_at),
        "encryption_method": str(encryption_method),
    }


def build_share_plaintext_package(
    entry: dict[str, Any],
    metadata: dict[str, str],
) -> dict[str, Any]:
    # FMT-2: заголовок без шифрования (только для учебных/внутренних сценариев)
    """Build share plaintext package."""
    return {
        "version": SHARE_VERSION,
        "cryptosafe_share": True,
        "timestamp": _utc_now_iso(),
        "header": {"encrypted": False},
        "entry": build_share_entry_only(entry),
        "metadata": metadata,
    }


def build_share_encrypted_package(encrypted_block: dict[str, Any]) -> dict[str, Any]:
    # FMT-2: как FMT-1, но cryptosafe_share и header.encrypted=true
    # копируем encryption целиком (hybrid, ephemeral_public_key_pem, context_key — для CRY)
    """Build share encrypted package."""
    encryption = dict(encrypted_block.get("encryption") or {})
    integrity_src = encrypted_block.get("integrity") or {}
    sig_src = encrypted_block.get("signature") or {}
    signature_value = str(sig_src.get("value", "") or integrity_src.get("signature", "") or "")
    package: dict[str, Any] = {
        "version": SHARE_VERSION,
        "cryptosafe_share": True,
        "timestamp": _utc_now_iso(),
        "header": {"encrypted": True},
        "encryption": encryption,
        "data": str(encrypted_block.get("data", "") or ""),
        "integrity": {
            "hash": str(integrity_src.get("hash", "") or ""),
            "signature": signature_value,
        },
    }
    if encrypted_block.get("encrypted_key"):
        package["encrypted_key"] = encrypted_block.get("encrypted_key")
    if encrypted_block.get("tamper_evidence"):
        package["tamper_evidence"] = encrypted_block.get("tamper_evidence")
    return package


def is_share_package(data: dict[str, Any]) -> bool:
    """Is share package."""
    return bool(data.get("cryptosafe_share"))


def parse_share_plaintext(data: dict[str, Any]) -> dict[str, Any]:
    # расшифрованный share без AES
    """Parse share plaintext."""
    if data.get("header", {}).get("encrypted") is not False:
        raise ValueError("ожидался plaintext share")
    entry = data.get("entry") or {}
    meta = data.get("metadata") or {}
    if not isinstance(entry, dict):
        raise ValueError("нет entry")
    body = {
        "version": data.get("version", SHARE_VERSION),
        "format": "cryptosafe_share",
        "entry": build_share_entry_only(entry),
        "recipient": meta.get("recipient", ""),
        "sharer": meta.get("sharer", ""),
        "permission": meta.get("permission", "read_only"),
        "expires_at": meta.get("expires_at", ""),
        "encryption_method": meta.get("encryption_method", ""),
    }
    return body
