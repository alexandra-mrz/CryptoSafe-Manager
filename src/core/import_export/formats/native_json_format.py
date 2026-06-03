from __future__ import annotations

# Sprint 6: нативный пакет cryptosafe_export (FMT-1)

from datetime import datetime, timezone
from typing import Any

NATIVE_VERSION = "1.0"


def _utc_now_iso() -> str:
    # время экспорта в заголовке пакета
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_native_export_package(data: dict[str, Any]) -> bool:
    # проверка маркера формата
    """Is native export package."""
    return bool(data.get("cryptosafe_export"))


def build_native_export_package(encrypted_block: dict[str, Any]) -> dict[str, Any]:
    # FMT-1: обёртка файла экспорта
    """Build native export package."""
    enc = dict(encrypted_block.get("encryption") or {})
    # в encryption только поля из спецификации + нужные нам mode/compression
    encryption = {
        "algorithm": str(enc.get("algorithm", "AES-256-GCM")),
        "key_derivation": str(enc.get("key_derivation", "PBKDF2-HMAC-SHA256")),
        "iterations": int(enc.get("iterations", 100_000)),
        "salt": str(enc.get("salt", "")),
        "nonce": str(enc.get("nonce", "")),
    }
    if enc.get("mode"):
        encryption["mode"] = enc.get("mode")
    if enc.get("compression"):
        encryption["compression"] = enc.get("compression")

    integrity_src = encrypted_block.get("integrity") or {}
    sig_src = encrypted_block.get("signature") or {}
    signature_value = str(sig_src.get("value", "") or integrity_src.get("signature", "") or "")

    package = {
        "version": NATIVE_VERSION,
        "cryptosafe_export": True,
        "timestamp": _utc_now_iso(),
        "encryption": encryption,
        "data": str(encrypted_block.get("data", "") or ""),
        "integrity": {
            "hash": str(integrity_src.get("hash", "") or ""),
            "signature": signature_value,
        },
    }
    if encrypted_block.get("tamper_evidence"):
        package["tamper_evidence"] = encrypted_block.get("tamper_evidence")
    return package


def get_signature_from_package(package: dict[str, Any]) -> str:
    # FMT-1: подпись в integrity; старый формат — отдельный блок signature
    """Get signature from package."""
    integrity = package.get("integrity") or {}
    if integrity.get("signature"):
        return str(integrity.get("signature"))
    sig = package.get("signature") or {}
    return str(sig.get("value", "") or "")


def get_export_extra_metadata(package: dict[str, Any]) -> dict[str, Any]:
    # доп. поля вне FMT-1 (если были в старом пакете)
    """Get export extra metadata."""
    extra: dict[str, Any] = {}
    for key in ("format", "export_mode", "entry_count", "entry_ids", "metadata"):
        if key in package:
            extra[key] = package[key]
    return extra
