from __future__ import annotations

# Sprint 6: JSON тела vault (FMT / EXP)

import json
from datetime import datetime, timezone
from typing import Any


def _utc_now_iso() -> str:
    # exported_at в ISO 8601 UTC
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def entries_to_json_dict(entries: list[dict], *, source_app: str = "CryptoSafe Manager") -> dict[str, Any]:
    # собрать тело экспорта с метаданными (EXP-2 — позже расширим)
    """Entries to json dict."""
    clean_entries = []
    for item in entries:
        clean_entries.append(
            {
                "id": item.get("id"),
                "title": str(item.get("title", "") or ""),
                "username": str(item.get("username", "") or ""),
                "password": str(item.get("password", "") or ""),
                "url": str(item.get("url", "") or ""),
                "notes": str(item.get("notes", "") or ""),
                "tags": str(item.get("tags", "") or ""),
                "created_at": str(item.get("created_at", "") or ""),
                "updated_at": str(item.get("updated_at", "") or ""),
            }
        )
    return {
        "version": "1.0",
        "format": "cryptosafe_vault_json",
        "exported_at": _utc_now_iso(),
        "source_application": source_app,
        "entry_count": len(clean_entries),
        "entries": clean_entries,
    }


def parse_json_dict(data: dict[str, Any]) -> list[dict]:
    # разобрать импортированный JSON в список записей
    """Parse json dict."""
    raw = data.get("entries", [])
    if not isinstance(raw, list):
        return []
    result: list[dict] = []
    for item in raw:
        if isinstance(item, dict):
            result.append(item)
    return result
