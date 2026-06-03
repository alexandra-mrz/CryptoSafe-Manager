from __future__ import annotations

# Sprint 6: JSON Bitwarden (EXP-1 / IMP-1)

from typing import Any


def entries_to_bitwarden_json(entries: list[dict]) -> dict[str, Any]:
    # упрощённый экспорт items[] как в Bitwarden unencrypted export
    """Entries to bitwarden json."""
    items = []
    for item in entries:
        uri = str(item.get("url", "") or "")
        uris = [{"uri": uri}] if uri else []
        items.append(
            {
                "type": 1,
                "name": str(item.get("title", "") or ""),
                "notes": str(item.get("notes", "") or ""),
                "favorite": False,
                "login": {
                    "username": str(item.get("username", "") or ""),
                    "password": str(item.get("password", "") or ""),
                    "uris": uris,
                },
                "fields": [],
            }
        )
    return {
        "encrypted": False,
        "folders": [],
        "items": items,
    }


def parse_bitwarden_json(data: dict[str, Any]) -> list[dict]:
    # IMP-1: items[] из Bitwarden export
    """Parse bitwarden json."""
    raw_items = data.get("items", [])
    if not isinstance(raw_items, list):
        return []
    result: list[dict] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        login = item.get("login") or {}
        if not isinstance(login, dict):
            login = {}
        uris = login.get("uris") or []
        url = ""
        if isinstance(uris, list) and uris:
            first = uris[0]
            if isinstance(first, dict):
                url = str(first.get("uri", "") or "")
        result.append(
            {
                "title": str(item.get("name", "") or ""),
                "username": str(login.get("username", "") or ""),
                "password": str(login.get("password", "") or ""),
                "url": url,
                "notes": str(item.get("notes", "") or ""),
                "tags": "",
            }
        )
    return result
