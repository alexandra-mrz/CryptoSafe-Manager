from __future__ import annotations

# Утилиты поискового индекса.


def build_search_text(entry: dict, audit_text: str = "") -> str:
    """Собрать строку для поиска по записи."""
    parts = [
        str(entry.get("title", "") or ""),
        str(entry.get("username", "") or ""),
        str(entry.get("url", "") or ""),
        str(entry.get("notes", "") or ""),
        str(entry.get("category", "") or ""),
        str(entry.get("tags", "") or ""),
    ]
    if audit_text:
        parts.append(str(audit_text))
    return " ".join(parts)

