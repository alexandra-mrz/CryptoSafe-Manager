from __future__ import annotations

# COMP-1..COMP-4: стандарты журнала аудита

import json
from datetime import datetime, timezone

from src.core.audit.log_entry import parse_log_rows
from src.core.audit.log_storage import get_retention_policy

# COMP-2: источник времени — системные часы в UTC
AUDIT_TIME_SOURCE = "system_utc"

_CEF_VENDOR = "CryptoSafe"
_CEF_PRODUCT = "Manager"
_CEF_VERSION = "1"

_SEVERITY_NUM = {
    "INFO": "3",
    "WARN": "6",
    "ERROR": "8",
    "CRITICAL": "10",
}


def get_audit_timestamp() -> str:
    # COMP-2: ISO 8601 с часовым поясом UTC
    """Get audit timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def format_cef(entry: dict) -> str:
    # COMP-1: Common Event Format (упрощённый)
    """Format cef."""
    event_type = str(entry.get("event_type", "unknown"))
    severity = _SEVERITY_NUM.get(str(entry.get("severity", "INFO")), "3")
    parts = [
        f"rt={entry.get('timestamp', '')}",
        f"cat={entry.get('category', '')}",
        f"src={entry.get('source', '')}",
        f"uid={entry.get('user_id', '')}",
    ]
    entry_id = entry.get("entry_id")
    if entry_id is not None:
        parts.append(f"cs1={entry_id}")
    details = entry.get("details")
    if isinstance(details, dict):
        for key, value in details.items():
            safe_key = str(key).replace("=", "_")
            parts.append(f"{safe_key}={value}")
    ext = " ".join(parts)
    return (
        f"CEF:0|{_CEF_VENDOR}|{_CEF_PRODUCT}|{_CEF_VERSION}|"
        f"{event_type}|{event_type}|{severity}|{ext}"
    )


def format_cef_from_row(row: tuple) -> str:
    # COMP-1: CEF-строка из строки БД (для export_cef)
    """Format cef from row."""
    event_type, timestamp, entry_id, details_text, _signature = row
    entry = {
        "event_type": event_type,
        "timestamp": timestamp,
        "entry_id": entry_id,
        "severity": "INFO",
        "category": "",
        "source": "",
        "user_id": "local",
        "details": {},
    }
    try:
        stored = json.loads(details_text)
        body = stored.get("entry_data", stored)
        if isinstance(body, dict):
            entry["event_type"] = str(body.get("event_type", event_type))
            entry["timestamp"] = str(body.get("timestamp", timestamp))
            entry["severity"] = str(body.get("severity", "INFO"))
            entry["category"] = str(body.get("category", ""))
            entry["source"] = str(body.get("source", ""))
            entry["user_id"] = str(body.get("user_id", "local"))
            entry["entry_id"] = body.get("entry_id", entry_id)
            if isinstance(body.get("details"), dict):
                entry["details"] = body["details"]
    except json.JSONDecodeError:
        pass
    return format_cef(entry)


def reconstruct_chronological(items: list[dict]) -> list[dict]:
    # COMP-4: восстановление цепочки событий по sequence_number
    """Reconstruct chronological."""
    def _seq(item: dict) -> int:
        num = item.get("sequence_number")
        if num is None:
            stored = item.get("stored")
            if isinstance(stored, dict):
                num = stored.get("sequence_number")
        try:
            return int(num)
        except (TypeError, ValueError):
            return 0

    return sorted(items, key=_seq)


def fetch_chronological_timeline() -> list[dict]:
    # COMP-4: все записи в хронологическом порядке
    """Fetch chronological timeline."""
    from src.core.audit.audit_logger import fetch_all_rows

    items = parse_log_rows(fetch_all_rows())
    return reconstruct_chronological(items)
