from __future__ import annotations

# LOG-1 / LOG-2 / LOG-3: категории, структура записи, маскирование данных

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

# LOG-1: категории событий
CATEGORY_AUTH = "authentication"
CATEGORY_VAULT = "vault"
CATEGORY_CLIPBOARD = "clipboard"
CATEGORY_SYSTEM = "system"
CATEGORY_SECURITY = "security"
CATEGORY_CONFIG = "configuration"

# LOG-1: какое событие к какой категории относится
EVENT_CATEGORY = {
    "UserLoggedIn": CATEGORY_AUTH,
    "UserLoggedOut": CATEGORY_AUTH,
    "LoginFailed": CATEGORY_AUTH,
    "PasswordChanged": CATEGORY_AUTH,
    "EntryCreated": CATEGORY_VAULT,
    "EntryAdded": CATEGORY_VAULT,
    "EntryRead": CATEGORY_VAULT,
    "EntryUpdated": CATEGORY_VAULT,
    "EntryDeleted": CATEGORY_VAULT,
    "ClipboardCopied": CATEGORY_CLIPBOARD,
    "ClipboardCleared": CATEGORY_CLIPBOARD,
    "ClipboardAutoCleared": CATEGORY_CLIPBOARD,
    "AppStartup": CATEGORY_SYSTEM,
    "AppShutdown": CATEGORY_SYSTEM,
    "VaultLocked": CATEGORY_SYSTEM,
    "VaultUnlocked": CATEGORY_SYSTEM,
    "ClipboardSnoopingDetected": CATEGORY_SECURITY,
    "ClipboardCopyBlocked": CATEGORY_SECURITY,
    "SettingsChanged": CATEGORY_CONFIG,
    "AuditExported": CATEGORY_CONFIG,
    "ClipboardError": CATEGORY_CLIPBOARD,
    "VaultSearched": CATEGORY_VAULT,
    "ClipboardMonitorStarted": CATEGORY_CLIPBOARD,
    "ClipboardMonitorStopped": CATEGORY_CLIPBOARD,
    # INT-4: будущие интеграции (Sprint 6/7, TOTP)
    "VaultImported": CATEGORY_VAULT,
    "VaultExported": CATEGORY_VAULT,
    "VaultShared": CATEGORY_VAULT,
    "PanicModeActivated": CATEGORY_SECURITY,
    "SecurityHardening": CATEGORY_SECURITY,
    "TotpCodeGenerated": CATEGORY_VAULT,
}

# LOG-1: источник по умолчанию
EVENT_SOURCE = {
    "UserLoggedIn": "authentication",
    "UserLoggedOut": "authentication",
    "LoginFailed": "authentication",
    "PasswordChanged": "authentication",
    "EntryCreated": "vault",
    "EntryAdded": "vault",
    "EntryRead": "vault",
    "EntryUpdated": "vault",
    "EntryDeleted": "vault",
    "ClipboardCopied": "clipboard",
    "ClipboardCleared": "clipboard",
    "ClipboardAutoCleared": "clipboard",
    "ClipboardError": "clipboard",
    "AppStartup": "system",
    "AppShutdown": "system",
    "VaultLocked": "system",
    "VaultUnlocked": "system",
    "ClipboardSnoopingDetected": "clipboard",
    "ClipboardCopyBlocked": "clipboard",
    "SettingsChanged": "settings",
    "AuditExported": "log_export",
    "VaultSearched": "vault",
    "ClipboardMonitorStarted": "clipboard",
    "ClipboardMonitorStopped": "clipboard",
    "VaultImported": "vault",
    "VaultExported": "vault",
    "VaultShared": "import_export",
    "PanicModeActivated": "system",
    "SecurityHardening": "security",
    "TotpCodeGenerated": "vault",
}

# LOG-3: секретные поля
_SECRET_WORDS = ("password", "master_password", "pwd", "passphrase", "secret", "token")
_KEY_WORDS = ("key", "encryption_key", "private_key", "salt", "nonce", "mnemonic")
_PERSONAL_WORDS = ("email", "phone", "name", "username", "login", "address")


def utc_timestamp() -> str:
    # LOG-2 / COMP-2: ISO 8601 UTC с часовым поясом
    """Utc timestamp."""
    from src.core.audit.audit_compliance import get_audit_timestamp

    return get_audit_timestamp()


def get_event_category(event_type: str) -> str:
    # LOG-1: категория по типу события
    """Get event category."""
    return EVENT_CATEGORY.get(event_type, "other")


def get_event_severity(event_type: str) -> str:
    # LOG-2: INFO, WARN, ERROR, CRITICAL
    """Get event severity."""
    if event_type in ("ClipboardSnoopingDetected",):
        return "CRITICAL"
    if "Failed" in event_type or "Error" in event_type:
        return "ERROR"
    if event_type in ("ClipboardCopyBlocked", "EntryDeleted", "LoginFailed"):
        return "WARN"
    return "INFO"


def _is_secret_key(key: str) -> bool:
    # LOG-3: имя поля похоже на пароль
    low = key.lower()
    for word in _SECRET_WORDS:
        if word in low:
            return True
    return False


def _is_key_field(key: str) -> bool:
    # LOG-3: имя поля похоже на ключ
    low = key.lower()
    for word in _KEY_WORDS:
        if word in low:
            return True
    return False


def _is_personal_key(key: str) -> bool:
    # LOG-3: персональные данные — хешируем
    low = key.lower()
    for word in _PERSONAL_WORDS:
        if word in low:
            return True
    return False


def _hash_personal(value: Any) -> str:
    # LOG-3: персональные данные как хеш
    text = str(value)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return "hash:" + digest[:16]


def anonymize_search_query(query: str) -> str:
    # INT-2: текст поиска только как хеш
    """Anonymize search query."""
    text = (query or "").strip()
    if not text:
        return ""
    return _hash_personal(text)


def sanitize_details(value: Any) -> Any:
    # LOG-3: не писать пароли и ключи в открытом виде
    """Sanitize details."""
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            if _is_secret_key(key):
                clean[key] = "[REDACTED]"
            elif _is_key_field(key):
                clean[key] = "[REDACTED]"
            elif _is_personal_key(key):
                clean[key] = _hash_personal(item)
            else:
                clean[key] = sanitize_details(item)
        return clean
    if isinstance(value, list):
        return [sanitize_details(item) for item in value]
    return value


def normalize_event_type(event_name: str, payload: Any) -> str:
    # LOG-1: автоочистка буфера как отдельный тип
    """Normalize event type."""
    if event_name == "ClipboardCleared" and isinstance(payload, dict):
        if str(payload.get("reason", "")) == "timeout":
            return "ClipboardAutoCleared"
    return event_name


def build_log_entry(event_name: str, payload: Any) -> dict[str, Any]:
    # LOG-2: поля записи
    """Build log entry."""
    event_type = normalize_event_type(event_name, payload)

    entry_id = None
    source = EVENT_SOURCE.get(event_type, "unknown")
    details_data: dict[str, Any] = {}

    if isinstance(payload, dict):
        entry_id = payload.get("entry_id")
        if payload.get("source"):
            source = str(payload.get("source"))
        for key, item in payload.items():
            if key in ("entry_id", "source"):
                continue
            details_data[key] = item
    elif payload is not None:
        details_data = {"value": str(payload)}

    details_data = sanitize_details(details_data)

    return {
        "timestamp": utc_timestamp(),
        "time_source": "system_utc",
        "event_type": event_type,
        "severity": get_event_severity(event_type),
        "user_id": "local",
        "source": source,
        "category": get_event_category(event_type),
        "details": details_data,
        "entry_id": entry_id,
    }


def parse_log_rows(rows: list[tuple]) -> list[dict]:
    # PERF-3/4: разбор строк БД для просмотра и фильтрации
    """Parse log rows."""
    items = []
    for event_type, timestamp, entry_id, details_text, signature in rows:
        try:
            stored = json.loads(details_text)
        except json.JSONDecodeError:
            stored = {}
        entry_data = stored.get("entry_data", stored)
        if not isinstance(entry_data, dict):
            entry_data = {}
        items.append(
            {
                "event_type": str(entry_data.get("event_type", event_type)),
                "timestamp": str(entry_data.get("timestamp", timestamp)),
                "severity": str(entry_data.get("severity", "INFO")),
                "user_id": str(entry_data.get("user_id", "local")),
                "source": str(entry_data.get("source", "")),
                "entry_id": entry_data.get("entry_id", entry_id),
                "sequence_number": stored.get("sequence_number"),
                "previous_hash": str(stored.get("previous_hash", "")),
                "entry_hash": str(stored.get("entry_hash", "")),
                "signature": signature,
                "details": entry_data.get("details", {}),
                "stored": stored,
                "details_text": details_text,
            }
        )
    return items


def filter_audit_items(
    items: list[dict],
    type_value: str = "",
    severity_value: str = "",
    user_value: str = "",
    date_from: str = "",
    date_to: str = "",
    search: str = "",
) -> list[dict]:
    # PERF-3: фильтрация записей
    """Filter audit items."""
    user_value = user_value.strip().lower()
    search = search.strip().lower()
    filtered = []
    for item in items:
        if type_value and item["event_type"] != type_value:
            continue
        if severity_value and item["severity"] != severity_value:
            continue
        if user_value and user_value not in str(item["user_id"]).lower():
            continue
        ts = item["timestamp"][:10]
        if date_from and ts < date_from:
            continue
        if date_to and ts > date_to:
            continue
        if search:
            blob = json.dumps(item, ensure_ascii=False).lower()
            if search not in blob:
                continue
        filtered.append(item)
    return filtered
