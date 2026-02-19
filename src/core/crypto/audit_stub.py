# EVT-2: Заглушки журнала аудита подписываются на события и пишут тестовые записи в лог

from src.core.events import (
    get_event_bus,
    ENTRY_ADDED,
    ENTRY_UPDATED,
    ENTRY_DELETED,
    USER_LOGGED_IN,
    USER_LOGGED_OUT,
    CLIPBOARD_COPIED,
    CLIPBOARD_CLEARED,
)


def _write_audit(action: str, entry_id=None, details: str = ""):
    """Пишет запись в audit_log (заглушка — тестовые записи)."""
    try:
        from src.database.db import get_db
        import datetime
        db = get_db()
        with db.get_connection() as conn:
            conn.execute(
                "INSERT INTO audit_log (action, timestamp, entry_id, details, signature) VALUES (?, ?, ?, ?, ?)",
                (action, datetime.datetime.now(datetime.UTC).isoformat(), entry_id, details, "stub")
            )
    except Exception:
        pass


def _on_entry_added(entry_id=None, **kwargs):
    _write_audit(ENTRY_ADDED, entry_id=entry_id, details="Entry added (stub)")

def _on_entry_updated(entry_id=None, **kwargs):
    _write_audit(ENTRY_UPDATED, entry_id=entry_id, details="Entry updated (stub)")

def _on_entry_deleted(entry_id=None, **kwargs):
    _write_audit(ENTRY_DELETED, entry_id=entry_id, details="Entry deleted (stub)")

def _on_user_logged_in(**kwargs):
    _write_audit(USER_LOGGED_IN, details="User logged in (stub)")

def _on_user_logged_out(**kwargs):
    _write_audit(USER_LOGGED_OUT, details="User logged out (stub)")

def _on_clipboard_copied(**kwargs):
    _write_audit(CLIPBOARD_COPIED, details="Clipboard copied (stub)")

def _on_clipboard_cleared(**kwargs):
    _write_audit(CLIPBOARD_CLEARED, details="Clipboard cleared (stub)")


def register_audit_handlers():
    """Подписка заглушек аудита на все события."""
    bus = get_event_bus()
    bus.subscribe(ENTRY_ADDED, _on_entry_added)
    bus.subscribe(ENTRY_UPDATED, _on_entry_updated)
    bus.subscribe(ENTRY_DELETED, _on_entry_deleted)
    bus.subscribe(USER_LOGGED_IN, _on_user_logged_in)
    bus.subscribe(USER_LOGGED_OUT, _on_user_logged_out)
    bus.subscribe(CLIPBOARD_COPIED, _on_clipboard_copied)
    bus.subscribe(CLIPBOARD_CLEARED, _on_clipboard_cleared)
