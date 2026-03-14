
from __future__ import annotations

# система аудита: обработчики evt-2 пишут события в таблицу audit_log

from datetime import datetime
from typing import Any

from src.core.events import EventBus, get_event_bus
from src.database.db import get_default_database


_db = get_default_database()


def _insert_audit_row(action: str, entry_id: int | None, details: str) -> None:
    conn = _db.create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_log (action, timestamp, entry_id, details, signature)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                action,
                datetime.utcnow().isoformat(timespec="seconds"),
                entry_id,
                details,
                "",  # signature будет добавлена в Sprint 5
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _handle_event(event_name: str, payload: Any) -> None:
    # общий обработчик для большинства событий
    entry_id = None
    if isinstance(payload, dict):
        entry_id = payload.get("entry_id")
    _insert_audit_row(action=event_name, entry_id=entry_id, details=str(payload))


def setup_audit_subscribers(bus: EventBus | None = None) -> None:
    # подписать обработчики на нужные события
    if bus is None:
        bus = get_event_bus()

    # события crud по записям
    bus.subscribe("EntryAdded", _handle_event, async_handler=True)
    bus.subscribe("EntryUpdated", _handle_event, async_handler=True)
    bus.subscribe("EntryDeleted", _handle_event, async_handler=True)

    # события авторизации
    bus.subscribe("UserLoggedIn", _handle_event, async_handler=True)
    bus.subscribe("UserLoggedOut", _handle_event, async_handler=True)

    # события по буферу обмена (для будущих спринтов)
    bus.subscribe("ClipboardCopied", _handle_event, async_handler=True)
    bus.subscribe("ClipboardCleared", _handle_event, async_handler=True)


# при импорте модуля сразу настраиваем подписки
setup_audit_subscribers()
