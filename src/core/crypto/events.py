# EVT-1: Система событий (публикация/подписка)
# EVT-3: поддержка синхронной обработки (асинхронная — по желанию, Should)

from typing import Callable, Any, List
import threading

# Типы событий по ТЗ
ENTRY_ADDED = "EntryAdded"
ENTRY_UPDATED = "EntryUpdated"
ENTRY_DELETED = "EntryDeleted"
USER_LOGGED_IN = "UserLoggedIn"
USER_LOGGED_OUT = "UserLoggedOut"
CLIPBOARD_COPIED = "ClipboardCopied"
CLIPBOARD_CLEARED = "ClipboardCleared"


class EventBus:
    """Простая шина событий: подписка и публикация."""

    def __init__(self):
        self._handlers: dict[str, List[Callable[..., Any]]] = {}
        self._lock = threading.Lock()

    def subscribe(self, event_type: str, handler: Callable[..., Any]) -> None:
        with self._lock:
            if event_type not in self._handlers:
                self._handlers[event_type] = []
            self._handlers[event_type].append(handler)

    def publish(self, event_type: str, **kwargs) -> None:
        with self._lock:
            handlers = list(self._handlers.get(event_type, []))
        for h in handlers:
            try:
                h(**kwargs)
            except Exception:
                pass  # SEC-3: не раскрываем детали в сообщениях — логируем минимально

    def unsubscribe(self, event_type: str, handler: Callable[..., Any]) -> None:
        with self._lock:
            if event_type in self._handlers:
                self._handlers[event_type] = [x for x in self._handlers[event_type] if x != handler]


# Глобальная шина
_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus
