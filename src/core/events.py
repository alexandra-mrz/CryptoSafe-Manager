from __future__ import annotations

# шина событий приложения: evt-1 / evt-3, синхронные и асинхронные обработчики через внутреннюю очередь

import queue
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List


EventHandler = Callable[[str, Any], None]


@dataclass
class _Subscription:
    event_name: str
    handler: EventHandler
    is_async: bool


class EventBus:
    def __init__(self) -> None:
        self._handlers: Dict[str, List[_Subscription]] = {}
        self._queue: "queue.Queue[tuple[str, Any, EventHandler]]" = queue.Queue()
        self._stop_event = threading.Event()
        self._worker = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker.start()

    # ===== Подписка и публикация =====

    def subscribe(self, event_name: str, handler: EventHandler, *, async_handler: bool = False) -> None:
        subs = self._handlers.setdefault(event_name, [])
        subs.append(_Subscription(event_name, handler, async_handler))

    def publish(self, event_name: str, payload: Any = None) -> None:
        for sub in self._handlers.get(event_name, []):
            if sub.is_async:
                self._queue.put((event_name, payload, sub.handler))
            else:
                sub.handler(event_name, payload)

    # ===== Внутренний поток для асинхронных обработчиков =====

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                event_name, payload, handler = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                handler(event_name, payload)
            finally:
                self._queue.task_done()

    def stop(self) -> None:
        self._stop_event.set()
        self._worker.join(timeout=1.0)


_event_bus = EventBus()


def get_event_bus() -> EventBus:
    return _event_bus
