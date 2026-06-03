from __future__ import annotations

# MON-1: фоновый мониторинг изменений системного буфера

import threading
import time
from typing import Callable, Optional

from src.core.clipboard.platform_adapter import ClipboardAdapter


class ClipboardMonitor:
    # монитор буфера обмена: отслеживает изменения в фоне

    """Публичный класс ClipboardMonitor."""
    def __init__(
        self,
        adapter: ClipboardAdapter,
        on_change: Callable[[str], None],
        *,
        interval_seconds: float = 0.5,
    ) -> None:
        # adapter — платформа, on_change — callback при смене текста в буфере
        self._adapter = adapter
        self._on_change = on_change
        self._interval_seconds = float(interval_seconds)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_value = ""

    def start(self) -> None:
        # запускаем поток только один раз
        """Start."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._last_value = self._safe_get_text()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        # остановить поток мониторинга
        """Stop."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def _safe_get_text(self) -> str:
        # прочитать буфер без падения при ошибке ОС
        try:
            value = self._adapter.get_clipboard_content()
            return str(value or "")
        except Exception:
            return ""

    def _loop(self) -> None:
        # цикл опроса буфера каждые interval_seconds
        while not self._stop_event.is_set():
            current = self._safe_get_text()
            if current != self._last_value:
                self._last_value = current
                self._on_change(current)
            time.sleep(self._interval_seconds)

