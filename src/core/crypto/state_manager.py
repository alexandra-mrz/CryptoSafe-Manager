# CFG-1: StateManager — сессия, буфер обмена и таймер, таймер неактивности

import threading
import time
from typing import Optional

# Состояние сессии
SESSION_LOCKED = "locked"
SESSION_UNLOCKED = "unlocked"


class StateManager:
    """Централизованное состояние: сессия, буфер, таймеры."""

    def __init__(self):
        self._lock = threading.Lock()
        self._session_state = SESSION_LOCKED
        self._clipboard_content: Optional[str] = None
        self._clipboard_timer_end: Optional[float] = None  # время окончания (для Спринта 4)
        self._last_activity_time: Optional[float] = None   # для авто-блокировки (Спринт 7)

    @property
    def session_state(self) -> str:
        with self._lock:
            return self._session_state

    def set_session_unlocked(self) -> None:
        with self._lock:
            self._session_state = SESSION_UNLOCKED
            self._last_activity_time = time.time()

    def set_session_locked(self) -> None:
        with self._lock:
            self._session_state = SESSION_LOCKED
            self._clipboard_content = None
            self._clipboard_timer_end = None

    @property
    def clipboard_content(self) -> Optional[str]:
        with self._lock:
            return self._clipboard_content

    def set_clipboard(self, content: Optional[str], clear_after_seconds: Optional[float] = None) -> None:
        with self._lock:
            self._clipboard_content = content
            self._clipboard_timer_end = (time.time() + clear_after_seconds) if clear_after_seconds else None

    def get_clipboard_timer_remaining(self) -> Optional[float]:
        """Секунды до очистки буфера (заглушка таймера для GUI)."""
        with self._lock:
            if self._clipboard_timer_end is None:
                return None
            remain = self._clipboard_timer_end - time.time()
            return max(0.0, remain) if remain > 0 else 0.0

    def touch_activity(self) -> None:
        with self._lock:
            self._last_activity_time = time.time()

    def get_idle_seconds(self) -> float:
        """Секунды неактивности (для авто-блокировки Спринт 7)."""
        with self._lock:
            if self._last_activity_time is None:
                return 0.0
            return time.time() - self._last_activity_time


_state: Optional[StateManager] = None


def get_state_manager() -> StateManager:
    global _state
    if _state is None:
        _state = StateManager()
    return _state
