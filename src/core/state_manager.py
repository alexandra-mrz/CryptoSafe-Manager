from __future__ import annotations

# менеджер состояния приложения: сессия, буфер обмена, неактивность и настройки по окружениям

import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

from src.core.events import EventBus, get_event_bus
from src.database.db import get_default_database


@dataclass
class AppState:
    locked: bool = True
    clipboard_seconds_left: int = 0
    inactivity_seconds: int = 0


class StateManager:
    def __init__(self, env: Optional[str] = None) -> None:
        self._db = get_default_database()
        self._bus: EventBus = get_event_bus()

        self.env = env or os.getenv("CRYPTOSAFE_ENV", "development")
        self.state = AppState()

        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

        self._bus.subscribe("UserLoggedIn", self._on_user_logged_in)
        self._bus.subscribe("UserLoggedOut", self._on_user_logged_out)
        self._bus.subscribe("ClipboardCopied", self._on_clipboard_copied)
        self._bus.subscribe("ClipboardCleared", self._on_clipboard_cleared)

        self._load_initial_config()

        self._thread.start()

    def _make_key(self, base_key: str) -> str:
        return f"{self.env}.{base_key}"

    def get_setting(self, base_key: str, default: Any | None = None) -> Any:
        key = self._make_key(base_key)
        conn = self._db.create_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT setting_value FROM settings WHERE setting_key = ?",
                (key,),
            )
            row = cur.fetchone()
            if row is None:
                return default
            value = row["setting_value"]
            return value if value is not None else default
        finally:
            conn.close()

    def set_setting(self, base_key: str, value: Any, *, encrypted: bool = False) -> None:
        key = self._make_key(base_key)
        conn = self._db.create_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO settings (setting_key, setting_value, encrypted)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    encrypted = excluded.encrypted
                """,
                (key, str(value), 1 if encrypted else 0),
            )
            conn.commit()
        finally:
            conn.close()

    def _load_initial_config(self) -> None:
        clipboard_timeout = self.get_setting("clipboard_timeout_seconds", None)
        if clipboard_timeout is not None:
            try:
                self.state.clipboard_seconds_left = int(clipboard_timeout)
            except ValueError:
                self.state.clipboard_seconds_left = 0

    def _on_user_logged_in(self, event: str, payload: Any) -> None:
        self.state.locked = False
        self.state.inactivity_seconds = 0

    def _on_user_logged_out(self, event: str, payload: Any) -> None:
        self.state.locked = True

    def _on_clipboard_copied(self, event: str, payload: Any) -> None:
        self.state.inactivity_seconds = 0
        if isinstance(payload, dict):
            seconds = payload.get("timeout")
            if isinstance(seconds, int) and seconds > 0:
                self.state.clipboard_seconds_left = seconds

    def _on_clipboard_cleared(self, event: str, payload: Any) -> None:
        self.state.clipboard_seconds_left = 0

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(1.0)
            self.state.inactivity_seconds += 1
            if self.state.clipboard_seconds_left > 0:
                self.state.clipboard_seconds_left -= 1

    def stop(self) -> None:
        self._stop_event.set()
        self._thread.join(timeout=1.0)


_state_manager: Optional[StateManager] = None


def get_state_manager() -> StateManager:
    global _state_manager
    if _state_manager is None:
        _state_manager = StateManager()
    return _state_manager

