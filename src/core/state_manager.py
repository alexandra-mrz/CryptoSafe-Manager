
from __future__ import annotations

# состояние сессии, буфер, неактивность, настройки из settings

import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

from src.core.events import EventBus, get_event_bus
from src.core.crypto.key_storage import update_cache_activity, clear_all_keys
from src.database.db import get_default_database

SETTING_PASSWORD_POLICY = "password_policy"
SETTING_KEY_PARAMS = "key_params"
SETTING_AUTO_LOCK_TIMEOUT = "auto_lock_timeout"


@dataclass
class AppState:
    """Публичный класс AppState."""
    locked: bool = True
    clipboard_seconds_left: int = 0
    inactivity_seconds: int = 0
    login_timestamp: Optional[float] = None
    last_activity_timestamp: Optional[float] = None
    failed_attempt_count: int = 0


class StateManager:
    """Публичный класс StateManager."""
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
        self._bus.subscribe("UserActivity", self._on_user_activity)

        self._load_initial_config()

        self._thread.start()

    def _make_key(self, base_key: str) -> str:
        return f"{self.env}.{base_key}"

    def get_setting(self, base_key: str, default: Any | None = None) -> Any:
        """Get setting."""
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
        """Set setting."""
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
        if self.get_setting(SETTING_PASSWORD_POLICY, None) is None:
            self.set_setting(SETTING_PASSWORD_POLICY, '{"min_length": 12}')
        if self.get_setting(SETTING_KEY_PARAMS, None) is None:
            self.set_setting(SETTING_KEY_PARAMS, '{"pbkdf2_iterations": 100000}')
        if self.get_setting(SETTING_AUTO_LOCK_TIMEOUT, None) is None:
            self.set_setting(SETTING_AUTO_LOCK_TIMEOUT, "5")
        # CFG-1/CFG-3: настройки буфера по умолчанию
        if self.get_setting("clipboard_notifications_enabled", None) is None:
            self.set_setting("clipboard_notifications_enabled", "1", encrypted=True)
        if self.get_setting("clipboard_security_level", None) is None:
            self.set_setting("clipboard_security_level", "basic", encrypted=True)
        if self.get_setting("clipboard_app_whitelist", None) is None:
            self.set_setting("clipboard_app_whitelist", "", encrypted=True)
        if self.get_setting("activity_sensitivity", None) is None:
            self.set_setting("activity_sensitivity", "medium", encrypted=True)
        if self.get_setting("device_type", None) is None:
            self.set_setting("device_type", "desktop", encrypted=True)
        if self.get_setting("minimize_to_tray", None) is None:
            self.set_setting("minimize_to_tray", "1", encrypted=True)
        if self.get_setting("start_minimized", None) is None:
            self.set_setting("start_minimized", "0", encrypted=True)
        if self.get_setting("panic_stealth_mode", None) is None:
            self.set_setting("panic_stealth_mode", "0", encrypted=True)
        if self.get_setting("panic_quit_app", None) is None:
            self.set_setting("panic_quit_app", "0", encrypted=True)
        if self.get_setting("security_profile", None) is None:
            self.set_setting("security_profile", "standard", encrypted=True)

    def _on_user_logged_in(self, event: str, payload: Any) -> None:
        self.state.locked = False
        self.state.inactivity_seconds = 0
        self.state.login_timestamp = time.time()
        self.state.last_activity_timestamp = time.time()

    def _on_user_logged_out(self, event: str, payload: Any) -> None:
        self.state.locked = True
        clear_all_keys()

    def _on_clipboard_copied(self, event: str, payload: Any) -> None:
        self.state.inactivity_seconds = 0
        self.state.last_activity_timestamp = time.time()
        if isinstance(payload, dict):
            seconds = payload.get("timeout")
            if isinstance(seconds, int) and seconds > 0:
                self.state.clipboard_seconds_left = seconds

    def _on_clipboard_cleared(self, event: str, payload: Any) -> None:
        self.state.clipboard_seconds_left = 0

    def _on_user_activity(self, event: str, payload: Any) -> None:
        self.state.inactivity_seconds = 0
        self.state.last_activity_timestamp = time.time()

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(1.0)
            self.state.inactivity_seconds += 1
            if self.state.clipboard_seconds_left > 0:
                self.state.clipboard_seconds_left -= 1
            update_cache_activity(self.state.inactivity_seconds)

    def stop(self) -> None:
        """Stop."""
        self._stop_event.set()
        self._thread.join(timeout=1.0)


_state_manager: Optional[StateManager] = None


def get_state_manager() -> StateManager:
    """Get state manager."""
    global _state_manager
    if _state_manager is None:
        _state_manager = StateManager()
    return _state_manager
