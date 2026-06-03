from __future__ import annotations

# Sprint 7 / PANIC-1..PANIC-4: аварийная блокировка (по примеру sprint7.md)

import threading
from typing import Any, Callable, List, Optional


class PanicMode:
    """Emergency response system with default handlers delegating to core services."""

    def __init__(self, config: Optional[dict] = None, *, register_defaults: bool = True) -> None:
        self._config: dict[str, Any] = dict(config or {})
        self._activated = False
        self._handlers: List[Callable[[], None]] = []
        self._log_callback: Optional[Callable[[str], None]] = None
        self._lock = threading.Lock()
        if register_defaults:
            self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register default panic response handlers (sprint7.md example)."""
        # PANIC-2: порядок как в ТЗ — clipboard → lock → windows → wipe → UI
        self.register_handler(self._abort_io)
        self.register_handler(self._clear_clipboard)
        self.register_handler(self._lock_vault)
        self.register_handler(self._close_windows)
        self.register_handler(self._wipe_memory)
        self.register_handler(self._apply_ui_actions)

    def register_handler(self, handler: Callable[[], None]) -> None:
        """Register handler."""
        self._handlers.append(handler)

    def set_log_callback(self, callback: Callable[[str], None]) -> None:
        # опциональный override; по умолчанию — _log_panic_event
        """Set log callback."""
        self._log_callback = callback

    def update_config(self, config: dict) -> None:
        """Update config."""
        self._config.update(config)

    @property
    def activated(self) -> bool:
        """Activated."""
        return self._activated

    def reset(self) -> None:
        # PANIC-4: после unlock
        """Reset."""
        with self._lock:
            self._activated = False

    def activate(self, method: str = "hotkey") -> None:
        """Activate."""
        with self._lock:
            if self._activated:
                return
            self._activated = True

        for handler in list(self._handlers):
            try:
                handler()
            except Exception:
                pass

        if self._config.get("stealth_mode"):
            self._execute_stealth_actions()
        self._log_panic_event(method)

    def _abort_io(self) -> None:
        # INT-4: прервать длительный import/export
        try:
            from src.core.security.integration import set_io_aborted

            set_io_aborted(True)
        except Exception:
            pass

    def _clear_clipboard(self) -> None:
        # INT-2: делегирование в ClipboardService
        svc = self._config.get("clipboard_service")
        if svc is not None:
            try:
                svc.force_clear(reason="panic")
            except Exception:
                pass
            return
        try:
            from src.core.clipboard.platform_adapter import create_platform_adapter

            create_platform_adapter().clear_clipboard()
        except Exception:
            pass

    def _lock_vault(self) -> None:
        # PANIC-2: lock через GUI callback или core-сервисы
        lock_cb = self._config.get("lock_callback")
        if lock_cb is not None:
            try:
                lock_cb()
            except Exception:
                pass
            return
        try:
            from src.core.crypto.authentication import lock_session
            from src.core.crypto.key_storage import clear_all_keys
            from src.core.events import get_event_bus
            from src.core.security.integration import log_security_hardening

            clear_all_keys()
            lock_session()
            state_manager = self._config.get("state_manager")
            if state_manager is not None:
                state_manager.state.locked = True
            bus = get_event_bus()
            bus.publish("UserLoggedOut", {"source": "panic"})
            bus.publish("VaultLocked", {"source": "panic"})
            log_security_hardening("system", "vault_locked", {"source": "panic"})
        except Exception:
            pass

    def _close_windows(self) -> None:
        # PANIC-2: закрыть вторичные окна (GUI callback из MainWindow)
        cb = self._config.get("close_windows_callback")
        if cb is None:
            return
        try:
            cb()
        except Exception:
            pass

    def _wipe_memory(self) -> None:
        # PANIC-2: очистка чувствительных буферов
        try:
            from src.core.security.memory_guard import SecureMemory

            SecureMemory()
        except Exception:
            pass
        svc = self._config.get("clipboard_service")
        if svc is None:
            return
        try:
            content = getattr(svc, "current_content", None)
            if content is not None:
                content.secure_wipe()
        except Exception:
            pass

    def _apply_ui_actions(self) -> None:
        # PANIC-2: скрыть главное окно; опционально выход
        hide_cb = self._config.get("hide_window_callback")
        if hide_cb is not None:
            try:
                hide_cb()
            except Exception:
                pass
        if not self._config.get("quit_app"):
            return
        quit_cb = self._config.get("quit_callback")
        if quit_cb is not None:
            try:
                quit_cb()
            except Exception:
                pass

    def _execute_stealth_actions(self) -> None:
        # PANIC-3 (Should)
        actions = self._config.get("stealth_actions") or {}
        if actions.get("show_fake_error"):
            self._show_fake_error()

    def _show_fake_error(self) -> None:
        # PANIC-3 (Should): decoy app / URL — см. docs/SPRINT7_IMPLEMENTATION.md
        try:
            from PyQt6.QtWidgets import QMessageBox

            QMessageBox.critical(
                None,
                "Application Error",
                "The application has encountered an unexpected error and must close.",
            )
        except Exception:
            pass

    def _log_panic_event(self, method: str) -> None:
        # PANIC-4 + INT-3
        if self._log_callback is not None:
            try:
                self._log_callback(method)
            except Exception:
                pass
            return
        try:
            from src.core.events import get_event_bus

            get_event_bus().publish("PanicModeActivated", {"activation_method": method})
        except Exception:
            pass
        try:
            from src.core.security.integration import log_security_hardening

            log_security_hardening("panic", "activated", {"activation_method": method})
        except Exception:
            pass
        try:
            from src.core.audit.audit_logger import AuditLogger

            AuditLogger().log_event("PanicModeActivated", {"activation_method": method})
        except Exception:
            pass
