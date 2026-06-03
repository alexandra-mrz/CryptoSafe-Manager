from __future__ import annotations

# Sprint 7 / ACT-1..ACT-2: мониторинг активности для auto-lock

import ctypes
import platform
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _system_idle_seconds() -> Optional[float]:
    # ACT-1: экран/ввод — GetLastInputInfo (Windows)
    if platform.system() != "Windows":
        return None
    try:
        class LASTINPUTINFO(ctypes.Structure):
            """Публичный класс LASTINPUTINFO."""
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

        info = LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
            return None
        tick = ctypes.windll.kernel32.GetTickCount()
        idle_ms = tick - info.dwTime
        return idle_ms / 1000.0
    except Exception:
        return None


class ActivityMonitor:
    # ACT-1: mouse/key/focus через record_activity + системный idle

    """Публичный класс ActivityMonitor."""
    def __init__(self, lock_callback: Callable[[], None], config: dict) -> None:
        self._lock_callback = lock_callback
        self._config = dict(config)
        self._last_activity = _utc_now()
        self._monitoring = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def update_config(self, config: dict) -> None:
        """Update config."""
        with self._lock:
            self._config.update(config)

    def record_activity(self, source: str = "ui") -> None:
        # ACT-1: событие из GUI (мышь, клавиатура, фокус)
        """Record activity."""
        with self._lock:
            self._last_activity = _utc_now()
            _ = source

    def start_monitoring(self) -> None:
        """Start monitoring."""
        with self._lock:
            if self._monitoring:
                return
            self._monitoring = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()

    def stop_monitoring(self) -> None:
        """Stop monitoring."""
        with self._lock:
            self._monitoring = False
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def get_idle_seconds(self) -> float:
        """Get idle seconds."""
        with self._lock:
            return (_utc_now() - self._last_activity).total_seconds()

    def _effective_timeout(self) -> float:
        # ACT-2: 1..480 мин, sensitivity множитель
        minutes = int(self._config.get("lock_timeout_minutes", 5))
        minutes = max(1, min(480, minutes))
        sensitivity = str(self._config.get("activity_sensitivity", "medium") or "medium")
        factor = {"low": 1.25, "medium": 1.0, "high": 0.75}.get(sensitivity, 1.0)
        device = str(self._config.get("device_type", "desktop") or "desktop")
        if device == "laptop":
            factor *= 0.9
        return minutes * 60.0 * factor

    def _monitor_loop(self) -> None:
        interval = float(self._config.get("check_interval", 1.0))
        while True:
            with self._lock:
                if not self._monitoring:
                    break
            sys_idle = _system_idle_seconds()
            if sys_idle is not None and sys_idle < 2.0:
                self.record_activity("system")
            idle = self.get_idle_seconds()
            if idle >= self._effective_timeout():
                try:
                    self._lock_callback()
                except Exception:
                    pass
                self.record_activity("auto_lock")
            time.sleep(max(0.2, interval))
