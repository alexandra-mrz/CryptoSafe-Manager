from __future__ import annotations

# Sprint 7 / INT-1..INT-4: интеграция с vault, clipboard, audit, import/export

from typing import Any, Optional

from src.core.events import get_event_bus
from src.core.security.memory_guard import secure_wipe, wipe_local
from src.core.security.side_channel_protection import constant_time_compare

_io_aborted = False


def set_io_aborted(value: bool) -> None:
    # INT-4: прервать длительный import/export при панике
    """Set io aborted."""
    global _io_aborted
    _io_aborted = value


def io_aborted() -> bool:
    """Io aborted."""
    return _io_aborted


def check_io_aborted() -> None:
    """Check io aborted."""
    if _io_aborted:
        raise InterruptedError("операция прервана (panic)")


def wipe_sensitive_buffer(data: bytearray | bytes) -> None:
    # INT-1 / INT-2 / INT-4: единый wipe
    """Wipe sensitive buffer."""
    secure_wipe(data)


def secure_contains(needle: str, haystack: str) -> bool:
    # INT-1: поиск без раннего сравнения по длине needle (кроме пустого)
    """Secure contains."""
    if not needle:
        return True
    n = needle.lower().encode("utf-8")
    h = haystack.lower().encode("utf-8")
    if len(n) == 0:
        return True
    if len(n) > len(h):
        return False
    last = len(h) - len(n)
    for i in range(last + 1):
        if constant_time_compare(h[i : i + len(n)], n):
            return True
    return False


def log_security_hardening(component: str, action: str, details: Optional[dict[str, Any]] = None) -> None:
    # INT-3: события усиления безопасности
    """Log security hardening."""
    payload = {"component": component, "action": action}
    if details:
        payload.update(details)
    get_event_bus().publish("SecurityHardening", payload)
