# публичный API модуля clipboard (Sprint 4)

from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.clipboard.clipboard_service import ClipboardService, SecureClipboardItem
from src.core.clipboard.platform_adapter import (
    ClipboardAdapter,
    InMemoryClipboardAdapter,
    LinuxClipboardAdapter,
    MacOSClipboardAdapter,
    PyperclipClipboardAdapter,
    WindowsClipboardAdapter,
    create_platform_adapter,
)

__all__ = [
    "ClipboardAdapter",
    "InMemoryClipboardAdapter",
    "PyperclipClipboardAdapter",
    "MacOSClipboardAdapter",
    "LinuxClipboardAdapter",
    "WindowsClipboardAdapter",
    "create_platform_adapter",
    "ClipboardMonitor",
    "SecureClipboardItem",
    "ClipboardService",
]

