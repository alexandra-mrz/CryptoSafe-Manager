from __future__ import annotations

# PLAT-1..4: адаптеры буфера обмена под Windows / macOS / Linux

from abc import ABC, abstractmethod
from typing import Optional
import subprocess
import platform

class ClipboardAdapter(ABC):
    """Публичный абстрактный адаптер буфера обмена."""

    @abstractmethod
    def copy_to_clipboard(self, data: str) -> bool:
        # записать текст в системный буфер
        """Copy to clipboard."""
        pass

    @abstractmethod
    def clear_clipboard(self) -> bool:
        # очистить системный буфер
        """Clear clipboard."""
        pass

    @abstractmethod
    def get_clipboard_content(self) -> Optional[str]:
        # прочитать текст из буфера
        """Get clipboard content."""
        pass

class InMemoryClipboardAdapter(ClipboardAdapter):
    # простой адаптер в памяти (удобен для тестов)

    """Публичный класс InMemoryClipboardAdapter."""
    def __init__(self) -> None:
        # пустой буфер в памяти (для unit-тестов)
        self._value = ""

    def copy_to_clipboard(self, data: str) -> bool:
        """Copy to clipboard."""
        self._value = str(data)
        return True

    def clear_clipboard(self) -> bool:
        """Clear clipboard."""
        self._value = ""
        return True

    def get_clipboard_content(self) -> Optional[str]:
        """Get clipboard content."""
        return self._value


class PyperclipClipboardAdapter(ClipboardAdapter):
    # кроссплатформенный fallback через pyperclip (PLAT-4)

    """Публичный класс PyperclipClipboardAdapter."""
    def copy_to_clipboard(self, data: str) -> bool:
        # pyperclip.copy
        """Copy to clipboard."""
        try:
            import pyperclip  # type: ignore

            pyperclip.copy(str(data))
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        """Clear clipboard."""
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        """Get clipboard content."""
        try:
            import pyperclip  # type: ignore

            value = pyperclip.paste()
            return str(value or "")
        except Exception:
            return None


class WindowsClipboardAdapter(ClipboardAdapter):
    # Windows: win32clipboard + EmptyClipboard + CF_UNICODETEXT (PLAT-1)

    """Публичный класс WindowsClipboardAdapter."""
    def __init__(self) -> None:
        # win32clipboard или fallback на pyperclip
        try:
            import win32clipboard  # type: ignore
        except Exception:
            win32clipboard = None
        self.win32clipboard = win32clipboard
        self._fallback = PyperclipClipboardAdapter()

    def copy_to_clipboard(self, data: str) -> bool:
        """Copy to clipboard."""
        if self.win32clipboard is None:
            return self._fallback.copy_to_clipboard(data)
        try:
            self.win32clipboard.OpenClipboard()
            self.win32clipboard.EmptyClipboard()
            # пишем unicode-текст в системный буфер
            self.win32clipboard.SetClipboardText(str(data), self.win32clipboard.CF_UNICODETEXT)
            self.win32clipboard.CloseClipboard()
            return True
        except Exception:
            try:
                self.win32clipboard.CloseClipboard()
            except Exception:
                pass
            return False

    def clear_clipboard(self) -> bool:
        """Clear clipboard."""
        if self.win32clipboard is None:
            return self._fallback.clear_clipboard()
        try:
            self.win32clipboard.OpenClipboard()
            self.win32clipboard.EmptyClipboard()
            self.win32clipboard.CloseClipboard()
            return True
        except Exception:
            try:
                self.win32clipboard.CloseClipboard()
            except Exception:
                pass
            return False

    def get_clipboard_content(self) -> Optional[str]:
        """Get clipboard content."""
        if self.win32clipboard is None:
            return self._fallback.get_clipboard_content()
        try:
            self.win32clipboard.OpenClipboard()
            value = self.win32clipboard.GetClipboardData(self.win32clipboard.CF_UNICODETEXT)
            self.win32clipboard.CloseClipboard()
            return str(value)
        except Exception:
            try:
                self.win32clipboard.CloseClipboard()
            except Exception:
                pass
            return None


class MacOSClipboardAdapter(ClipboardAdapter):
    # macOS: pyobjc + NSPasteboard (PLAT-2)

    """Публичный класс MacOSClipboardAdapter."""
    def __init__(self) -> None:
        # NSPasteboard или fallback на pyperclip
        try:
            from AppKit import NSPasteboard, NSPasteboardTypeString  # type: ignore
        except Exception:
            NSPasteboard = None
            NSPasteboardTypeString = None
        self.NSPasteboard = NSPasteboard
        self.NSPasteboardTypeString = NSPasteboardTypeString
        self._fallback = PyperclipClipboardAdapter()

    def copy_to_clipboard(self, data: str) -> bool:
        """Copy to clipboard."""
        if self.NSPasteboard is None or self.NSPasteboardTypeString is None:
            return self._fallback.copy_to_clipboard(data)
        try:
            pasteboard = self.NSPasteboard.generalPasteboard()
            pasteboard.clearContents()
            pasteboard.declareTypes_owner_([self.NSPasteboardTypeString], None)
            ok = pasteboard.setString_forType_(str(data), self.NSPasteboardTypeString)
            return bool(ok)
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        """Clear clipboard."""
        if self.NSPasteboard is None:
            return self._fallback.clear_clipboard()
        try:
            pasteboard = self.NSPasteboard.generalPasteboard()
            pasteboard.clearContents()
            return True
        except Exception:
            return False

    def get_clipboard_content(self) -> Optional[str]:
        """Get clipboard content."""
        if self.NSPasteboard is None or self.NSPasteboardTypeString is None:
            return self._fallback.get_clipboard_content()
        try:
            pasteboard = self.NSPasteboard.generalPasteboard()
            value = pasteboard.stringForType_(self.NSPasteboardTypeString)
            return str(value) if value is not None else ""
        except Exception:
            return None


class LinuxClipboardAdapter(ClipboardAdapter):
    # Linux: pyperclip + xsel/xclip + Wayland wl-clipboard (PLAT-3)

    """Публичный класс LinuxClipboardAdapter."""
    def __init__(self) -> None:
        # selection: clipboard или primary (X11)
        self._fallback = PyperclipClipboardAdapter()
        self._selection = "clipboard"

    def copy_to_clipboard(self, data: str) -> bool:
        # wl-copy / xclip / xsel, иначе pyperclip
        """Copy to clipboard."""
        text = str(data)
        # Wayland backend (wl-copy)
        if self._run_cmd(["wl-copy"], text):
            return True
        # X11 backends
        if self._run_cmd(["xclip", "-selection", self._selection], text):
            return True
        if self._run_cmd(["xsel", "--" + self._selection, "--input"], text):
            return True
        # fallback
        return self._fallback.copy_to_clipboard(text)

    def clear_clipboard(self) -> bool:
        """Clear clipboard."""
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        # Wayland backend (wl-paste)
        """Get clipboard content."""
        out = self._run_cmd_capture(["wl-paste", "-n"])
        if out is not None:
            return out
        # X11 backends
        out = self._run_cmd_capture(["xclip", "-o", "-selection", self._selection])
        if out is not None:
            return out
        out = self._run_cmd_capture(["xsel", "--" + self._selection, "--output"])
        if out is not None:
            return out
        # fallback
        return self._fallback.get_clipboard_content()

    def set_private_selection(self, use_primary: bool) -> None:
        # private selection: PRIMARY vs CLIPBOARD
        """Set private selection."""
        self._selection = "primary" if bool(use_primary) else "clipboard"

    def _run_cmd(self, cmd: list[str], data: str) -> bool:
        # записать в буфер через внешнюю команду
        try:
            process = subprocess.run(
                cmd,
                input=data.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            return process.returncode == 0
        except Exception:
            return False

    def _run_cmd_capture(self, cmd: list[str]) -> Optional[str]:
        # прочитать буфер через внешнюю команду
        try:
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if process.returncode != 0:
                return None
            return process.stdout.decode("utf-8", errors="ignore")
        except Exception:
            return None


def create_platform_adapter() -> ClipboardAdapter:
    # фабрика адаптеров по платформе
    """Create platform adapter."""
    system = platform.system().lower()
    if system.startswith("win"):
        return WindowsClipboardAdapter()
    if system.startswith("darwin"):
        return MacOSClipboardAdapter()
    if system.startswith("linux"):
        return LinuxClipboardAdapter()
    return PyperclipClipboardAdapter()

