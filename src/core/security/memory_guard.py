from __future__ import annotations

# Sprint 7 / MEM-1..MEM-4 — по примеру ТЗ (sprint7.md)

import ctypes
import platform
import sys
from typing import Any, Union

from src.core.security.side_channel_protection import constant_time_equal_int


class SecureMemory:
    """Secure memory allocation and wiping."""

    def __init__(self) -> None:
        self.system = platform.system()
        self._setup_platform_functions()

    def _setup_platform_functions(self) -> None:
        """Setup platform-specific memory functions."""
        if self.system == "Windows":
            self.kernel32 = ctypes.windll.kernel32
            self._VirtualLock = self.kernel32.VirtualLock
            self._VirtualUnlock = self.kernel32.VirtualUnlock
            try:
                self._RtlSecureZeroMemory = self.kernel32.RtlSecureZeroMemory
            except AttributeError:
                self._RtlSecureZeroMemory = None
        elif self.system in ("Linux", "Darwin"):
            if sys.platform != "win32":
                self.libc = ctypes.CDLL(None)
                self._mlock = self.libc.mlock
                self._munlock = self.libc.munlock
                self._memset = self.libc.memset

    def allocate_secure(self, size: int) -> Any:
        """Allocate memory with locking to prevent swapping."""
        buffer = (ctypes.c_char * size)()

        if self.system == "Windows":
            self._VirtualLock(buffer, size)
        elif hasattr(self, "_mlock"):
            self._mlock(buffer, size)

        return buffer

    def secure_zero(self, buffer: Any, size: int) -> None:
        """Securely zero memory."""
        if size <= 0:
            return

        if self.system == "Windows":
            if self._RtlSecureZeroMemory is not None:
                self._RtlSecureZeroMemory(buffer, size)
            else:
                ctypes.memset(buffer, 0, size)
        elif hasattr(self, "libc"):
            try:
                memset_s = self.libc.memset_s
                memset_s(buffer, size, 0, size)
            except Exception:
                self._memset(buffer, 0, size)
        else:
            ctypes.memset(buffer, 0, size)

        ctypes.memset(buffer, 0, size)

    def free_secure(self, buffer: Any, size: int) -> None:
        """Free securely allocated memory."""
        self.secure_zero(buffer, size)

        if self.system == "Windows":
            self._VirtualUnlock(buffer, size)
        elif hasattr(self, "_munlock"):
            self._munlock(buffer, size)

        del buffer


class SecretHolder:
    """Holder for sensitive data with automatic wiping."""

    def __init__(self, data: bytes) -> None:
        self._memory = SecureMemory()
        self._size = len(data)
        self._buffer = self._memory.allocate_secure(self._size)

        if self._size:
            ctypes.memmove(self._buffer, data, self._size)

            staging = bytearray(data)
            view = (ctypes.c_char * self._size).from_buffer(staging)
            self._memory.secure_zero(view, self._size)

    def get_data(self) -> bytes:
        """Get copy of data (caller must wipe after use)."""
        return bytes(self._buffer)

    def copy_bytes(self) -> bytes:
        """Copy bytes."""
        return self.get_data()

    def __del__(self) -> None:
        """Automatically wipe when destroyed."""
        if hasattr(self, "_buffer") and self._buffer:
            self._memory.free_secure(self._buffer, self._size)


_default_memory = SecureMemory()


def secure_wipe(data: Union[bytes, bytearray], *, passes: int = 1) -> None:
    """Secure wipe."""
    if not data:
        return
    buf = bytearray(data) if isinstance(data, bytes) else data
    length = len(buf)
    if length == 0:
        return
    view = (ctypes.c_char * length).from_buffer(buf)
    count = max(1, int(passes))
    for _ in range(count):
        _default_memory.secure_zero(view, length)


def wipe_local(data: bytearray) -> None:
    """MEM-4: wipe local/stack buffer after use."""
    secure_wipe(data)


def stack_canary_ok(expected: int, actual: int) -> bool:
    """MEM-4: stack canary check for critical functions."""
    return constant_time_equal_int(expected, actual)
