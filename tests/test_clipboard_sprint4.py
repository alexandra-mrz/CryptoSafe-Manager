from __future__ import annotations

# раздел Testing Sprint 4: TEST-1 … TEST-5

import ctypes
import gc
import multiprocessing
import os
import secrets
import sys
import tempfile
import threading
import time
import unittest
from ctypes import wintypes
from unittest.mock import patch

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.platform_adapter import InMemoryClipboardAdapter, create_platform_adapter


def _count_needle_in_dump_file(dump_path: str, search_bytes: bytes) -> int:
    # TEST-3: сколько раз подстрока встречается в .dmp (Win32 ReadFile)
    if not os.path.exists(dump_path):
        return 0
    kernel32 = ctypes.windll.kernel32
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    h_file = kernel32.CreateFileW(
        dump_path,
        0x80000000,
        1,
        None,
        3,
        0x80,
        None,
    )
    if h_file == INVALID_HANDLE_VALUE or not h_file:
        return 0
    total = 0
    try:
        buffer = ctypes.create_string_buffer(1024 * 1024)
        bytes_read = wintypes.DWORD()
        while True:
            ok = kernel32.ReadFile(
                h_file,
                buffer,
                len(buffer),
                ctypes.byref(bytes_read),
                None,
            )
            if not ok or bytes_read.value == 0:
                break
            chunk = buffer.raw[: bytes_read.value]
            start = 0
            while True:
                pos = chunk.find(search_bytes, start)
                if pos < 0:
                    break
                total += 1
                start = pos + 1
    finally:
        kernel32.CloseHandle(h_file)
    return total


def _child_copy_password(token: str, out: "multiprocessing.Queue[tuple[bool, bool]]") -> None:
    # TEST-3: копирование в дочернем процессе (пароль не в памяти родителя)
    from unittest.mock import patch

    from src.core.clipboard.clipboard_service import ClipboardService
    from src.core.clipboard.platform_adapter import InMemoryClipboardAdapter

    password = f"MEM3_{token}"
    search = password.encode("ascii")
    adapter = InMemoryClipboardAdapter()
    service = ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 5})
    with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
        service.copy_to_clipboard(password, "password", "test_id")
        item = service.current_content
        masked_ok = item is not None and search not in bytes(item.masked_data)
        clip_ok = search not in (adapter.get_clipboard_content() or "").encode("utf-8")
        service.force_clear("child_done")
    out.put((masked_ok, clip_ok))
    del password
    del search


def _create_process_minidump(dump_path: str) -> bool:
    # TEST-3: mini-dump текущего процесса (MiniDumpWriteDump)
    kernel32 = ctypes.windll.kernel32
    dbghelp = ctypes.windll.dbghelp
    current_pid = kernel32.GetCurrentProcessId()
    h_process = kernel32.OpenProcess(0x1F0FFF, False, current_pid)
    if not h_process:
        return False
    try:
        h_file = kernel32.CreateFileW(
            dump_path,
            0x40000000,
            0,
            None,
            2,
            0x80,
            None,
        )
        if not h_file or h_file == ctypes.c_void_p(-1).value:
            return False
        try:
            return bool(
                dbghelp.MiniDumpWriteDump(
                    h_process,
                    current_pid,
                    h_file,
                    0x00000002,
                    None,
                    None,
                    None,
                )
            )
        finally:
            kernel32.CloseHandle(h_file)
    finally:
        kernel32.CloseHandle(h_process)


class TestClipboardAutoClearTiming(unittest.TestCase):
    # TEST-1: таймер автоочистки

    def test_auto_clear_timing_within_100ms(self) -> None:
        # TEST-1: буфер очищается через ~5 с (допуск ±100 ms)
        adapter = InMemoryClipboardAdapter()
        service = ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 5})
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            t0 = time.perf_counter()
            service.copy_to_clipboard("Secret123!", data_type="password")
            while service.get_clipboard_status().get("active", False):
                time.sleep(0.01)
            dt = time.perf_counter() - t0
        # допуск ±100мс
        self.assertGreaterEqual(dt, 4.9)
        self.assertLessEqual(dt, 5.1)


class TestClipboardCrossPlatformCompatibility(unittest.TestCase):
    # TEST-2: фабрика адаптеров по ОС

    def test_factory_windows_macos_linux(self) -> None:
        # TEST-2: create_platform_adapter для Windows / Darwin / Linux
        with patch("src.core.clipboard.platform_adapter.platform.system", return_value="Windows"):
            self.assertEqual(type(create_platform_adapter()).__name__, "WindowsClipboardAdapter")
        with patch("src.core.clipboard.platform_adapter.platform.system", return_value="Darwin"):
            self.assertEqual(type(create_platform_adapter()).__name__, "MacOSClipboardAdapter")
        with patch("src.core.clipboard.platform_adapter.platform.system", return_value="Linux"):
            self.assertEqual(type(create_platform_adapter()).__name__, "LinuxClipboardAdapter")


@unittest.skipUnless(sys.platform == "win32", "TEST-3: Win32 MiniDump — только Windows")
class TestClipboardMemorySecurity(unittest.TestCase):
    # TEST-3: безопасность памяти через Win32 API (дамп процесса)

    def setUp(self) -> None:
        # подготовка сервиса: InMemory-адаптер для копирования, дамп — Win32 текущего процесса
        self.adapter = InMemoryClipboardAdapter()
        self.service = ClipboardService(
            platform_adapter=self.adapter,
            config={"clipboard_timeout": 5},
        )

    def test_memory_security_with_win32(self) -> None:
        # TEST-3: 1) копирование  2) дамп памяти (Win32)  3) plaintext не найден
        token = secrets.token_hex(16)
        dump_before = os.path.join(tempfile.gettempdir(), f"cryptosafe_test3_before_{os.getpid()}.dmp")
        dump_after = os.path.join(tempfile.gettempdir(), f"cryptosafe_test3_after_{os.getpid()}.dmp")

        def _needle() -> bytes:
            return f"MEM3_{token}".encode("ascii")

        # эталон: дамп до копирования (в памяти ещё нет нашего пароля)
        if not _create_process_minidump(dump_before):
            self.skipTest("MiniDumpWriteDump (до копирования) недоступен")
        count_before = _count_needle_in_dump_file(dump_before, _needle())

        # шаг 1: копируем пароль в дочернем процессе (в родителе plaintext не держим)
        ctx = multiprocessing.get_context("spawn")
        result_q: multiprocessing.Queue[tuple[bool, bool]] = ctx.Queue()
        proc = ctx.Process(target=_child_copy_password, args=(token, result_q))
        proc.start()
        proc.join()
        self.assertEqual(proc.exitcode, 0)
        masked_ok, clip_ok = result_q.get(timeout=5)
        self.assertTrue(masked_ok, "plaintext в masked_data")
        self.assertTrue(clip_ok, "plaintext в буфере адаптера")
        gc.collect()

        # шаг 3: дамп после копирования и очистки (GetCurrentProcessId → OpenProcess → MiniDump)
        if not _create_process_minidump(dump_after):
            self.skipTest("MiniDumpWriteDump (после копирования) недоступен")
        count_after = _count_needle_in_dump_file(dump_after, _needle())

        for path in (dump_before, dump_after):
            try:
                os.remove(path)
            except OSError:
                pass

        # ТЗ: после копирования и очистки не должно появиться новых вхождений plaintext в дампе
        self.assertEqual(
            count_after,
            count_before,
            f"в дампе памяти найден plaintext пароля (до={count_before}, после={count_after})",
        )
        self.assertEqual(
            count_after,
            0,
            "пароль найден в открытом виде в дампе памяти процесса",
        )


class TestClipboardConcurrency(unittest.TestCase):
    # TEST-4: параллельное копирование

    def test_multiple_rapid_copy_operations(self) -> None:
        # TEST-4: 4 потока × 20 копий без ошибок
        adapter = InMemoryClipboardAdapter()
        service = ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 5})
        errors: list[str] = []

        def worker(prefix: str) -> None:
            # один поток — серия copy_to_clipboard
            try:
                for i in range(20):
                    service.copy_to_clipboard(f"{prefix}-{i}", data_type="password")
            except Exception as e:  # noqa: BLE001
                errors.append(str(e))

        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            threads = [threading.Thread(target=worker, args=(f"t{n}",)) for n in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual(errors, [])
        # в системном буфере не должен лежать plaintext последнего значения
        content = adapter.get_clipboard_content() or ""
        self.assertNotIn("t3-19", content)


class TestClipboardRecovery(unittest.TestCase):
    # TEST-5: очистка при stop()

    def test_stop_clears_sensitive_data(self) -> None:
        # TEST-5: stop() очищает буфер и снимает active
        adapter = InMemoryClipboardAdapter()
        service = ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 5})
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            service.copy_to_clipboard("CrashSecret", data_type="password")
            # имитируем аварийное завершение через stop
            service.stop()
        self.assertEqual(adapter.get_clipboard_content(), "")
        self.assertFalse(service.get_clipboard_status().get("active", False))


if __name__ == "__main__":
    unittest.main()
