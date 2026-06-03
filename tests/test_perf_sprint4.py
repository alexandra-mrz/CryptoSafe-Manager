from __future__ import annotations

# раздел Performance Sprint 4: PERF-1 … PERF-3

import time
import tracemalloc
import unittest
from unittest.mock import patch

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.platform_adapter import InMemoryClipboardAdapter


class TestSprint4ClipboardPerformance(unittest.TestCase):
    # тесты производительности буфера обмена

    def _make_service(self) -> ClipboardService:
        # сервис с InMemory-адаптером и таймаутом 30 с
        adapter = InMemoryClipboardAdapter()
        return ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 30})

    def test_perf_copy_under_100ms(self) -> None:
        # PERF-1: copy_to_clipboard < 100 ms
        svc = self._make_service()
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            t0 = time.perf_counter()
            svc.copy_to_clipboard("Password!123", data_type="password", source_entry_id="1")
            dt_ms = (time.perf_counter() - t0) * 1000.0
        self.assertLess(dt_ms, 100.0)

    def test_perf_monitor_idle_cpu_under_1_percent(self) -> None:
        # PERF-2: монитор в idle < 1% CPU за 2 с
        svc = self._make_service()
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            svc.start()
            try:
                wall_start = time.perf_counter()
                cpu_start = time.process_time()
                time.sleep(2.0)
                wall = time.perf_counter() - wall_start
                cpu = time.process_time() - cpu_start
            finally:
                svc.stop()
        # процессорная доля за интервал
        cpu_percent = (cpu / wall) * 100.0 if wall > 0 else 100.0
        self.assertLess(cpu_percent, 1.0)

    def test_perf_memory_overhead_under_10mb(self) -> None:
        # PERF-3: пик памяти после 200 копий < 10 MB
        tracemalloc.start()
        svc = self._make_service()
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            for i in range(200):
                svc.copy_to_clipboard(f"secret-{i}", data_type="password", source_entry_id=str(i))
            svc.stop()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertLess(peak, 10 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
