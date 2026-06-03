from __future__ import annotations

# Sprint 8 / TEST-1: clipboard — доп. unit-тесты (быстрый прогон + coverage)

import threading
import unittest
from unittest.mock import patch

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.platform_adapter import InMemoryClipboardAdapter, create_platform_adapter


class TestSprint8ClipboardFull(unittest.TestCase):
    def test_factory_all_platforms(self) -> None:
        for system, name in (
            ("Windows", "WindowsClipboardAdapter"),
            ("Darwin", "MacOSClipboardAdapter"),
            ("Linux", "LinuxClipboardAdapter"),
        ):
            with patch("src.core.clipboard.platform_adapter.platform.system", return_value=system):
                self.assertEqual(type(create_platform_adapter()).__name__, name)

    def test_rapid_copy_threads(self) -> None:
        adapter = InMemoryClipboardAdapter()
        service = ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 5})
        errors: list[str] = []

        def worker(prefix: str) -> None:
            try:
                for i in range(15):
                    service.copy_to_clipboard(f"{prefix}-{i}", data_type="password")
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))

        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            threads = [threading.Thread(target=worker, args=(f"t{n}",)) for n in range(3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(errors, [])
        service.stop()
        self.assertEqual(adapter.get_clipboard_content(), "")

    def test_get_status_after_copy(self) -> None:
        adapter = InMemoryClipboardAdapter()
        service = ClipboardService(platform_adapter=adapter, config={"clipboard_timeout": 10})
        with patch("src.core.clipboard.clipboard_service.is_session_unlocked", return_value=True):
            service.copy_to_clipboard("note text", data_type="notes")
            status = service.get_clipboard_status()
            self.assertTrue(status.get("active"))
            service.clear_clipboard()
            self.assertFalse(service.get_clipboard_status().get("active"))
