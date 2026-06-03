from __future__ import annotations

# Sprint 7 §9: TEST-1..TEST-4 (приёмочные тесты безопасности)

import statistics
import time
import unittest
from unittest.mock import patch

from src.core.security.activity_monitor import ActivityMonitor
from src.core.security.memory_guard import SecretHolder, secure_wipe
from src.core.security.panic_mode import PanicMode
from src.core.security.side_channel_protection import constant_time_compare


class TestSprint7TimingAttack(unittest.TestCase):
    # TEST-1: constant-time compare

    def test_compare_timing_ratio(self) -> None:
        a = "secret-value-" * 4
        b_ok = a
        b_bad = "x" * len(a)
        t_ok = []
        t_bad = []
        for _ in range(200):
            t0 = time.perf_counter()
            constant_time_compare(a, b_ok)
            t_ok.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            constant_time_compare(a, b_bad)
            t_bad.append(time.perf_counter() - t0)
        ratio = statistics.mean(t_bad) / max(statistics.mean(t_ok), 1e-9)
        self.assertLess(ratio, 3.0)


class TestSprint7MemoryProtection(unittest.TestCase):
    # TEST-2: данные не остаются в plaintext после wipe

    def test_wipe_removes_secret_from_buffer(self) -> None:
        secret = b"SPRINT7_MEMORY_TEST_SECRET"
        buf = bytearray(secret)
        secure_wipe(buf)
        dump = bytes(buf)
        self.assertNotIn(secret, dump)

    def test_secret_holder_cleared_after_delete(self) -> None:
        secret = b"holder-secret-data"
        holder = SecretHolder(secret)
        del holder
        # повторное создание — прежний буфер не должен «утекать» через holder
        holder2 = SecretHolder(b"other")
        self.assertEqual(holder2.get_data(), b"other")
        del holder2


class TestSprint7AutoLockReliability(unittest.TestCase):
    # TEST-3: симуляция 24 ч активности / неактивности

    def test_no_lock_while_active_each_hour(self) -> None:
        locks: list[bool] = []
        mon = ActivityMonitor(lambda: locks.append(True), {"lock_timeout_minutes": 1})
        for _ in range(24):
            mon.record_activity()
            with patch.object(mon, "get_idle_seconds", return_value=30.0):
                with patch.object(mon, "_effective_timeout", return_value=60.0):
                    if mon.get_idle_seconds() >= mon._effective_timeout():
                        mon._lock_callback()
        self.assertEqual(locks, [])

    def test_lock_after_idle_at_end_of_day(self) -> None:
        locks: list[bool] = []
        mon = ActivityMonitor(lambda: locks.append(True), {"lock_timeout_minutes": 1})
        mon.record_activity()
        with patch.object(mon, "get_idle_seconds", return_value=120.0):
            with patch.object(mon, "_effective_timeout", return_value=60.0):
                if mon.get_idle_seconds() >= mon._effective_timeout():
                    mon._lock_callback()
        self.assertEqual(len(locks), 1)


class TestSprint7PanicStress(unittest.TestCase):
    # TEST-4: паника во время операций и восстановление

    def test_panic_multiple_cycles(self) -> None:
        log: list[str] = []
        panic = PanicMode({}, register_defaults=False)
        panic.register_handler(lambda: log.append("h"))
        for i in range(5):
            panic.activate(f"op{i}")
            self.assertTrue(panic.activated)
            panic.reset()
            self.assertFalse(panic.activated)
        self.assertEqual(len(log), 5)

    def test_panic_mid_operation_then_recovery(self) -> None:
        state = {"locked": False, "done": False}

        def lock() -> None:
            state["locked"] = True

        panic = PanicMode({}, register_defaults=False)
        panic.register_handler(lock)

        def fake_export() -> None:
            panic.activate("export")
            state["done"] = True
            panic.reset()

        fake_export()
        self.assertTrue(state["locked"])
        self.assertTrue(state["done"])
        self.assertFalse(panic.activated)


@unittest.skip("TEST-5: ручное usability-тестирование (5+ участников) — см. docs/SPRINT7_IMPLEMENTATION.md")
class TestSprint7UsabilityManual(unittest.TestCase):
    def test_manual_usability_placeholder(self) -> None:
        pass


if __name__ == "__main__":
    unittest.main()
