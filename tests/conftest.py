from __future__ import annotations

# Sprint 8 / TEST-4: маркировка perf/slow для быстрого прогона по умолчанию

import pytest

@pytest.fixture(autouse=True)
def _reset_io_abort_flag() -> None:
    """Сброс флага прерывания import/export после panic-тестов."""
    from src.core.security.integration import set_io_aborted

    set_io_aborted(False)
    yield
    set_io_aborted(False)


_PERF_MODULES = frozenset(
    {
        "test_perf_sprint3",
        "test_perf_sprint4",
        "test_perf_sprint5",
        "test_perf_sprint7",
        "test_gui_pyautogui",
        "test_integration_app",
    }
)

_SLOW_MODULES = frozenset(
    {
        "test_sprint6_validation",
        "test_audit_sprint5_validation",
        "test_sprint8_io",
        "test_sprint8_src_coverage",
        "test_sprint8_extended",
        "test_sprint8_io_integration",
        "test_sprint8_coverage_boost",
    }
)

_PERF_CLASSES = frozenset({"TestSprint6Performance"})

_SLOW_TESTS = frozenset(
    {
        "test_crud_integration_100_entries",
        "test_concurrency_simple",
        "test_generator_10000",
        "test_pbkdf2_same_input_same_output_100_times",
        "test_memory_security_with_win32",
        "test_auto_clear_timing_within_100ms",
        "test_default_params_yield_valid_hash",
        "test_different_time_cost_yield_valid_hashes",
        "test_different_memory_cost_yield_valid_hashes",
        "test_different_parallelism_yield_valid_hashes",
    }
)

_PERF_TESTS = frozenset(
    {
        "test_perf3_qr_generation_under_100ms",
        "test_export_import_1000_performance",
    }
)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        mod = item.module.__name__.rsplit(".", 1)[-1]
        cls = getattr(item, "cls", None)
        cls_name = cls.__name__ if cls is not None else ""

        if mod in _PERF_MODULES or cls_name in _PERF_CLASSES or item.name in _PERF_TESTS:
            item.add_marker(pytest.mark.perf)
        elif mod in _SLOW_MODULES or item.name in _SLOW_TESTS:
            item.add_marker(pytest.mark.slow)
