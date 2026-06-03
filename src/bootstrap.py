from __future__ import annotations

# Sprint 8 / INT-1, INT-4: единая инициализация подсистем Sprints 1–7
#
# Порядок слоёв (INT-2 — без циклических зависимостей):
#   1. src.database     — схема и доступ к SQLite
#   2. src.core.events  — шина событий
#   3. src.core.crypto  — KDF, ключи, аутентификация
#   4. src.core.security — hardening (Sprint 7)
#   5. src.core.vault / clipboard / import_export / audit — доменная логика
#   6. src.core.state_manager — фоновое состояние сессии
#   7. src.gui          — PyQt6 (импортировать после core)

import sys
from typing import Optional

_initialized = False


def initialize_application(*, preload_gui: bool = False) -> None:
    """
    INT-1: подключить все подсистемы приложения одним вызовом.
    Идемпотентно — повторный вызов безопасен.
    """
    global _initialized
    if _initialized:
        return

    # Sprint 1 — конфигурация и события
    from src.core.config import get_default_config_manager  # noqa: F401
    from src.core.events import get_event_bus

    bus = get_event_bus()

    # Sprint 5 — аудит (подписки на EventBus)
    from src.core.audit.audit_logger import setup_audit_subscribers

    setup_audit_subscribers(bus)

    # Sprint 1 — state manager (фоновый поток, settings)
    from src.core.state_manager import get_state_manager

    get_state_manager()

    # Sprint 7 — модуль интеграции hardening (lazy hooks, без GUI)
    from src.core.security import integration as _security_integration  # noqa: F401

    _ = _security_integration

    if preload_gui:
        import src.gui.main_window  # noqa: F401

    _initialized = True


def main(argv: Optional[list[str]] = None) -> None:
    """INT-4: точка входа `python -m src` / run.py."""
    _ = argv
    initialize_application()
    from src.gui.main_window import run_app

    run_app()


if __name__ == "__main__":
    main(sys.argv[1:])
