from .gui.main_window import run_app  # noqa: F401
# импортируем audit_logger и state_manager, чтобы подписки
# и фоновый менеджер состояния гарантированно настроились
from .core import audit_logger  # noqa: F401
from .core import state_manager  # noqa: F401


if __name__ == "__main__":
    run_app()

