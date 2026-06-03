from __future__ import annotations

# Sprint 7 / ACT-4, PLAT-1: вход по мастер-паролю (+ Secure Desktop на Windows)

from PyQt6.QtWidgets import QDialog, QFormLayout, QHBoxLayout, QMessageBox, QPushButton, QVBoxLayout

from src.core.crypto.authentication import get_failed_attempt_count, unlock_session
from src.core.events import get_event_bus
from src.core.security.platform_security import prompt_with_secure_desktop_fallback
from src.core.state_manager import get_state_manager
from src.gui.ux_helpers import show_user_error

from .password_entry import PasswordEntry


# ACT-4: повторная аутентификация после auto-lock / panic
class LoginDialog(QDialog):
    """Публичный класс LoginDialog."""
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Вход")

        self.password_entry = PasswordEntry(self)
        form = QFormLayout()
        form.addRow("Мастер-пароль", self.password_entry)

        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Отмена")
        self.ok_button.clicked.connect(self._on_ok)
        self.cancel_button.clicked.connect(self.reject)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.ok_button)
        buttons.addWidget(self.cancel_button)

        main = QVBoxLayout(self)
        main.addLayout(form)
        main.addLayout(buttons)

    def exec(self) -> int:
        # PLAT-1: Secure Desktop на Windows (fallback — обычный диалог)
        """Exec."""
        _used_secure, code = prompt_with_secure_desktop_fallback(lambda: super().exec())
        return code

    def _on_ok(self) -> None:
        pwd = self.password_entry.text()
        if not pwd:
            QMessageBox.warning(self, "Ошибка", "Введите мастер-пароль.")
            return
        if unlock_session(pwd):
            self.accept()
        else:
            sm = get_state_manager()
            sm.state.failed_attempt_count = get_failed_attempt_count()
            get_event_bus().publish(
                "LoginFailed",
                {"source": "login_dialog", "attempts": get_failed_attempt_count()},
            )
            show_user_error(self, "wrong_password")
