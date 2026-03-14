from __future__ import annotations

from PyQt6.QtWidgets import QDialog, QFormLayout, QHBoxLayout, QMessageBox, QPushButton, QVBoxLayout

from src.core.crypto.authentication import get_failed_attempt_count, unlock_session
from src.core.state_manager import get_state_manager

from .password_entry import PasswordEntry


# диалог входа по мастер-паролю (AUTH-1: после первой настройки вместо setup)
class LoginDialog(QDialog):
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
            QMessageBox.warning(self, "Ошибка", "Неверный пароль. Попробуйте снова.")
