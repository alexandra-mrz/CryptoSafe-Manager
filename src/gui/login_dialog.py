# Окно входа — приветствие и понятный запрос пароля

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QPushButton, QMessageBox, QLineEdit
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from src.gui.widgets.password_entry import PasswordEntry


class LoginDialog(QDialog):
    """Экран входа: название приложения, пояснение, логин, пароль, кнопки."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("CryptoSafe Manager — Вход")
        # Фиксированный комфортный размер, чтобы всё сразу было видно
        self.setFixedSize(620, 260)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        main = QVBoxLayout(self)
        main.setSpacing(20)
        main.setContentsMargins(28, 28, 28, 28)

        # Заголовок
        title = QLabel("CryptoSafe Manager")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        main.addWidget(title)

        hint = QLabel("Введите логин и пароль для доступа к хранилищу паролей.")
        hint.setWordWrap(True)
        hint.setAlignment(Qt.AlignCenter)
        hint.setStyleSheet("color: #555;")
        main.addWidget(hint)

        # Простая форма логин/пароль во всю ширину
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        form.setContentsMargins(0, 8, 0, 0)

        self._username_edit = QLineEdit()
        self._username_edit.setPlaceholderText("Например: ivan.petrov")
        self._username_edit.setMinimumWidth(320)
        form.addRow("Имя пользователя (логин):", self._username_edit)

        self._password = PasswordEntry(self)
        self._password.setMinimumWidth(320)
        form.addRow("Пароль:", self._password)

        main.addLayout(form)

        main.addStretch()

        # Кнопки
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_exit = QPushButton("Выход")
        btn_exit.clicked.connect(self.reject)
        btn_open = QPushButton("Открыть")
        btn_open.setDefault(True)
        btn_open.setAutoDefault(True)
        btn_open.clicked.connect(self._on_login)
        btn_open.setMinimumWidth(100)
        btn_row.addWidget(btn_exit)
        btn_row.addWidget(btn_open)
        main.addLayout(btn_row)

    def _on_login(self):
        username = (self._username_edit.text() or "").strip()
        pwd = self._password.get().strip()
        if not username:
            QMessageBox.warning(self, "Вход", "Введите имя пользователя (логин).")
            return
        if not pwd:
            QMessageBox.warning(self, "Вход", "Введите пароль для входа в хранилище.")
            return
        # Заглушка проверки: пока просто принимаем любые логин и пароль
        self.accept()
