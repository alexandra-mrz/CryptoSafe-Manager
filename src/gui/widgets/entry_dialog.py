# диалог добавления записи: название, логин, пароль, url

from __future__ import annotations

from PyQt6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from .password_entry import PasswordEntry


class EntryDialog(QDialog):
    def __init__(self, parent=None, title: str = "", username: str = "", password: str = "", url: str = "") -> None:
        super().__init__(parent)
        self.setWindowTitle("Добавить запись")

        self.title_edit = QLineEdit(self)
        self.title_edit.setPlaceholderText("Название")
        self.title_edit.setText(title)

        self.username_edit = QLineEdit(self)
        self.username_edit.setPlaceholderText("Логин")
        self.username_edit.setText(username)

        self.password_entry = PasswordEntry(self)
        self.password_entry.setText(password)

        self.url_edit = QLineEdit(self)
        self.url_edit.setPlaceholderText("URL")
        self.url_edit.setText(url)

        form = QFormLayout()
        form.addRow("Название", self.title_edit)
        form.addRow("Логин", self.username_edit)
        form.addRow("Пароль", self.password_entry)
        form.addRow("URL", self.url_edit)

        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Отмена")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.ok_button)
        buttons.addWidget(self.cancel_button)

        main = QVBoxLayout(self)
        main.addLayout(form)
        main.addLayout(buttons)

    def get_title(self) -> str:
        return self.title_edit.text().strip()

    def get_username(self) -> str:
        return self.username_edit.text().strip()

    def get_password(self) -> str:
        return self.password_entry.text()

    def get_url(self) -> str:
        return self.url_edit.text().strip()
