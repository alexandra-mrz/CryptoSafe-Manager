
from __future__ import annotations

from PyQt6.QtWidgets import (
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QMessageBox,
)

from src.database.db import get_default_database

from src.core.crypto.authentication import set_master_password, unlock_session

from .password_entry import PasswordEntry


# простой мастер первого запуска
class SetupWizard(QDialog):

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Первый запуск")

        self.master_password = PasswordEntry(self)
        self.master_confirm = PasswordEntry(self)

        self.db_path_edit = QLineEdit(self)
        self.db_browse_button = QPushButton("Выбрать...")
        self.db_browse_button.clicked.connect(self._choose_db_path)

        self.kdf_params_edit = QLineEdit(self)
        self.kdf_params_edit.setPlaceholderText("Параметры KDF (заглушка)")

        form = QFormLayout()
        form.addRow("Мастер-пароль", self.master_password)
        form.addRow("Подтверждение", self.master_confirm)

        db_layout = QHBoxLayout()
        db_layout.addWidget(self.db_path_edit)
        db_layout.addWidget(self.db_browse_button)
        form.addRow("Путь к базе данных", db_layout)

        form.addRow("Настройки шифрования", self.kdf_params_edit)

        buttons_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Отмена")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        buttons_layout.addStretch(1)
        buttons_layout.addWidget(self.ok_button)
        buttons_layout.addWidget(self.cancel_button)

        main_layout = QVBoxLayout(self)
        main_layout.addLayout(form)
        main_layout.addLayout(buttons_layout)

    def _choose_db_path(self) -> None:
        file_name, _ = QFileDialog.getSaveFileName(self, "Выбор базы данных", "", "DB Files (*.db);;All Files (*)")
        if file_name:
            self.db_path_edit.setText(file_name)

    # проверяем, что мастер-пароль введён и совпадает с подтверждением
    # без этого мастер не закрывается
    def accept(self) -> None:
        pwd = self.master_password.text()
        confirm = self.master_confirm.text()
        db_path = self.db_path_edit.text().strip()

        if not pwd:
            QMessageBox.warning(self, "Ошибка", "Мастер-пароль не может быть пустым.")
            return

        if pwd != confirm:
            QMessageBox.warning(self, "Ошибка", "Пароль и подтверждение не совпадают.")
            return

        if not db_path:
            QMessageBox.warning(self, "Ошибка", "Нужно выбрать файл базы данных.")
            return

        try:
            get_default_database()
            set_master_password(pwd)
            unlock_session(pwd)
        except ValueError as e:
            QMessageBox.warning(self, "Ошибка", str(e))
            return
        super().accept()
