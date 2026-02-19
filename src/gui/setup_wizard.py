# Первый запуск — создание хранилища с понятными подсказками

import os
import secrets
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QFileDialog, QMessageBox, QGroupBox, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from src.core.config import get_config
from src.core.validation import validate_password_length, sanitize_string
from src.gui.widgets.password_entry import PasswordEntry


class SetupWizard(QDialog):
    """Первый запуск: приветствие, создание пароля и выбор места хранения данных."""

    def __init__(self, parent=None, on_success=None):
        super().__init__(parent)
        self.on_success = on_success
        self.setWindowTitle("CryptoSafe Manager — Первый запуск")
        self.setMinimumSize(480, 420)
        self.setFixedSize(500, 460)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        main = QVBoxLayout(self)
        main.setSpacing(16)
        main.setContentsMargins(28, 28, 28, 28)

        # Приветствие
        title = QLabel("Создание хранилища паролей")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        main.addWidget(title)

        hint = QLabel(
            "Создайте учётную запись: логин и мастер-пароль. "
            "Мастер-пароль используется для шифрования данных и входа в программу. "
            "Запомните его — без него доступ к хранилищу невозможен."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #555; margin-bottom: 8px;")
        main.addWidget(hint)

        # Учётная запись (логин)
        grp_user = QGroupBox("Учётная запись")
        grp_user.setStyleSheet("QGroupBox { font-weight: bold; }")
        ly_user = QVBoxLayout(grp_user)
        ly_user.addWidget(QLabel("Имя пользователя (логин):"))
        self._username_edit = QLineEdit()
        self._username_edit.setPlaceholderText("Например: ivan.petrov")
        self._username_edit.setMinimumWidth(320)
        ly_user.addWidget(self._username_edit)
        main.addWidget(grp_user)

        # Пароль
        grp_pwd = QGroupBox("Мастер-пароль")
        grp_pwd.setStyleSheet("QGroupBox { font-weight: bold; }")
        ly_pwd = QVBoxLayout(grp_pwd)
        ly_pwd.addWidget(QLabel("Придумайте пароль:"))
        self._pw1 = PasswordEntry(self)
        self._pw1.setMinimumWidth(320)
        ly_pwd.addWidget(self._pw1)
        ly_pwd.addWidget(QLabel("Повторите пароль:"))
        self._pw2 = PasswordEntry(self)
        self._pw2.setMinimumWidth(320)
        ly_pwd.addWidget(self._pw2)
        main.addWidget(grp_pwd)

        # Где хранить данные
        grp_db = QGroupBox("Где хранить данные")
        ly_db = QVBoxLayout(grp_db)
        ly_db.addWidget(QLabel("Файл базы данных (можно оставить по умолчанию):"))
        path_row = QHBoxLayout()
        self._db_path_edit = QLineEdit()
        self._db_path_edit.setText(get_config().db_path)
        self._db_path_edit.setPlaceholderText("Путь к файлу хранилища")
        path_row.addWidget(self._db_path_edit)
        btn_browse = QPushButton("Обзор...")
        btn_browse.setFixedWidth(80)
        btn_browse.clicked.connect(self._browse_db)
        path_row.addWidget(btn_browse)
        ly_db.addLayout(path_row)
        main.addWidget(grp_db)

        main.addStretch()

        # Кнопки
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_cancel = QPushButton("Отмена")
        btn_cancel.clicked.connect(self.reject)
        btn_ok = QPushButton("Создать хранилище")
        btn_ok.setDefault(True)
        btn_ok.setMinimumWidth(140)
        btn_ok.clicked.connect(self._submit)
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(btn_ok)
        main.addLayout(btn_row)

    def _browse_db(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Выбор файла хранилища",
            self._db_path_edit.text() or os.path.expanduser("~"),
            "База данных (*.db);;Все файлы (*)"
        )
        if path:
            self._db_path_edit.setText(path)

    def _submit(self):
        username = sanitize_string(self._username_edit.text())
        if not username:
            QMessageBox.warning(self, "Ошибка", "Введите имя пользователя (логин).")
            return
        p1 = sanitize_string(self._pw1.get())
        p2 = sanitize_string(self._pw2.get())
        if not p1 or not p2:
            QMessageBox.warning(self, "Ошибка", "Введите пароль и повторите его в обоих полях.")
            return
        if p1 != p2:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают. Проверьте поле «Повторите пароль».")
            return
        if not validate_password_length(p1, min_len=4):
            QMessageBox.warning(self, "Ошибка", "Пароль должен быть не короче 4 символов.")
            return
        db_path = sanitize_string(self._db_path_edit.text())
        if not db_path:
            QMessageBox.warning(self, "Ошибка", "Укажите путь к файлу хранилища.")
            return
        cfg = get_config()
        cfg.db_path = db_path
        from src.database.db import get_db
        get_db().init_schema()
        # Сохраняем логин в настройках (простая заглушка для будущего использования)
        try:
            from src.core.settings_store import set_setting
            set_setting("master_username", username)
        except Exception:
            pass
        salt = secrets.token_bytes(16)
        with get_db().get_connection() as conn:
            conn.execute(
                "INSERT INTO key_store (key_type, salt, hash, params) VALUES (?, ?, ?, ?)",
                ("master", salt, b"", "{}")
            )
        if self.on_success:
            self.on_success()
        self.accept()
