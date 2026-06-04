from __future__ import annotations

from urllib.parse import urlparse

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QPixmap
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkRequest
from PyQt6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QCheckBox,
    QVBoxLayout,
)

from .password_entry import PasswordEntry
from src.core.vault.password_generator import PasswordGenOptions, generate_password


class _PasswordGenDialog(QDialog):
    """Окно настроек генератора пароля."""
    def __init__(self, parent=None) -> None:
        """Создать диалог генератора."""
        super().__init__(parent)
        self.setWindowTitle("Генератор пароля")

        self.length_spin = QSpinBox(self)
        self.length_spin.setRange(8, 64)
        self.length_spin.setValue(16)

        self.cb_upper = QCheckBox("A-Z", self)
        self.cb_upper.setChecked(True)
        self.cb_lower = QCheckBox("a-z", self)
        self.cb_lower.setChecked(True)
        self.cb_digits = QCheckBox("0-9", self)
        self.cb_digits.setChecked(True)
        self.cb_symbols = QCheckBox("!@#$%^&*", self)
        self.cb_symbols.setChecked(True)

        form = QFormLayout()
        form.addRow("Длина", self.length_spin)
        form.addRow("Наборы", QLabel("Выберите, что включать"))
        form.addRow("", self.cb_upper)
        form.addRow("", self.cb_lower)
        form.addRow("", self.cb_digits)
        form.addRow("", self.cb_symbols)

        btn_ok = QPushButton("Сгенерировать", self)
        btn_cancel = QPushButton("Отмена", self)
        btn_ok.clicked.connect(self.accept)
        btn_cancel.clicked.connect(self.reject)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(btn_ok)
        buttons.addWidget(btn_cancel)

        main = QVBoxLayout(self)
        main.addLayout(form)
        main.addLayout(buttons)

    def options(self) -> PasswordGenOptions:
        """Вернуть выбранные настройки."""
        return PasswordGenOptions(
            length=int(self.length_spin.value()),
            use_uppercase=bool(self.cb_upper.isChecked()),
            use_lowercase=bool(self.cb_lower.isChecked()),
            use_digits=bool(self.cb_digits.isChecked()),
            use_symbols=bool(self.cb_symbols.isChecked()),
        )


class EntryDialog(QDialog):
    """Диалог создания/редактирования записи."""
    def __init__(
        self,
        parent=None,
        title: str = "",
        username: str = "",
        password: str = "",
        url: str = "",
        notes: str = "",
        category: str = "",
        tags: str = "",
    ) -> None:
        """Создать форму записи."""
        super().__init__(parent)
        self.setWindowTitle("Добавить запись")
        self._password_was_generated = False
        self._net = QNetworkAccessManager(self)
        self._last_favicon_url = ""

        self.title_edit = QLineEdit(self)
        self.title_edit.setPlaceholderText("Название")
        self.title_edit.setText(title)

        self.username_edit = QLineEdit(self)
        self.username_edit.setPlaceholderText("Логин")
        self.username_edit.setText(username)

        self.password_entry = PasswordEntry(self)
        self.password_entry.setText(password)
        self.password_entry.textChanged.connect(self._update_strength)

        self.strength_bar = QProgressBar(self)
        self.strength_bar.setRange(0, 4)
        self.strength_bar.setValue(0)
        self.strength_label = QLabel("Сила пароля: 0/4", self)

        self.btn_generate = QPushButton("Сгенерировать…", self)
        self.btn_generate.clicked.connect(self._on_generate_clicked)

        self.url_edit = QLineEdit(self)
        self.url_edit.setPlaceholderText("URL")
        self.url_edit.setText(url)
        self.url_edit.textChanged.connect(self._on_url_changed)

        self.favicon_label = QLabel(self)
        self.favicon_label.setFixedSize(16, 16)
        self.favicon_label.setScaledContents(True)

        self.notes_edit = QLineEdit(self)
        self.notes_edit.setPlaceholderText("Заметки")
        self.notes_edit.setText(notes)

        self.category_edit = QLineEdit(self)
        self.category_edit.setPlaceholderText("Категория")
        self.category_edit.setText(category)

        self.tags_edit = QLineEdit(self)
        self.tags_edit.setPlaceholderText("Теги")
        self.tags_edit.setText(tags)

        form = QFormLayout()
        form.addRow("Название", self.title_edit)
        form.addRow("Логин", self.username_edit)
        form.addRow("Пароль", self.password_entry)
        strength_row = QHBoxLayout()
        strength_row.addWidget(self.strength_bar, 1)
        strength_row.addWidget(self.strength_label)
        form.addRow("", strength_row)
        form.addRow("", self.btn_generate)

        url_row = QHBoxLayout()
        url_row.addWidget(self.url_edit, 1)
        url_row.addWidget(self.favicon_label)
        form.addRow("URL", url_row)
        form.addRow("Заметки", self.notes_edit)
        form.addRow("Категория", self.category_edit)
        form.addRow("Теги", self.tags_edit)

        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Отмена")
        self.ok_button.clicked.connect(self._on_ok_clicked)
        self.cancel_button.clicked.connect(self.reject)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.ok_button)
        buttons.addWidget(self.cancel_button)

        main = QVBoxLayout(self)
        main.addLayout(form)
        main.addLayout(buttons)

        self._update_strength(self.password_entry.text())
        self._on_url_changed(self.url_edit.text())

    def get_title(self) -> str:
        """Вернуть title."""
        return self.title_edit.text().strip()

    def get_username(self) -> str:
        """Вернуть username."""
        return self.username_edit.text().strip()

    def get_password(self) -> str:
        """Вернуть password."""
        return self.password_entry.text()

    def get_url(self) -> str:
        """Вернуть URL."""
        return self.url_edit.text().strip()

    def get_notes(self) -> str:
        """Вернуть notes."""
        return self.notes_edit.text().strip()

    def get_category(self) -> str:
        """Вернуть category."""
        return self.category_edit.text().strip()

    def get_tags(self) -> str:
        """Вернуть tags."""
        return self.tags_edit.text().strip()

    def _score_password(self, pw: str) -> int:
        """Посчитать простую силу пароля 0..4."""
        score = 0
        if len(pw) >= 12:
            score += 1
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
            score += 1
        if any(c.isdigit() for c in pw):
            score += 1
        if any(not c.isalnum() for c in pw):
            score += 1
        return score

    def _update_strength(self, pw: str) -> None:
        """Обновить индикатор силы."""
        score = self._score_password(pw)
        self.strength_bar.setValue(score)
        self.strength_label.setText(f"Сила пароля: {score}/4")

    def _on_generate_clicked(self) -> None:
        """Открыть генератор и подставить пароль."""
        dlg = _PasswordGenDialog(self)
        if not dlg.exec():
            return
        pw = generate_password(dlg.options())
        self._password_was_generated = True
        self.password_entry.setText(pw)
        self.password_entry.setFocusToEdit()

    def _normalize_url(self, text: str) -> str:
        """Нормализовать и проверить URL."""
        raw = (text or "").strip()
        if not raw:
            return ""
        if " " in raw:
            return ""
        if "://" not in raw:
            raw = "https://" + raw
        try:
            p = urlparse(raw)
            if not p.netloc:
                return ""
            return raw
        except Exception:
            return ""

    def _favicon_url(self, url_text: str) -> str:
        """Собрать ссылку на favicon."""
        url_norm = self._normalize_url(url_text)
        if not url_norm:
            return ""
        p = urlparse(url_norm)
        host = p.netloc
        if not host:
            return ""
        return f"{p.scheme}://{host}/favicon.ico"

    def _on_url_changed(self, text: str) -> None:
        """Проверить URL, обновить favicon и подсказку login."""
        url_norm = self._normalize_url(text)
        if text.strip() and not url_norm:
            self.url_edit.setStyleSheet("border: 1px solid #d93025;")
        else:
            self.url_edit.setStyleSheet("")

        fav_url = self._favicon_url(text)
        if not fav_url or fav_url == self._last_favicon_url:
            return
        self._last_favicon_url = fav_url
        self._fetch_favicon(fav_url)

        if not self.username_edit.text().strip() and url_norm:
            dom = urlparse(url_norm).netloc.split(":")[0]
            if dom and "." in dom:
                self.username_edit.setPlaceholderText(f"user@{dom}")

    def _fetch_favicon(self, fav_url: str) -> None:
        """Запросить favicon по сети."""
        req = QNetworkRequest(QUrl(fav_url))
        reply = self._net.get(req)
        reply.finished.connect(lambda: self._on_favicon_reply(reply))

    def _on_favicon_reply(self, reply) -> None:
        """Принять и отобразить favicon."""
        try:
            data = reply.readAll().data()
            if data:
                pix = QPixmap()
                if pix.loadFromData(data):
                    self.favicon_label.setPixmap(pix)
        finally:
            reply.deleteLater()

    def _on_ok_clicked(self) -> None:
        """Проверить форму и закрыть диалог."""
        title = self.get_title()
        pw = self.get_password()
        if not title:
            QMessageBox.warning(self, "Ошибка", "Название обязательно.")
            return
        if not pw:
            QMessageBox.warning(self, "Ошибка", "Пароль обязателен.")
            return

        if self.url_edit.text().strip() and not self._normalize_url(self.url_edit.text()):
            QMessageBox.warning(self, "Ошибка", "Некорректный URL.")
            return

        if not self._password_was_generated:
            if self._score_password(pw) < 3:
                QMessageBox.warning(self, "Ошибка", "Пароль слишком слабый (нужно >= 3/4).")
                return

        self.accept()
