# Диалог настроек — вкладки: Безопасность, Внешний вид, Дополнительно (тема и язык работают)

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget, QFormLayout,
    QLabel, QLineEdit, QComboBox, QPushButton, QMessageBox
)
from PyQt5.QtCore import Qt

from src.core.settings_store import get_setting, set_setting
from src.gui.theme import apply_theme, apply_saved_theme


THEMES = ["Светлая", "Тёмная"]
LANGUAGES = ["Русский", "English"]


class SettingsDialog(QDialog):
    """Диалог настроек со вкладками; тема и язык сохраняются и применяются."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки")
        self.setMinimumSize(440, 300)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        if parent:
            self.setWindowModality(Qt.WindowModal)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        tabs = QTabWidget()

        # Безопасность
        sec = QWidget()
        sec_layout = QFormLayout(sec)
        sec_layout.setSpacing(10)
        self._clipboard_timeout = QLineEdit()
        self._clipboard_timeout.setPlaceholderText("секунды")
        self._clipboard_timeout.setText(str(get_setting("clipboard_timeout", "30")))
        sec_layout.addRow("Таймаут буфера обмена (сек):", self._clipboard_timeout)
        self._autolock = QLineEdit()
        self._autolock.setPlaceholderText("секунды")
        self._autolock.setText(str(get_setting("autolock_seconds", "300")))
        sec_layout.addRow("Авто-блокировка (сек):", self._autolock)
        tabs.addTab(sec, "Безопасность")

        # Внешний вид — тема и язык
        app = QWidget()
        app_layout = QFormLayout(app)
        self._theme_combo = QComboBox()
        self._theme_combo.addItems(THEMES)
        idx = self._theme_combo.findText(get_setting("theme", "Светлая"))
        if idx >= 0:
            self._theme_combo.setCurrentIndex(idx)
        app_layout.addRow("Тема:", self._theme_combo)
        self._lang_combo = QComboBox()
        self._lang_combo.addItems(LANGUAGES)
        idx = self._lang_combo.findText(get_setting("language", "Русский"))
        if idx >= 0:
            self._lang_combo.setCurrentIndex(idx)
        app_layout.addRow("Язык:", self._lang_combo)
        tabs.addTab(app, "Внешний вид")

        # Дополнительно
        adv = QWidget()
        adv_layout = QVBoxLayout(adv)
        adv_layout.addWidget(QLabel("Резервное копирование и экспорт настраиваются отдельно."))
        tabs.addTab(adv, "Дополнительно")

        layout.addWidget(tabs)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_save = QPushButton("Сохранить")
        btn_save.setMinimumWidth(90)
        btn_save.clicked.connect(self._save)
        btn_close = QPushButton("Закрыть")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_save)
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)

    def _save(self):
        try:
            timeout = self._clipboard_timeout.text().strip()
            if timeout.isdigit():
                set_setting("clipboard_timeout", timeout)
            lock = self._autolock.text().strip()
            if lock.isdigit():
                set_setting("autolock_seconds", lock)
            theme = self._theme_combo.currentText()
            set_setting("theme", theme)
            lang = self._lang_combo.currentText()
            set_setting("language", lang)
            from PyQt5.QtWidgets import QApplication
            app = QApplication.instance()
            if app:
                apply_theme(app, theme)
            QMessageBox.information(self, "Настройки", "Настройки сохранены. Тема применена.\nЯзык вступит в силу после перезапуска.")
        except Exception:
            QMessageBox.warning(self, "Ошибка", "Не удалось сохранить настройки.")
