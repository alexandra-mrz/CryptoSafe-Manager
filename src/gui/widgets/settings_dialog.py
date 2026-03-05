from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


# диалог настроек с тремя вкладками
class SettingsDialog(QDialog):

    languageChanged = pyqtSignal(str)
    themeChanged = pyqtSignal(str)

    def __init__(self, parent=None, clipboard_timeout: int = 30, auto_lock_minutes: int = 5,
                 current_language: str = "ru", current_theme: str = "system") -> None:
        super().__init__(parent)

        self.setWindowTitle("Настройки")

        self.tabs = QTabWidget(self)

        # вкладка безопасности
        security_tab = self._create_security_tab(clipboard_timeout, auto_lock_minutes)
        appearance_tab = self._create_appearance_tab(current_language, current_theme)
        advanced_tab = self._create_advanced_tab()

        self.tabs.addTab(security_tab, "Безопасность")
        self.tabs.addTab(appearance_tab, "Вид")
        self.tabs.addTab(advanced_tab, "Дополнительно")

        buttons_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Отмена")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        buttons_layout.addStretch(1)
        buttons_layout.addWidget(self.ok_button)
        buttons_layout.addWidget(self.cancel_button)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(self.tabs)
        main_layout.addLayout(buttons_layout)

    def _create_security_tab(self, clipboard_timeout: int, auto_lock_minutes: int):
        widget = QWidget(self)
        layout = QFormLayout(widget)

        self.clipboard_spin = QSpinBox(widget)
        self.clipboard_spin.setRange(5, 600)
        self.clipboard_spin.setValue(clipboard_timeout)

        self.auto_lock_spin = QSpinBox(widget)
        self.auto_lock_spin.setRange(1, 120)
        self.auto_lock_spin.setValue(auto_lock_minutes)

        layout.addRow("Таймаут буфера (сек.)", self.clipboard_spin)
        layout.addRow("Автоблокировка (мин.)", self.auto_lock_spin)

        return widget

    def _create_appearance_tab(self, current_language: str, current_theme: str):
        widget = QWidget(self)
        layout = QFormLayout(widget)

        self.language_combo = QComboBox(widget)
        self.language_combo.addItem("Русский", "ru")
        self.language_combo.addItem("English", "en")
        index = self.language_combo.findData(current_language)
        if index >= 0:
            self.language_combo.setCurrentIndex(index)
        # живое обновление языка
        self.language_combo.currentIndexChanged.connect(self._emit_language_changed)

        self.theme_combo = QComboBox(widget)
        self.theme_combo.addItem("Системная", "system")
        self.theme_combo.addItem("Светлая", "light")
        self.theme_combo.addItem("Тёмная", "dark")
        t_index = self.theme_combo.findData(current_theme)
        if t_index >= 0:
            self.theme_combo.setCurrentIndex(t_index)
        # живое обновление темы
        self.theme_combo.currentIndexChanged.connect(self._emit_theme_changed)

        layout.addRow("Язык", self.language_combo)
        layout.addRow("Тема", self.theme_combo)

        return widget

    def _create_advanced_tab(self):
        widget = QWidget(self)
        layout = QVBoxLayout(widget)

        layout.addWidget(QLabel("backup и экспорт будут добавлены в следующих спринтах."))
        return widget

    def accept(self) -> None:
        # при нажатии ok изменения уже отправлены сигналами
        # здесь просто закрываем диалог
        super().accept()

    def _emit_language_changed(self) -> None:
        lang_code = self.language_combo.currentData()
        if isinstance(lang_code, str):
            self.languageChanged.emit(lang_code)

    def _emit_theme_changed(self) -> None:
        theme_code = self.theme_combo.currentData()
        if isinstance(theme_code, str):
            self.themeChanged.emit(theme_code)

