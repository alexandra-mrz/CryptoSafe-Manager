
from __future__ import annotations

# Sprint 7 / CFG-1..CFG-3: профили безопасности и настройки Sprint 7

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


# диалог настроек с тремя вкладками
class SettingsDialog(QDialog):

    """Публичный класс SettingsDialog."""
    languageChanged = pyqtSignal(str)
    themeChanged = pyqtSignal(str)

    def __init__(
        self,
        parent=None,
        clipboard_timeout: int = 30,
        auto_lock_minutes: int = 5,
        current_language: str = "ru",
        current_theme: str = "system",
        notifications_enabled: bool = True,
        security_level: str = "basic",
        app_whitelist: str = "",
        activity_sensitivity: str = "medium",
        device_type: str = "desktop",
        minimize_to_tray: bool = True,
        start_minimized: bool = False,
        panic_stealth: bool = False,
        panic_quit: bool = False,
        security_profile: str = "standard",
    ) -> None:
        super().__init__(parent)

        self.setWindowTitle("Настройки")

        self.tabs = QTabWidget(self)

        security_tab = self._create_security_tab(
            clipboard_timeout,
            auto_lock_minutes,
            notifications_enabled,
            security_level,
            app_whitelist,
            activity_sensitivity,
            device_type,
            minimize_to_tray,
            start_minimized,
            panic_stealth,
            panic_quit,
            security_profile,
        )
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

    def _create_security_tab(
        self,
        clipboard_timeout: int,
        auto_lock_minutes: int,
        notifications_enabled: bool,
        security_level: str,
        app_whitelist: str,
        activity_sensitivity: str,
        device_type: str,
        minimize_to_tray: bool,
        start_minimized: bool,
        panic_stealth: bool,
        panic_quit: bool,
        security_profile: str,
    ):
        widget = QWidget(self)
        layout = QFormLayout(widget)

        self.profile_combo = QComboBox(widget)
        self.profile_combo.addItem("Standard — баланс", "standard")
        self.profile_combo.addItem("Enhanced — усиленная защита", "enhanced")
        self.profile_combo.addItem("Paranoid — максимум", "paranoid")
        pidx = self.profile_combo.findData(security_profile)
        if pidx >= 0:
            self.profile_combo.setCurrentIndex(pidx)
        self.profile_combo.currentIndexChanged.connect(self._apply_security_profile)

        self.clipboard_spin = QSpinBox(widget)
        self.clipboard_spin.setRange(0, 300)
        self.clipboard_spin.setValue(clipboard_timeout)

        self.auto_lock_spin = QSpinBox(widget)
        self.auto_lock_spin.setRange(1, 480)
        self.auto_lock_spin.setValue(auto_lock_minutes)

        self.sensitivity_combo = QComboBox(widget)
        self.sensitivity_combo.addItem("Низкая", "low")
        self.sensitivity_combo.addItem("Средняя", "medium")
        self.sensitivity_combo.addItem("Высокая", "high")
        sidx = self.sensitivity_combo.findData(activity_sensitivity)
        if sidx >= 0:
            self.sensitivity_combo.setCurrentIndex(sidx)

        self.device_combo = QComboBox(widget)
        self.device_combo.addItem("Настольный ПК", "desktop")
        self.device_combo.addItem("Ноутбук", "laptop")
        didx = self.device_combo.findData(device_type)
        if didx >= 0:
            self.device_combo.setCurrentIndex(didx)

        self.notify_checkbox = QCheckBox("Показывать уведомления буфера", widget)
        self.notify_checkbox.setChecked(bool(notifications_enabled))

        self.security_level_combo = QComboBox(widget)
        self.security_level_combo.addItem("basic", "basic")
        self.security_level_combo.addItem("advanced", "advanced")
        self.security_level_combo.addItem("paranoid", "paranoid")
        sec_idx = self.security_level_combo.findData(str(security_level))
        if sec_idx >= 0:
            self.security_level_combo.setCurrentIndex(sec_idx)

        self.whitelist_edit = QLineEdit(widget)
        self.whitelist_edit.setPlaceholderText("app1.exe, app2.exe")
        self.whitelist_edit.setText(str(app_whitelist or ""))

        self.minimize_tray_check = QCheckBox("Сворачивать в трей", widget)
        self.minimize_tray_check.setChecked(minimize_to_tray)
        self.start_minimized_check = QCheckBox("Запуск свёрнутым в трей", widget)
        self.start_minimized_check.setChecked(start_minimized)
        self.panic_stealth_check = QCheckBox("Stealth: fake error при панике", widget)
        self.panic_stealth_check.setChecked(panic_stealth)
        self.panic_quit_check = QCheckBox("Закрыть приложение после паники", widget)
        self.panic_quit_check.setChecked(panic_quit)

        layout.addRow("Профиль безопасности", self.profile_combo)
        layout.addRow("Таймаут буфера (сек., 0 = никогда)", self.clipboard_spin)
        layout.addRow("Автоблокировка (мин., 1–480)", self.auto_lock_spin)
        layout.addRow("Чувствительность активности", self.sensitivity_combo)
        layout.addRow("Тип устройства", self.device_combo)
        layout.addRow("Уведомления", self.notify_checkbox)
        layout.addRow("Уровень безопасности", self.security_level_combo)
        layout.addRow("Whitelist приложений", self.whitelist_edit)
        layout.addRow("", self.minimize_tray_check)
        layout.addRow("", self.start_minimized_check)
        layout.addRow("", self.panic_stealth_check)
        layout.addRow("", self.panic_quit_check)

        return widget

    def _apply_security_profile(self) -> None:
        # CFG-1: подставить значения профиля в поля
        profile = str(self.profile_combo.currentData() or "standard")
        if profile == "standard":
            self.clipboard_spin.setValue(30)
            self.auto_lock_spin.setValue(5)
            self.sensitivity_combo.setCurrentIndex(self.sensitivity_combo.findData("medium"))
            self.security_level_combo.setCurrentIndex(self.security_level_combo.findData("basic"))
            self.panic_stealth_check.setChecked(False)
        elif profile == "enhanced":
            self.clipboard_spin.setValue(15)
            self.auto_lock_spin.setValue(3)
            self.sensitivity_combo.setCurrentIndex(self.sensitivity_combo.findData("high"))
            self.security_level_combo.setCurrentIndex(self.security_level_combo.findData("advanced"))
            self.panic_stealth_check.setChecked(False)
        elif profile == "paranoid":
            self.clipboard_spin.setValue(5)
            self.auto_lock_spin.setValue(1)
            self.sensitivity_combo.setCurrentIndex(self.sensitivity_combo.findData("high"))
            self.security_level_combo.setCurrentIndex(self.security_level_combo.findData("paranoid"))
            self.panic_stealth_check.setChecked(True)

    def _create_appearance_tab(self, current_language: str, current_theme: str):
        widget = QWidget(self)
        layout = QFormLayout(widget)

        self.language_combo = QComboBox(widget)
        self.language_combo.addItem("Русский", "ru")
        self.language_combo.addItem("English", "en")
        index = self.language_combo.findData(current_language)
        if index >= 0:
            self.language_combo.setCurrentIndex(index)
        self.language_combo.currentIndexChanged.connect(self._emit_language_changed)

        self.theme_combo = QComboBox(widget)
        self.theme_combo.addItem("Системная", "system")
        self.theme_combo.addItem("Светлая", "light")
        self.theme_combo.addItem("Тёмная", "dark")
        t_index = self.theme_combo.findData(current_theme)
        if t_index >= 0:
            self.theme_combo.setCurrentIndex(t_index)
        self.theme_combo.currentIndexChanged.connect(self._emit_theme_changed)

        layout.addRow("Язык", self.language_combo)
        layout.addRow("Тема", self.theme_combo)

        return widget

    def _create_advanced_tab(self):
        widget = QWidget(self)
        layout = QVBoxLayout(widget)

        layout.addWidget(
            QLabel(
                "Резервная копия и восстановление — меню «Файл».\n"
                "Экспорт/импорт записей — меню «Данные»."
            )
        )
        return widget

    def accept(self) -> None:
        """Accept."""
        super().accept()

    def _emit_language_changed(self) -> None:
        lang_code = self.language_combo.currentData()
        if isinstance(lang_code, str):
            self.languageChanged.emit(lang_code)

    def _emit_theme_changed(self) -> None:
        theme_code = self.theme_combo.currentData()
        if isinstance(theme_code, str):
            self.themeChanged.emit(theme_code)
