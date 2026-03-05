from __future__ import annotations

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QMainWindow,
    QStatusBar,
    QLabel,
    QMenu,
    QMenuBar,
    QMessageBox,
    QWidget,
    QVBoxLayout,
)

from PyQt6.QtGui import QGuiApplication

from src.core.config import get_default_config_manager
from src.core.events import get_event_bus
from src.core.state_manager import get_state_manager
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.settings_dialog import SettingsDialog
from src.gui.widgets.setup_wizard import SetupWizard
from src.gui.widgets.state_monitor import StateMonitor


# основное окно приложения на pyqt6
class MainWindow(QMainWindow):

    def __init__(self) -> None:
        super().__init__()

        # чуть увеличим окно, чтобы таблица и статус-бар смотрелись комфортно
        self.resize(900, 600)

        self.config_manager = get_default_config_manager()
        self._state_manager = get_state_manager()
        self.current_language = "ru"
        self.current_theme = "system"

        # гарантируем, что таймаут буфера положительный
        self.clipboard_timeout = max(
            1, int(self.config_manager.config.clipboard_timeout_seconds)
        )
        self.auto_lock_minutes = self.config_manager.config.auto_lock_minutes

        self._clipboard_seconds_left = self.clipboard_timeout
        # текущее состояние блокировки берём из StateManager
        self._locked = self._state_manager.state.locked
        self._bus = get_event_bus()

        self._table = SecureTable(self)
        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)
        layout.addWidget(self._table)
        self.setCentralWidget(central_widget)
        # применяем язык к заголовкам таблицы
        self._table.set_language(self.current_language)

        self._create_menu_bar()
        self._create_status_bar()

        self._clipboard_timer = QTimer(self)
        self._clipboard_timer.setInterval(1000)
        self._clipboard_timer.timeout.connect(self._update_clipboard_timer)
        self._clipboard_timer.start()
        # запускаем первый отсчёт
        self.reset_clipboard_timer()

        # реагируем на любое изменение системного буфера обмена
        QGuiApplication.clipboard().dataChanged.connect(self.reset_clipboard_timer)

        self._apply_language()
        self._apply_theme()

    # ===== Меню и статус =====

    def _create_menu_bar(self) -> None:
        menu_bar = QMenuBar(self)
        self.setMenuBar(menu_bar)

        # File
        self.file_menu = QMenu("Файл", self)
        menu_bar.addMenu(self.file_menu)

        # мастер-пароль и первичная настройка
        self.action_new = self.file_menu.addAction("Мастер-пароль / первое создание")
        self.action_new.triggered.connect(self._open_setup_wizard)

        self.action_backup = self.file_menu.addAction("Резервная копия")
        self.action_exit = self.file_menu.addAction("Выход")
        self.action_exit.triggered.connect(self.close)

        # Edit
        self.edit_menu = QMenu("Правка", self)
        menu_bar.addMenu(self.edit_menu)
        self.action_add = self.edit_menu.addAction("Добавить")
        self.action_edit = self.edit_menu.addAction("Изменить")
        self.action_delete = self.edit_menu.addAction("Удалить")
        self.action_add.triggered.connect(self._on_add_entry)
        self.action_edit.triggered.connect(self._on_edit_entry)
        self.action_delete.triggered.connect(self._on_delete_entry)

        # View
        self.view_menu = QMenu("Вид", self)
        menu_bar.addMenu(self.view_menu)

        self.action_view_logs = self.view_menu.addAction("Журнал аудита")
        self.action_view_logs.triggered.connect(self._open_audit_log_viewer)
        self.action_state_monitor = self.view_menu.addAction("Монитор состояний")
        self.action_state_monitor.triggered.connect(self._open_state_monitor)

        self.action_toggle_lock = self.view_menu.addAction("Заблокировать")
        self.action_toggle_lock.triggered.connect(self._toggle_lock_state)

        # Settings / Help
        self.settings_menu = QMenu("Настройки", self)
        menu_bar.addMenu(self.settings_menu)

        self.action_settings = self.settings_menu.addAction("Параметры...")
        self.action_settings.triggered.connect(self._open_settings_dialog)

        self.help_menu = QMenu("Справка", self)
        menu_bar.addMenu(self.help_menu)
        self.help_menu.addAction("О программе", self._show_about)

    def _create_status_bar(self) -> None:
        status = QStatusBar(self)
        self.setStatusBar(status)

        self.lock_label = QLabel(self)
        self.clipboard_label = QLabel(self)

        status.addWidget(self.lock_label)
        status.addWidget(self.clipboard_label)

        self._update_lock_label()
        self._update_clipboard_label()

    # ===== Таймер буфера и блокировка =====

    def reset_clipboard_timer(self) -> None:
        # на всякий случай не даём таймауту быть меньше 1
        timeout = max(1, int(self.clipboard_timeout))
        self._clipboard_seconds_left = timeout
        self._update_clipboard_label()
        # EVT-1: считаем, что пользователь скопировал что-то в буфер
        self._bus.publish(
            "ClipboardCopied",
            {"when": "now", "timeout": timeout},
        )

    def _update_clipboard_timer(self) -> None:
        if self._clipboard_seconds_left > 0:
            self._clipboard_seconds_left -= 1
            if self._clipboard_seconds_left == 0:
                # EVT-1: буфер "очищен" (реальная очистка будет позже)
                self._bus.publish("ClipboardCleared", {"when": "timer"})
        self._update_clipboard_label()

    def _update_clipboard_label(self) -> None:
        if self.current_language == "ru":
            if self._clipboard_seconds_left > 0:
                text = f"Буфер: очистка через {self._clipboard_seconds_left} с"
            else:
                text = "Буфер: очищен"
        else:
            if self._clipboard_seconds_left > 0:
                text = f"Clipboard: clears in {self._clipboard_seconds_left} s"
            else:
                text = "Clipboard: cleared"
        self.clipboard_label.setText(text)

    def _toggle_lock_state(self) -> None:
        # текущее состояние всегда берём из StateManager
        locked_now = self._state_manager.state.locked
        # EVT-1: простые события логина/логаута
        if locked_now:
            self._bus.publish("UserLoggedOut", None)
        else:
            self._bus.publish("UserLoggedIn", None)
        # синхронизируем локальный флаг и обновляем подпись
        self._locked = self._state_manager.state.locked
        self._update_lock_label()

    def _update_lock_label(self) -> None:
        # перед отрисовкой всегда берём актуальное состояние
        self._locked = self._state_manager.state.locked
        if self.current_language == "ru":
            text = "Статус: заблокировано" if self._locked else "Статус: разблокировано"
        else:
            text = "Status: locked" if self._locked else "Status: unlocked"
        self.lock_label.setText(text)

    # ===== Диалоги =====

    def _open_settings_dialog(self) -> None:
        dlg = SettingsDialog(
            self,
            clipboard_timeout=self.clipboard_timeout,
            auto_lock_minutes=self.auto_lock_minutes,
            current_language=self.current_language,
            current_theme=self.current_theme,
        )
        dlg.languageChanged.connect(self._change_language)
        dlg.themeChanged.connect(self._change_theme)

        if dlg.exec():
            self.clipboard_timeout = max(1, dlg.clipboard_spin.value())
            self.auto_lock_minutes = dlg.auto_lock_spin.value()
            self.config_manager.set("clipboard_timeout_seconds", self.clipboard_timeout)
            self.config_manager.set("auto_lock_minutes", self.auto_lock_minutes)
            self.reset_clipboard_timer()

    # открыть мастер первого запуска и вернуть результат exec()
    def _open_setup_wizard(self) -> int:
        wizard = SetupWizard(self)
        return wizard.exec()

    def _open_audit_log_viewer(self) -> None:
        viewer = AuditLogViewer(self)
        viewer.exec()

    def _open_state_monitor(self) -> None:
        monitor = StateMonitor(self)
        monitor.exec()

    def _show_about(self) -> None:
        QMessageBox.information(
            self,
            "О программе",
            "CryptoSafe Manager\nПростой GUI-шелл на PyQt6.",
        )

    # ===== простые заглушки для добавления/изменения/удаления =====

    # заглушка для добавления записи
    def _on_add_entry(self) -> None:
        # EVT-1: создаём заглушечное событие добавления записи
        self._bus.publish("EntryAdded", {"entry_id": None, "source": "menu"})
        if self.current_language == "ru":
            text = "Добавление записи будет реализовано в следующем спринте."
        else:
            text = "Add entry will be implemented in a later sprint."
        QMessageBox.information(self, "Информация", text)

    # заглушка для изменения записи
    def _on_edit_entry(self) -> None:
        self._bus.publish("EntryUpdated", {"entry_id": None, "source": "menu"})
        if self.current_language == "ru":
            text = "Редактирование записи будет реализовано в следующем спринте."
        else:
            text = "Edit entry will be implemented in a later sprint."
        QMessageBox.information(self, "Информация", text)

    # заглушка для удаления записи
    def _on_delete_entry(self) -> None:
        self._bus.publish("EntryDeleted", {"entry_id": None, "source": "menu"})
        if self.current_language == "ru":
            text = "Удаление записи будет реализовано в следующем спринте."
        else:
            text = "Delete entry will be implemented in a later sprint."
        QMessageBox.information(self, "Информация", text)

    # ===== Тема и язык =====

    def _change_language(self, code: str) -> None:
        self.current_language = code
        self._apply_language()

    def _change_theme(self, code: str) -> None:
        self.current_theme = code
        self._apply_theme()

    def _apply_language(self) -> None:
        # язык может меняться в любой момент, поэтому синхронизируем флаг
        self._locked = self._state_manager.state.locked
        if self.current_language == "ru":
            self.setWindowTitle("CryptoSafe Manager")
            self.file_menu.setTitle("Файл")
            self.edit_menu.setTitle("Правка")
            self.view_menu.setTitle("Вид")
            self.settings_menu.setTitle("Настройки")
            self.help_menu.setTitle("Справка")
            self.action_new.setText("Мастер-пароль / первое создание")
            self.action_backup.setText("Резервная копия")
            self.action_exit.setText("Выход")
            self.action_view_logs.setText("Журнал аудита")
            self.action_state_monitor.setText("Монитор состояний")
            self.action_toggle_lock.setText("Заблокировать" if not self._locked else "Разблокировать")
            self.action_settings.setText("Параметры...")
        else:
            self.setWindowTitle("CryptoSafe Manager")
            self.file_menu.setTitle("File")
            self.edit_menu.setTitle("Edit")
            self.view_menu.setTitle("View")
            self.settings_menu.setTitle("Settings")
            self.help_menu.setTitle("Help")
            self.action_new.setText("Master password / first setup")
            self.action_backup.setText("Backup")
            self.action_exit.setText("Exit")
            self.action_view_logs.setText("Audit Log")
            self.action_state_monitor.setText("State monitor")
            self.action_toggle_lock.setText("Lock" if not self._locked else "Unlock")
            self.action_settings.setText("Preferences...")

        self._update_lock_label()
        self._update_clipboard_label()
        # обновляем язык у таблицы
        self._table.set_language(self.current_language)

    def _apply_theme(self) -> None:
        app = QApplication.instance()
        if app is None:
            return

        if self.current_theme == "dark":
            app.setStyleSheet(
                """
                QMainWindow { background-color: #202124; color: #ffffff; }
                QMenuBar, QMenu, QStatusBar { background-color: #303134; color: #ffffff; }
                QStatusBar QLabel { color: #ffffff; }
                QTableWidget { 
                    background-color: #202124; 
                    color: #ffffff; 
                    gridline-color: #3c4043;
                    selection-background-color: #3c4043;
                    selection-color: #ffffff;
                }
                QHeaderView::section {
                    background-color: #202124;
                    color: #ffffff;
                    border: 1px solid #3c4043;
                }
                QPushButton { background-color: #3c4043; color: #ffffff; }
                """
            )
        elif self.current_theme == "light":
            app.setStyleSheet(
                """
                QMainWindow { background-color: #ffffff; color: #000000; }
                QMenuBar, QMenu, QStatusBar { background-color: #f1f3f4; color: #000000; }
                QStatusBar QLabel { color: #000000; }
                QTableWidget { background-color: #ffffff; color: #000000; gridline-color: #dadce0; }
                QPushButton { background-color: #e8eaed; color: #000000; }
                """
            )
        else:
            app.setStyleSheet("")


def run_app() -> None:
    # простой запуск приложения
    import sys

    app = QApplication(sys.argv)
    window = MainWindow()
    # Сначала показываем мастер первого запуска.
    # Если пользователь нажал Отмена или закрыл окно, приложение завершается.
    result = window._open_setup_wizard()
    if result != QDialog.DialogCode.Accepted:
        return

    # после успешного мастера считаем, что пользователь вошёл
    window._locked = False
    window._bus.publish("UserLoggedIn", None)
    window._update_lock_label()

    window.show()
    sys.exit(app.exec())

