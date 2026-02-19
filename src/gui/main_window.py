# Главное окно — меню, центральная таблица, строка состояния

import datetime
import os
import sys

if __name__ == "__main__" or not __package__:
    _root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if _root not in sys.path:
        sys.path.insert(0, _root)

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QMenuBar, QMenu, QAction,
    QStatusBar, QMessageBox, QFileDialog, QApplication, QToolBar
)
from PyQt5.QtCore import QTimer, Qt

from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.settings_dialog import SettingsDialog
from src.core.config import get_config
from src.core.state_manager import get_state_manager
from src.core.events import get_event_bus, USER_LOGGED_IN, ENTRY_ADDED
from src.database.db import get_db
from src.core.audit_stub import register_audit_handlers


def _ensure_db_and_tables():
    """Проверяет наличие БД."""
    cfg = get_config()
    if not os.path.isfile(cfg.db_path):
        return False
    try:
        get_db(cfg.db_path).init_schema()
        return True
    except Exception:
        return False


class MainWindow(QMainWindow):
    """Главное окно приложения."""

    def __init__(self):
        super().__init__()
        register_audit_handlers()
        self.setWindowTitle("CryptoSafe Manager")
        self.setMinimumSize(640, 440)
        self.resize(860, 520)
        self.setAttribute(Qt.WA_QuitOnClose, True)

        self._state = get_state_manager()
        self._bus = get_event_bus()

        # Меню
        menubar = self.menuBar()
        file_menu = menubar.addMenu("Файл")
        file_menu.addAction("Создать", self._on_file_new)
        file_menu.addAction("Открыть", self._on_file_open)
        file_menu.addSeparator()
        file_menu.addAction("Резервная копия", self._on_backup)
        file_menu.addSeparator()
        file_menu.addAction("Выход", self._on_quit)

        edit_menu = menubar.addMenu("Правка")
        edit_menu.addAction("Добавить", self._on_add)
        edit_menu.addAction("Изменить", self._on_edit)
        edit_menu.addAction("Удалить", self._on_delete)

        view_menu = menubar.addMenu("Вид")
        view_menu.addAction("Логи", self._on_view_logs)
        view_menu.addAction("Настройки", self._on_settings)

        help_menu = menubar.addMenu("Справка")
        help_menu.addAction("О программе", self._on_about)

        # Панель инструментов
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setStyleSheet("QToolBar { spacing: 6px; padding: 4px; }")
        toolbar.addAction("Добавить", self._on_add)
        toolbar.addAction("Изменить", self._on_edit)
        toolbar.addAction("Удалить", self._on_delete)
        self.addToolBar(toolbar)

        # Центральная область с отступами
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(12, 8, 12, 12)
        layout.setSpacing(8)
        self._table = SecureTable(self)
        self._table.setStyleSheet("QTableWidget { border: 1px solid #ccc; border-radius: 4px; gridline-color: #e0e0e0; }")
        layout.addWidget(self._table)

        # Строка состояния
        self._status = self.statusBar()
        self._status.showMessage("Готово")
        self._login_status = "Сессия: разблокировано"
        self._clipboard_timer_text = "Буфер: —"
        self._update_status_bar()

        self._log_window = None
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update_clipboard_timer)
        self._timer.start(1000)

    def _update_status_bar(self):
        self._status.showMessage(f"{self._login_status}  |  {self._clipboard_timer_text}  |  Готово")

    def _update_clipboard_timer(self):
        remain = self._state.get_clipboard_timer_remaining()
        if remain is not None and remain > 0:
            self._clipboard_timer_text = f"Буфер: очистка через {int(remain)} с"
        else:
            self._clipboard_timer_text = "Буфер: —"
        self._update_status_bar()

    def _load_test_data(self):
        self._table.clear()
        try:
            db = get_db()
            with db.get_connection() as conn:
                rows = conn.execute(
                    "SELECT id, title, username, url, updated_at FROM vault_entries ORDER BY updated_at DESC"
                ).fetchall()
                for r in rows:
                    self._table.add_row(
                        r["id"],
                        r["title"] or "",
                        r["username"] or "",
                        r["url"] or "",
                        r["updated_at"] or ""
                    )
                if not rows:
                    now = datetime.datetime.now(datetime.UTC).isoformat()
                    self._table.add_row(0, "Пример 1", "user1", "https://example.com", now)
                    self._table.add_row(0, "Пример 2", "user2", "", now)
        except Exception:
            self._table.add_row(0, "Тест 1", "user1", "https://test.com", "")
            self._table.add_row(0, "Тест 2", "user2", "", "")

    def _on_file_new(self):
        self._status.showMessage("Создать — заглушка")

    def _on_file_open(self):
        self._status.showMessage("Открыть — заглушка")

    def _on_backup(self):
        get_db().backup("")
        self._status.showMessage("Резервная копия — заглушка")

    def _on_quit(self):
        self.close()
        QApplication.instance().quit()

    def _on_add(self):
        self._bus.publish(ENTRY_ADDED, entry_id=None)
        self._status.showMessage("Добавить запись — заглушка")

    def _on_edit(self):
        self._status.showMessage("Изменить — заглушка")

    def _on_delete(self):
        self._status.showMessage("Удалить — заглушка")

    def _on_view_logs(self):
        if self._log_window is None or not self._log_window.isVisible():
            from PyQt5.QtWidgets import QDialog, QVBoxLayout
            self._log_window = QDialog(self)
            self._log_window.setWindowTitle("Журнал аудита")
            ly = QVBoxLayout(self._log_window)
            ly.addWidget(AuditLogViewer(self._log_window))
            self._log_window.resize(500, 350)
        self._log_window.show()
        self._log_window.raise_()
        self._log_window.activateWindow()

    def _on_settings(self):
        dlg = SettingsDialog(self)
        dlg.exec_()

    def _on_about(self):
        QMessageBox.about(self, "О программе", "CryptoSafe Manager")

    def show_and_load(self):
        """Вызывается после показа окна: загрузка данных и обновление статуса."""
        self._state.set_session_unlocked()
        self._bus.publish(USER_LOGGED_IN)
        self._load_test_data()
        self.show()
        self.raise_()
        self.activateWindow()


def run_app():
    """Запуск: сначала всегда окно с паролем (мастер настройки или вход), затем главное окно."""
    app = QApplication(sys.argv)
    app.setApplicationName("CryptoSafe Manager")
    from PyQt5.QtWidgets import QDialog

    if not _ensure_db_and_tables():
        from src.gui.setup_wizard import SetupWizard
        wizard = SetupWizard(parent=None, on_success=None)
        if wizard.exec_() != QDialog.Accepted:
            sys.exit(0)
    else:
        from src.gui.login_dialog import LoginDialog
        login = LoginDialog(parent=None)
        if login.exec_() != QDialog.Accepted:
            sys.exit(0)

    from src.gui.theme import apply_saved_theme
    apply_saved_theme(app)
    win = MainWindow()
    win.show_and_load()
    sys.exit(app.exec_())


def main():
    run_app()


if __name__ == "__main__":
    main()
