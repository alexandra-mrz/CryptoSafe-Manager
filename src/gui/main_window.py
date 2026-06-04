
# Sprint 7: главное окно — ACT, TRAY, PANIC, UX, CFG (см. docs/SPRINT7_IMPLEMENTATION.md)

from __future__ import annotations

import time
from datetime import datetime

from PyQt6.QtCore import QTimer, QEvent
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QInputDialog,
    QMainWindow,
    QStatusBar,
    QLabel,
    QMenu,
    QMenuBar,
    QMessageBox,
    QProgressDialog,
    QLineEdit,
    QToolBar,
    QWidget,
    QVBoxLayout,
    QSystemTrayIcon,
    QFileDialog,
)

from PyQt6.QtGui import QAction, QColor, QIcon, QKeySequence, QPainter, QPixmap
from difflib import SequenceMatcher

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.config import get_default_config_manager
from src.core.events import get_event_bus
from src.core.state_manager import get_state_manager, SETTING_AUTO_LOCK_TIMEOUT
from src.core.crypto.authentication import lock_session, has_master_password, verify_master_password
from src.core.crypto.key_storage import set_app_active, clear_all_keys
from src.core.vault.entry_manager import EntryManager
from src.core.vault.search_index import build_search_text
from src.core.audit.log_integrity import (
    get_integrity_status,
    get_verify_interval_hours,
    should_lock_on_tamper,
    verify_on_startup,
    verify_periodic,
)
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.widgets.change_password_dialog import ChangePasswordDialog
from src.gui.widgets.entry_dialog import EntryDialog
from src.gui.widgets.login_dialog import LoginDialog
from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.settings_dialog import SettingsDialog
from src.gui.widgets.setup_wizard import SetupWizard
from src.gui.widgets.state_monitor import StateMonitor
from src.gui.widgets.export_dialog import ExportDialog
from src.gui.widgets.import_dialog import ImportDialog
from src.gui.widgets.sharing_dialog import SharingDialog
from src.core.import_export.io_integration import (
    extract_share_package_from_qr_body,
    process_scanned_qr_body,
    scan_qr_from_camera_with_hint,
)
from src.core.import_export.key_exchange import KeyExchange
from src.core.import_export.qr_code_service import QRCodeService
from src.core.security.activity_monitor import ActivityMonitor
from src.core.security.integration import log_security_hardening, set_io_aborted
from src.core.security.panic_mode import PanicMode
from src.core.security.security_config import (
    SETTING_ACTIVITY_SENSITIVITY,
    SETTING_DEVICE_TYPE,
    SETTING_MINIMIZE_TO_TRAY,
    SETTING_PANIC_QUIT,
    SETTING_PANIC_STEALTH,
    SETTING_SECURITY_PROFILE,
    SETTING_START_MINIMIZED,
    PROFILE_STANDARD,
    SecuritySettings,
    non_default_warnings,
    profile_changes_text,
    validate_settings,
)
from src.gui.widgets.lock_overlay import LockOverlay
from src.gui.ux_helpers import USER_HINTS, run_with_progress, show_exception, show_user_error

# UX-4: порог «большого» vault — расшифровываем порциями
_LAZY_VAULT_LIMIT = 200

# TRAY-1: цвет иконки по состоянию (заметнее стандартных pixmap Qt)
_TRAY_COLOR_UNLOCKED = QColor(46, 125, 50)
_TRAY_COLOR_LOCKED = QColor(198, 40, 40)
_TRAY_COLOR_BUSY = QColor(251, 192, 45)


def _tray_icon_for_color(color: QColor) -> QIcon:
    pm = QPixmap(32, 32)
    pm.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(color)
    painter.setPen(QColor(255, 255, 255))
    painter.drawEllipse(4, 4, 24, 24)
    painter.end()
    return QIcon(pm)


class MainWindow(QMainWindow):

    """Публичный класс MainWindow."""
    def __init__(self) -> None:
        super().__init__()
        self.resize(900, 600)

        self.config_manager = get_default_config_manager()
        self._state_manager = get_state_manager()
        self.current_language = "ru"
        self.current_theme = "system"

        # CLIP-2: 0 = never auto-clear, иначе 5..300
        self.clipboard_timeout = int(self.config_manager.config.clipboard_timeout_seconds)
        if self.clipboard_timeout < 0:
            self.clipboard_timeout = 0
        elif 0 < self.clipboard_timeout < 5:
            self.clipboard_timeout = 5
        elif self.clipboard_timeout > 300:
            self.clipboard_timeout = 300
        self.auto_lock_minutes = self.config_manager.config.auto_lock_minutes
        self._activity_sensitivity = str(
            self._state_manager.get_setting(SETTING_ACTIVITY_SENSITIVITY, "medium") or "medium"
        )
        self._device_type = str(self._state_manager.get_setting(SETTING_DEVICE_TYPE, "desktop") or "desktop")
        self.minimize_to_tray = str(self._state_manager.get_setting(SETTING_MINIMIZE_TO_TRAY, "1")) == "1"
        self.start_minimized = str(self._state_manager.get_setting(SETTING_START_MINIMIZED, "0")) == "1"
        self._panic_stealth = str(self._state_manager.get_setting(SETTING_PANIC_STEALTH, "0")) == "1"
        self._panic_quit = str(self._state_manager.get_setting(SETTING_PANIC_QUIT, "0")) == "1"
        self._security_profile = str(
            self._state_manager.get_setting(SETTING_SECURITY_PROFILE, PROFILE_STANDARD) or PROFILE_STANDARD
        )
        self._saved_geometry = None
        self._shake_times: list[float] = []
        self._panic_saved_search = ""
        self._tray_crypto_busy = False
        self._tray_crypto_blink = False
        self._exit_requested = False
        self._app_shutdown_done = False
        # CFG-1: доп. настройки буфера
        self.clipboard_notifications_enabled = True
        self.clipboard_security_level = "basic"
        self.clipboard_whitelist = ""

        # CFG-2: читаем из settings (encrypted table)
        n = self._state_manager.get_setting("clipboard_notifications_enabled", "1")
        self.clipboard_notifications_enabled = str(n) == "1"
        lvl = self._state_manager.get_setting("clipboard_security_level", "basic")
        self.clipboard_security_level = str(lvl or "basic")
        wl = self._state_manager.get_setting("clipboard_app_whitelist", "")
        self.clipboard_whitelist = str(wl or "")

        self._clipboard_seconds_left = self.clipboard_timeout
        self._locked = self._state_manager.state.locked
        self._bus = get_event_bus()
        self._clipboard_service = ClipboardService(
            bus=self._bus,
            config={"clipboard_timeout": self.clipboard_timeout},
        )
        self._clipboard_service.set_block_future_copies_on_suspicious(self.clipboard_security_level == "paranoid")
        self._clipboard_service.subscribe(self._on_clipboard_service_event)
        self._entry_manager = EntryManager()
        self._all_entries_encrypted: list[dict] = []
        self._search_history: list[str] = []
        self._clipboard_warned_5s = False

        self._table = SecureTable(self)
        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)
        layout.addWidget(self._table)
        self.setCentralWidget(central_widget)
        self._lock_overlay = LockOverlay(central_widget)
        self._lock_overlay.unlockRequested.connect(self._prompt_unlock)
        self._table.set_language(self.current_language)
        self._table.editRequested.connect(self._on_edit_entry_id)
        self._table.deleteRequested.connect(self._on_delete_entry_ids)
        self._table.copyUsernameRequested.connect(self._on_copy_username)
        self._table.copyPasswordRequested.connect(self._on_copy_password)
        self._table.copyAllRequested.connect(self._on_copy_all)
        self._table.passwordToggleRequested.connect(self._on_password_toggle_requested)

        # ACT-1 / ACT-2: поток auto-lock
        self._activity_monitor = ActivityMonitor(self._on_auto_lock, self._activity_config())

        self._create_menu_bar()
        self._create_toolbar()
        self._create_status_bar()

        self._tray_crypto_timer = QTimer(self)
        self._tray_crypto_timer.setInterval(400)
        self._tray_crypto_timer.timeout.connect(self._tray_crypto_tick)
        # PANIC-1: default handlers в PanicMode; config — сервисы GUI
        self._panic_mode = PanicMode(self._panic_config())
        self._create_tray_icon()

        self._activity_monitor.start_monitoring()
        # ACT-1: глобальный фильтр mouse/key/focus
        self._bus.subscribe("UserLoggedOut", self._on_session_locked)
        self._bus.subscribe("VaultLocked", self._on_tray_security_event)
        self._bus.subscribe("VaultUnlocked", self._on_tray_security_event)
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)

        panic_hotkey = QAction(self)
        panic_hotkey.setShortcut(QKeySequence("Ctrl+Shift+Esc"))
        panic_hotkey.triggered.connect(lambda: self._activate_panic("hotkey"))
        self.addAction(panic_hotkey)

        self._clipboard_timer = QTimer(self)
        self._clipboard_timer.setInterval(1000)
        self._clipboard_timer.timeout.connect(self._update_clipboard_timer)
        self._clipboard_timer.start()
        self._clipboard_service.start()
        self.reset_clipboard_timer()

        self._apply_language()
        self._apply_theme()
        self._setup_ux_shortcuts()
        self._setup_ux_accessibility()

        # VER-2: периодическая проверка (по умолчанию 24 часа)
        self._integrity_timer = QTimer(self)
        hours = get_verify_interval_hours()
        self._integrity_timer.setInterval(hours * 60 * 60 * 1000)
        self._integrity_timer.timeout.connect(self._run_periodic_integrity_check)
        self._integrity_timer.start()
        self._update_integrity_label()

    def _setup_ux_shortcuts(self) -> None:
        # UX-1: горячие клавиши
        find_sc = QAction(self)
        find_sc.setShortcut(QKeySequence("Ctrl+F"))
        find_sc.triggered.connect(lambda: self.search_edit.setFocus())
        self.addAction(find_sc)
        lock_sc = QAction(self)
        lock_sc.setShortcut(QKeySequence("Ctrl+L"))
        lock_sc.triggered.connect(self._toggle_lock_state)
        self.addAction(lock_sc)
        add_sc = QAction(self)
        add_sc.setShortcut(QKeySequence("Ctrl+N"))
        add_sc.triggered.connect(self._on_add_entry)
        self.addAction(add_sc)
        del_sc = QAction(self)
        del_sc.setShortcut(QKeySequence("Delete"))
        del_sc.triggered.connect(self._on_delete_entry)
        self.addAction(del_sc)

    def _setup_ux_accessibility(self) -> None:
        # UX-1: подписи для screen readers
        if hasattr(self, "search_edit"):
            self.search_edit.setAccessibleName("Поле поиска записей")
        if hasattr(self, "lock_label"):
            self.lock_label.setAccessibleName("Статус блокировки хранилища")

    def showEvent(self, event) -> None:
        """Showevent."""
        set_app_active(True)
        super().showEvent(event)

    def hideEvent(self, event) -> None:
        # TRAY-3: в трей ключи и буфер не сбрасываем
        """Hideevent."""
        super().hideEvent(event)

    def changeEvent(self, event) -> None:
        # TRAY-4: свернуть в трей
        """Changeevent."""
        if (
            event.type() == QEvent.Type.WindowStateChange
            and self.minimize_to_tray
            and self.isMinimized()
        ):
            self._saved_geometry = self.geometry()
            self.hide()
            if hasattr(self, "_tray"):
                self._tray.showMessage("CryptoSafe", "Приложение в трее")
            event.accept()
            return
        super().changeEvent(event)

    def _shutdown_application(self) -> None:
        if self._app_shutdown_done:
            return
        self._app_shutdown_done = True
        self._activity_monitor.stop_monitoring()
        self._bus.publish("AppShutdown", {"source": "main_window"})
        self._clipboard_service.stop()
        clear_all_keys()
        lock_session()

    def _quit_application(self) -> None:
        # TRAY-2: «Выход» — всегда завершить процесс (не сворачивать в трей)
        self._exit_requested = True
        self._shutdown_application()
        if hasattr(self, "_tray"):
            self._tray.hide()
        self.hide()
        app = QApplication.instance()
        if app is not None:
            app.quit()

    def closeEvent(self, event) -> None:
        # TRAY-4: крестик → в трей; «Выход» из меню → _quit_application
        """Closeevent."""
        if (
            not self._exit_requested
            and self.minimize_to_tray
            and hasattr(self, "_tray")
            and QSystemTrayIcon.isSystemTrayAvailable()
        ):
            event.ignore()
            self._saved_geometry = self.geometry()
            self.hide()
            self._tray.showMessage("CryptoSafe", "Приложение в трее")
            return
        self._shutdown_application()
        event.accept()
        super().closeEvent(event)
        if self._exit_requested or not self.minimize_to_tray:
            app = QApplication.instance()
            if app is not None:
                app.quit()

    def _activity_config(self) -> dict:
        return {
            "lock_timeout_minutes": int(self.auto_lock_minutes),
            "activity_sensitivity": self._activity_sensitivity,
            "device_type": self._device_type,
            "check_interval": 1.0,
        }

    def _record_activity(self, source: str = "ui") -> None:
        self._activity_monitor.record_activity(source)
        self._bus.publish("UserActivity", {"source": source})

    def eventFilter(self, obj, event) -> bool:
        # ACT-1 / PANIC-1: мышь, клавиатура, фокус; shake окна
        """Eventfilter."""
        et = event.type()
        if et in (
            QEvent.Type.MouseMove,
            QEvent.Type.MouseButtonPress,
            QEvent.Type.KeyPress,
            QEvent.Type.WindowActivate,
        ):
            self._record_activity("ui")
        if et == QEvent.Type.Move and obj is self:
            now = time.monotonic()
            self._shake_times = [t for t in self._shake_times if now - t < 1.0]
            self._shake_times.append(now)
            if len(self._shake_times) >= 6:
                self._shake_times.clear()
                self._activate_panic("shake")
        return super().eventFilter(obj, event)

    def _panic_config(self) -> dict:
        # PANIC-1 / PANIC-2: делегирование в ClipboardService, lock, UI callbacks
        return {
            "stealth_mode": self._panic_stealth,
            "stealth_actions": {"show_fake_error": self._panic_stealth},
            "quit_app": self._panic_quit,
            "clipboard_service": self._clipboard_service,
            "state_manager": self._state_manager,
            "lock_callback": lambda: self._do_auto_lock("panic"),
            "close_windows_callback": self._close_other_windows,
            "hide_window_callback": self.hide,
            "quit_callback": self._maybe_quit_after_panic,
        }

    def _activate_panic(self, method: str) -> None:
        # PANIC-1: hotkey / tray / shake → activate
        if hasattr(self, "search_edit"):
            self._panic_saved_search = self.search_edit.text()
        self._panic_mode.update_config(self._panic_config())
        self._panic_mode.activate(method)

    def _close_other_windows(self) -> None:
        # PANIC-2: закрыть диалоги import/export/share
        app = QApplication.instance()
        if app is None:
            return
        for widget in app.topLevelWidgets():
            if widget is not self and widget.isVisible():
                widget.close()

    def _maybe_quit_after_panic(self) -> None:
        # PANIC-2: опционально завершить приложение
        if self._panic_quit:
            QApplication.instance().quit()

    def _on_auto_lock(self) -> None:
        self._do_auto_lock("auto_lock")

    def _do_auto_lock(self, source: str = "manual") -> None:
        # ACT-3: wipe keys, clipboard, скрыть пароли, overlay
        if self._state_manager.state.locked:
            return
        self._table.set_show_passwords(False)
        if self.clipboard_timeout > 0:
            self._clipboard_service.force_clear(reason=source)
            self.reset_clipboard_timer()
        clear_all_keys()
        lock_session()
        self._state_manager.state.locked = True
        self._locked = True
        self._bus.publish("UserLoggedOut", {"source": source})
        self._bus.publish("VaultLocked", {"source": source})
        log_security_hardening("system", "vault_locked", {"source": source})
        self._lock_overlay.show_overlay()
        self._update_lock_label()
        self._update_tray_icon()

    def _on_session_locked(self, event: str, payload) -> None:
        self._locked = True
        self._table.set_show_passwords(False)
        self._lock_overlay.show_overlay()
        self._update_lock_label()
        self._update_tray_icon()

    def _prompt_unlock(self) -> None:
        # ACT-4: мастер-пароль + проверка целостности + восстановление UI
        if get_integrity_status() == "tampered":
            QMessageBox.critical(self, "Безопасность", "Обнаружено вмешательство в журнал аудита.")
            return
        dlg = LoginDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._panic_mode.reset()
        set_io_aborted(False)  # INT-4: сброс прерывания I/O после unlock
        self._state_manager.state.locked = False
        self._locked = False
        self._lock_overlay.hide_overlay()
        self._bus.publish("UserLoggedIn", {"source": "lock_overlay"})
        self._bus.publish("VaultUnlocked", {"source": "lock_overlay"})
        self._record_activity("unlock")
        self._update_lock_label()
        self._update_tray_icon()
        if hasattr(self, "search_edit") and self._panic_saved_search:
            self.search_edit.setText(self._panic_saved_search)
            self._apply_search_filter(self._panic_saved_search)
        self._load_vault_entries()

    def _create_menu_bar(self) -> None:
        menu_bar = QMenuBar(self)
        self.setMenuBar(menu_bar)
        self.file_menu = QMenu("Файл", self)
        menu_bar.addMenu(self.file_menu)
        self.action_new = self.file_menu.addAction("Мастер-пароль / первое создание")
        self.action_new.triggered.connect(self._open_setup_wizard)

        self.action_backup = self.file_menu.addAction("Резервная копия...")
        self.action_backup.triggered.connect(self._on_backup_database)
        self.action_restore = self.file_menu.addAction("Восстановить из копии...")
        self.action_restore.triggered.connect(self._on_restore_database)
        self.data_menu = QMenu("Данные", self)
        menu_bar.addMenu(self.data_menu)
        self.action_export = self.data_menu.addAction("Экспорт...")
        self.action_import = self.data_menu.addAction("Импорт...")
        self.action_share = self.data_menu.addAction("Обмен записью...")
        self.action_scan_qr = self.data_menu.addAction("Сканировать QR (камера)...")
        self.action_export.triggered.connect(self._open_export_dialog)
        self.action_import.triggered.connect(self._open_import_dialog)
        self.action_share.triggered.connect(self._open_sharing_dialog)
        self.action_scan_qr.triggered.connect(self._on_scan_qr_camera)
        self.action_change_password = self.file_menu.addAction("Сменить мастер-пароль")
        self.action_exit = self.file_menu.addAction("Выход")
        self.action_exit.triggered.connect(self.close)
        self.action_change_password.triggered.connect(self._open_change_password_dialog)
        self.edit_menu = QMenu("Правка", self)
        menu_bar.addMenu(self.edit_menu)
        self.action_add = self.edit_menu.addAction("Добавить")
        self.action_edit = self.edit_menu.addAction("Изменить")
        self.action_delete = self.edit_menu.addAction("Удалить")
        self.action_clear_clipboard = self.edit_menu.addAction("Очистить буфер")
        self.action_reveal_clipboard = self.edit_menu.addAction("Показать буфер (пароль)")
        self.action_add.triggered.connect(self._on_add_entry)
        self.action_edit.triggered.connect(self._on_edit_entry)
        self.action_delete.triggered.connect(self._on_delete_entry)
        self.action_clear_clipboard.triggered.connect(self._on_clear_clipboard)
        self.action_reveal_clipboard.triggered.connect(self._on_reveal_clipboard)
        self.view_menu = QMenu("Вид", self)
        menu_bar.addMenu(self.view_menu)

        self.action_view_logs = self.view_menu.addAction("Журнал аудита")
        self.action_view_logs.triggered.connect(self._open_audit_log_viewer)
        self.action_state_monitor = self.view_menu.addAction("Монитор состояний")
        self.action_state_monitor.triggered.connect(self._open_state_monitor)

        self.action_toggle_lock = self.view_menu.addAction("Заблокировать")
        self.action_toggle_lock.triggered.connect(self._toggle_lock_state)
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
        self.integrity_label = QLabel(self)
        self.clipboard_label = QLabel(self)
        self.clipboard_preview_label = QLabel(self)

        status.addWidget(self.lock_label)
        status.addWidget(self.integrity_label)
        status.addWidget(self.clipboard_label)
        status.addWidget(self.clipboard_preview_label)

        self._update_lock_label()
        self._update_clipboard_label()
        self._update_clipboard_preview_label(masked=True)

        self._record_activity("unlock")
        self._update_lock_label()
        self._update_tray_icon()
        self._load_vault_entries()

    def _create_tray_icon(self) -> None:
        # TRAY-1 / TRAY-2
        if not QSystemTrayIcon.isSystemTrayAvailable():
            QMessageBox.warning(
                self,
                "Трей",
                "Системный трей недоступен. Иконка в области уведомлений не будет показана.",
            )
            return
        self._tray = QSystemTrayIcon(_tray_icon_for_color(_TRAY_COLOR_UNLOCKED), self)
        self._tray.setToolTip("CryptoSafe Manager")
        self.setWindowIcon(_tray_icon_for_color(_TRAY_COLOR_UNLOCKED))
        menu = QMenu(self)
        self._tray_action_lock = menu.addAction("Заблокировать")
        self._tray_action_lock.triggered.connect(self._toggle_lock_state)
        self._tray_action_show = menu.addAction("Показать окно")
        self._tray_action_show.triggered.connect(self._show_from_tray)
        self._tray_action_search = menu.addAction("Быстрый поиск")
        self._tray_action_search.triggered.connect(self._tray_quick_search)
        self._tray_action_clip = menu.addAction("Буфер: пуст")
        self._tray_action_clip.triggered.connect(self._on_clear_clipboard)
        self._tray_action_panic = menu.addAction("Режим паники")
        self._tray_action_panic.triggered.connect(lambda: self._activate_panic("tray"))
        menu.addSeparator()
        self._tray_action_settings = menu.addAction("Настройки")
        self._tray_action_settings.triggered.connect(self._open_settings_dialog)
        self._tray_action_exit = menu.addAction("Выход")
        self._tray_action_exit.triggered.connect(self._quit_application)
        menu.aboutToShow.connect(self._update_tray_clipboard_menu)
        self._tray.setContextMenu(menu)
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()
        self._update_tray_icon()

    def _update_tray_icon(self) -> None:
        if not hasattr(self, "_tray"):
            return
        # TRAY-1: цвет + мигание при крипто-операциях
        if self._tray_crypto_busy:
            icon = _tray_icon_for_color(
                _TRAY_COLOR_BUSY if self._tray_crypto_blink else (
                    _TRAY_COLOR_LOCKED if self._locked else _TRAY_COLOR_UNLOCKED
                )
            )
        elif self._locked:
            icon = _tray_icon_for_color(_TRAY_COLOR_LOCKED)
        else:
            icon = _tray_icon_for_color(_TRAY_COLOR_UNLOCKED)
        self._tray.setIcon(icon)
        self.setWindowIcon(icon)
        if self._tray_crypto_busy:
            tip = "CryptoSafe — операция…"
        elif self._locked:
            tip = "CryptoSafe — заблокировано"
        else:
            tip = "CryptoSafe — разблокировано"
        self._tray.setToolTip(tip)
        if hasattr(self, "_tray_action_lock"):
            self._tray_action_lock.setText("Разблокировать" if self._locked else "Заблокировать")

    def _tray_crypto_tick(self) -> None:
        self._tray_crypto_blink = not self._tray_crypto_blink
        self._update_tray_icon()

    def _set_tray_crypto_busy(self, busy: bool) -> None:
        self._tray_crypto_busy = busy
        if busy:
            self._tray_crypto_timer.start()
        else:
            self._tray_crypto_timer.stop()
            self._tray_crypto_blink = False
            self._update_tray_icon()

    def _update_tray_clipboard_menu(self) -> None:
        if not hasattr(self, "_tray_action_clip"):
            return
        status = self._clipboard_service.get_clipboard_status()
        if bool(status.get("active", False)):
            sec = int(status.get("remaining_seconds", 0) or 0)
            self._tray_action_clip.setText(f"Буфер: активен ({sec} с) — очистить")
        else:
            self._tray_action_clip.setText("Буфер: пуст — очистить")

    def _show_from_tray(self) -> None:
        if self._saved_geometry is not None:
            self.setGeometry(self._saved_geometry)
        self.showNormal()
        self.raise_()
        self.activateWindow()
        self._record_activity("tray")

    def _on_tray_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._show_from_tray()

    def _tray_quick_search(self) -> None:
        self._show_from_tray()
        text, ok = QInputDialog.getText(self, "Поиск", "Запрос:")
        if ok and text.strip():
            self.search_edit.setText(text.strip())
            self._apply_search_filter(text.strip())

    def _on_tray_security_event(self, event: str, payload) -> None:
        if not self.clipboard_notifications_enabled or not hasattr(self, "_tray"):
            return
        if event == "VaultLocked":
            self._tray.showMessage("CryptoSafe", "Хранилище заблокировано")
        elif event == "VaultUnlocked":
            self._tray.showMessage("CryptoSafe", "Хранилище разблокировано")

    def _create_toolbar(self) -> None:
        tb = QToolBar("Tools", self)
        self.addToolBar(tb)

        self.search_edit = QLineEdit(self)
        self.search_edit.setPlaceholderText('Поиск (например: title:"work" url:google)')
        self.search_edit.textChanged.connect(self._apply_search_filter)
        self.search_edit.editingFinished.connect(self._remember_search_query)
        tb.addWidget(self.search_edit)

        self.action_toggle_passwords = QAction("Показать пароли", self)
        self.action_toggle_passwords.setCheckable(True)
        self.action_toggle_passwords.setShortcut(QKeySequence("Ctrl+Shift+P"))
        self.action_toggle_passwords.toggled.connect(self._table.set_show_passwords)
        tb.addAction(self.action_toggle_passwords)

    def reset_clipboard_timer(self) -> None:
        # читаем состояние из ClipboardService
        """Reset clipboard timer."""
        status = self._clipboard_service.get_clipboard_status()
        if bool(status.get("active", False)):
            self._clipboard_seconds_left = int(status.get("remaining_seconds", 0) or 0)
        else:
            self._clipboard_seconds_left = 0
        source = status.get("source_entry_id")
        try:
            source_id = int(source) if source not in (None, "") else None
        except Exception:
            source_id = None
        self._table.set_clipboard_source_entry_id(source_id)
        self._update_clipboard_label()

    def _update_clipboard_timer(self) -> None:
        locked_before = self._locked
        status = self._clipboard_service.get_clipboard_status()
        if bool(status.get("active", False)):
            self._clipboard_seconds_left = int(status.get("remaining_seconds", 0) or 0)
        else:
            self._clipboard_seconds_left = 0
        source = status.get("source_entry_id")
        try:
            source_id = int(source) if source not in (None, "") else None
        except Exception:
            source_id = None
        self._table.set_clipboard_source_entry_id(source_id)
        self._update_clipboard_label()
        self._update_clipboard_preview_label(masked=True)
        # UI-3: предупреждение за 5 секунд до очистки
        if self._clipboard_seconds_left == 5 and not self._clipboard_warned_5s:
            if self.clipboard_notifications_enabled:
                self.statusBar().showMessage("Буфер будет очищен через 5 секунд", 3000)
                if hasattr(self, "_tray"):
                    self._tray.showMessage("CryptoSafe", "Буфер будет очищен через 5 секунд")
            self._clipboard_warned_5s = True
        if self._clipboard_seconds_left > 5:
            self._clipboard_warned_5s = False
        # при автоблокировке обновляем подпись и сообщаем
        locked_now = self._state_manager.state.locked
        if locked_now != locked_before:
            self._locked = locked_now
            self._update_lock_label()
            if locked_now:
                # CLIP-4: при блокировке очищаем буфер
                self._clipboard_service.force_clear(reason="lock")
                QMessageBox.information(
                    self,
                    "Автоблокировка",
                    "Сессия заблокирована из-за неактивности.",
                )

    def _update_clipboard_label(self) -> None:
        if self.current_language == "ru":
            status = self._clipboard_service.get_clipboard_status()
            if bool(status.get("active", False)) and int(self.clipboard_timeout) == 0:
                text = "Буфер: автоочистка отключена"
            elif self._clipboard_seconds_left > 0:
                text = f"Буфер: очистка через {self._clipboard_seconds_left} с"
            else:
                text = "Буфер: очищен"
        else:
            status = self._clipboard_service.get_clipboard_status()
            if bool(status.get("active", False)) and int(self.clipboard_timeout) == 0:
                text = "Clipboard: auto-clear disabled"
            elif self._clipboard_seconds_left > 0:
                text = f"Clipboard: clears in {self._clipboard_seconds_left} s"
            else:
                text = "Clipboard: cleared"
        self.clipboard_label.setText(text)

    def _update_clipboard_preview_label(self, masked: bool) -> None:
        # UI-4: preview + тип + источник
        info = self._clipboard_service.get_clipboard_preview(masked=masked)
        if not bool(info.get("active", False)):
            self.clipboard_preview_label.setText("Preview: -")
            return
        dtype = str(info.get("data_type", "") or "")
        src = str(info.get("source_entry_id", "") or "-")
        val = str(info.get("preview", "") or "")
        if self.current_language == "ru":
            self.clipboard_preview_label.setText(f"Буфер[{dtype}] #{src}: {val}")
        else:
            self.clipboard_preview_label.setText(f"Clipboard[{dtype}] #{src}: {val}")

    def _on_clipboard_service_event(self, event_name: str, payload: dict) -> None:
        # observer от ClipboardService: без тяжелой логики, только обновляем счетчик
        if event_name == "clipboard_copied":
            if int(self.clipboard_timeout) == 0:
                self._clipboard_seconds_left = 0
            else:
                self._clipboard_seconds_left = max(5, int(self.clipboard_timeout))
            self._update_clipboard_preview_label(masked=True)
            # UI-3: уведомление при копировании
            if self.clipboard_notifications_enabled:
                self.statusBar().showMessage("Скопировано в буфер", 2000)
                if hasattr(self, "_tray"):
                    self._tray.showMessage("CryptoSafe", "Содержимое скопировано в буфер")
        elif event_name in {"clipboard_cleared", "clipboard_external_change"}:
            self._clipboard_seconds_left = 0
            self._update_clipboard_preview_label(masked=True)
            self._table.set_clipboard_source_entry_id(None)
            # UI-3: подтверждение очистки
            if self.clipboard_notifications_enabled:
                self.statusBar().showMessage("Буфер очищен", 2000)
                if hasattr(self, "_tray"):
                    self._tray.showMessage("CryptoSafe", "Буфер очищен")
        elif event_name == "clipboard_snooping_detected":
            # MON-2: уведомление пользователя о подозрительной активности
            reason = str(payload.get("reason", "unknown"))
            QMessageBox.warning(
                self,
                "Безопасность буфера",
                f"Обнаружена подозрительная активность буфера ({reason}). "
                "Копирование временно заблокировано.",
            )
        elif event_name == "clipboard_warning":
            # ERR-2/ERR-3: предупреждение для пользователя
            msg = str(payload.get("message", "Ошибка буфера обмена"))
            QMessageBox.warning(self, "Буфер обмена", msg)

    def _toggle_lock_state(self) -> None:
        if self._state_manager.state.locked:
            self._prompt_unlock()
        else:
            self._do_auto_lock("manual")

    def _on_clear_clipboard(self) -> None:
        # CLIP-4: ручная очистка буфера через UI
        self._clipboard_service.force_clear(reason="manual_ui")
        self.reset_clipboard_timer()

    def _on_reveal_clipboard(self) -> None:
        # UI-4: полный показ буфера после проверки мастер-пароля
        info = self._clipboard_service.get_clipboard_preview(masked=True)
        if not bool(info.get("active", False)):
            QMessageBox.information(self, "Информация", "Буфер пуст.")
            return
        pwd, ok = QInputDialog.getText(
            self,
            "Подтверждение",
            "Введите мастер-пароль:",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return
        if not verify_master_password(pwd):
            QMessageBox.warning(self, "Ошибка", "Неверный мастер-пароль.")
            return
        self._update_clipboard_preview_label(masked=False)

    def _update_lock_label(self) -> None:
        self._locked = self._state_manager.state.locked
        if self.current_language == "ru":
            text = "Статус: заблокировано" if self._locked else "Статус: разблокировано"
        else:
            text = "Status: locked" if self._locked else "Status: unlocked"
        self.lock_label.setText(text)
        # UX-2: цвет по состоянию безопасности
        if self._locked:
            self.lock_label.setStyleSheet("color: #c5221f; font-weight: bold;")
        else:
            self.lock_label.setStyleSheet("color: #188038; font-weight: bold;")
        self._update_tray_icon()
        self._update_integrity_colors()

    def _update_integrity_label(self) -> None:
        # VER-2: статус целостности в UI
        status = get_integrity_status()
        if self.current_language == "ru":
            if status == "ok":
                text = "Аудит: целостность OK"
            elif status == "tampered":
                text = "Аудит: ВМЕШАТЕЛЬСТВО"
            else:
                text = "Аудит: не проверялся"
        else:
            if status == "ok":
                text = "Audit: integrity OK"
            elif status == "tampered":
                text = "Audit: TAMPERED"
            else:
                text = "Audit: not checked"
        self.integrity_label.setText(text)
        self._update_integrity_colors()

    def _update_integrity_colors(self) -> None:
        # UX-2: цвет статуса аудита
        status = get_integrity_status()
        if status == "tampered":
            self.integrity_label.setStyleSheet("color: #c5221f; font-weight: bold;")
        elif status == "ok":
            self.integrity_label.setStyleSheet("color: #188038;")
        else:
            self.integrity_label.setStyleSheet("color: #5f6368;")

    def run_startup_integrity_check(self) -> None:
        # VER-1: проверка при запуске (после асинхронных записей в аудит)
        """Run startup integrity check."""
        self._bus.drain_async_handlers()
        result = verify_on_startup()
        self._update_integrity_label()
        if not result["ok"]:
            self._handle_tampering(result)

    def _run_periodic_integrity_check(self) -> None:
        # VER-2: периодическая проверка
        result = verify_periodic()
        self._update_integrity_label()
        if not result["ok"]:
            self._handle_tampering(result)

    def _handle_tampering(self, result: dict) -> None:
        # VER-4: уведомление и блокировка (опционально)
        msg = "Обнаружено возможное вмешательство в журнал аудита."
        QMessageBox.critical(self, "Безопасность аудита", msg)
        self.statusBar().showMessage(msg, 10000)
        if hasattr(self, "_tray"):
            self._tray.showMessage("CryptoSafe", msg)
        if should_lock_on_tamper():
            self._clipboard_service.force_clear(reason="tamper")
            clear_all_keys()
            lock_session()
            self._state_manager.state.locked = True
            self._locked = True
            self._table.set_show_passwords(False)
            self._lock_overlay.show_overlay()
            self._update_lock_label()

    def _open_export_dialog(self) -> None:
        if self._locked:
            show_user_error(self, "vault_locked")
            return

        def work() -> None:
            """Work."""
            dlg = ExportDialog(self, entry_manager=self._entry_manager)
            self._set_tray_crypto_busy(True)
            try:
                dlg.exec()
            finally:
                self._set_tray_crypto_busy(False)

        run_with_progress(self, "Экспорт...", work)

    def _open_import_dialog(self) -> None:
        if self._locked:
            show_user_error(self, "vault_locked")
            return

        def work() -> None:
            """Work."""
            dlg = ImportDialog(self)
            self._set_tray_crypto_busy(True)
            try:
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    self._load_vault_entries()
            finally:
                self._set_tray_crypto_busy(False)

        run_with_progress(self, "Импорт...", work)

    def _on_scan_qr_camera(self) -> None:
        # QR-2: сканирование с камеры из главного меню
        qr = QRCodeService()
        body = scan_qr_from_camera_with_hint(qr, self, timeout_sec=15.0)
        if body is None:
            return
        pkg = extract_share_package_from_qr_body(body)
        if pkg is not None:
            reply = QMessageBox.question(
                self,
                "Share из QR",
                "В QR найден пакет обмена записью.\nОткрыть вкладку «Получить»?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                SharingDialog(
                    self,
                    entry_manager=self._entry_manager,
                    clipboard_service=self._clipboard_service,
                    initial_tab=1,
                    initial_receive_package=pkg,
                ).exec()
            return
        try:
            QMessageBox.information(self, "QR", process_scanned_qr_body(KeyExchange(), body))
        except Exception as exc:
            show_exception(self, exc, code="qr_failed")

    def _current_security_settings(self) -> SecuritySettings:
        return SecuritySettings(
            profile=self._security_profile,
            auto_lock_minutes=int(self.auto_lock_minutes),
            activity_sensitivity=self._activity_sensitivity,
            device_type=self._device_type,
            clipboard_timeout_seconds=int(self.clipboard_timeout),
            clipboard_security_level=self.clipboard_security_level,
            minimize_to_tray=self.minimize_to_tray,
            start_minimized=self.start_minimized,
            panic_stealth_mode=self._panic_stealth,
            panic_quit_app=self._panic_quit,
        )

    def _settings_from_dialog(self, dlg: SettingsDialog) -> SecuritySettings:
        clip = int(dlg.clipboard_spin.value())
        if clip < 0:
            clip = 0
        elif 0 < clip < 5:
            clip = 5
        elif clip > 300:
            clip = 300
        return SecuritySettings(
            profile=str(dlg.profile_combo.currentData() or PROFILE_STANDARD),
            auto_lock_minutes=int(dlg.auto_lock_spin.value()),
            activity_sensitivity=str(dlg.sensitivity_combo.currentData() or "medium"),
            device_type=str(dlg.device_combo.currentData() or "desktop"),
            clipboard_timeout_seconds=clip,
            clipboard_security_level=str(dlg.security_level_combo.currentData() or "basic"),
            minimize_to_tray=bool(dlg.minimize_tray_check.isChecked()),
            start_minimized=bool(dlg.start_minimized_check.isChecked()),
            panic_stealth_mode=bool(dlg.panic_stealth_check.isChecked()),
            panic_quit_app=bool(dlg.panic_quit_check.isChecked()),
        )

    def _apply_security_settings(self, settings: SecuritySettings) -> None:
        self._security_profile = settings.profile
        self.auto_lock_minutes = settings.auto_lock_minutes
        self._activity_sensitivity = settings.activity_sensitivity
        self._device_type = settings.device_type
        self.clipboard_timeout = settings.clipboard_timeout_seconds
        self.clipboard_security_level = settings.clipboard_security_level
        self.minimize_to_tray = settings.minimize_to_tray
        self.start_minimized = settings.start_minimized
        self._panic_stealth = settings.panic_stealth_mode
        self._panic_quit = settings.panic_quit_app
        self.config_manager.set("clipboard_timeout_seconds", self.clipboard_timeout)
        self.config_manager.set("auto_lock_minutes", self.auto_lock_minutes)
        self._clipboard_service.set_timeout_seconds(self.clipboard_timeout)
        self._clipboard_service.set_block_future_copies_on_suspicious(
            self.clipboard_security_level == "paranoid"
        )
        sm = get_state_manager()
        sm.set_setting("clipboard_timeout_seconds", str(self.clipboard_timeout), encrypted=True)
        sm.set_setting(SETTING_AUTO_LOCK_TIMEOUT, str(self.auto_lock_minutes), encrypted=True)
        sm.set_setting(SETTING_ACTIVITY_SENSITIVITY, self._activity_sensitivity, encrypted=True)
        sm.set_setting(SETTING_DEVICE_TYPE, self._device_type, encrypted=True)
        sm.set_setting(SETTING_MINIMIZE_TO_TRAY, "1" if self.minimize_to_tray else "0", encrypted=True)
        sm.set_setting(SETTING_START_MINIMIZED, "1" if self.start_minimized else "0", encrypted=True)
        sm.set_setting(SETTING_PANIC_STEALTH, "1" if self._panic_stealth else "0", encrypted=True)
        sm.set_setting(SETTING_PANIC_QUIT, "1" if self._panic_quit else "0", encrypted=True)
        sm.set_setting(SETTING_SECURITY_PROFILE, settings.profile, encrypted=True)
        self._panic_mode.update_config(self._panic_config())
        self._activity_monitor.update_config(self._activity_config())
        self.reset_clipboard_timer()

    def _open_sharing_dialog(self) -> None:
        # UI-3: вкладки «Отправить» / «Получить»
        if self._locked:
            show_user_error(self, "vault_locked")
            return
        ids = [int(x) for x in self._table.get_selected_entry_ids()]
        dlg = SharingDialog(
            self,
            entry_ids=ids if ids else None,
            entry_manager=self._entry_manager,
            clipboard_service=self._clipboard_service,
        )
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._load_vault_entries()

    def _open_settings_dialog(self) -> None:
        old_settings = self._current_security_settings()
        dlg = SettingsDialog(
            self,
            clipboard_timeout=self.clipboard_timeout,
            auto_lock_minutes=self.auto_lock_minutes,
            current_language=self.current_language,
            current_theme=self.current_theme,
            notifications_enabled=self.clipboard_notifications_enabled,
            security_level=self.clipboard_security_level,
            app_whitelist=self.clipboard_whitelist,
            activity_sensitivity=self._activity_sensitivity,
            device_type=self._device_type,
            minimize_to_tray=self.minimize_to_tray,
            start_minimized=self.start_minimized,
            panic_stealth=self._panic_stealth,
            panic_quit=self._panic_quit,
            security_profile=self._security_profile,
        )
        dlg.languageChanged.connect(self._change_language)
        dlg.themeChanged.connect(self._change_theme)

        if not dlg.exec():
            return

        self.clipboard_notifications_enabled = bool(dlg.notify_checkbox.isChecked())
        self.clipboard_whitelist = str(dlg.whitelist_edit.text() or "")
        new_settings = self._settings_from_dialog(dlg)

        ok, errors = validate_settings(new_settings)
        if not ok:
            QMessageBox.warning(self, "Настройки", "\n".join(errors))
            return

        warns = non_default_warnings(new_settings)
        if warns:
            QMessageBox.information(self, "Настройки", "Внимание:\n" + "\n".join(warns))

        if new_settings.profile != old_settings.profile:
            text = profile_changes_text(old_settings, new_settings)
            answer = QMessageBox.question(
                self,
                "Смена профиля",
                f"Применить изменения?\n\n{text}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        try:
            self._apply_security_settings(new_settings)
            get_state_manager().set_setting(
                "clipboard_notifications_enabled",
                "1" if self.clipboard_notifications_enabled else "0",
                encrypted=True,
            )
            get_state_manager().set_setting("clipboard_security_level", self.clipboard_security_level, encrypted=True)
            get_state_manager().set_setting("clipboard_app_whitelist", self.clipboard_whitelist, encrypted=True)
        except Exception as exc:
            try:
                self._apply_security_settings(old_settings)
            except Exception:
                pass
            show_user_error(self, "generic_error", repr(exc))
            return

        self._bus.publish(
            "SettingsChanged",
            {
                "source": "settings_dialog",
                "clipboard_timeout": self.clipboard_timeout,
                "auto_lock_minutes": self.auto_lock_minutes,
                "security_profile": self._security_profile,
            },
        )

    def _open_setup_wizard(self) -> int:
        wizard = SetupWizard(self)
        return wizard.exec()

    def _open_audit_log_viewer(self) -> None:
        viewer = AuditLogViewer(self)
        viewer.vaultEntryRequested.connect(self.highlight_vault_entry)
        viewer.exec()

    def highlight_vault_entry(self, entry_id: int) -> None:
        # GUI-4: подсветка записи в таблице хранилища
        """Highlight vault entry."""
        self._table.highlight_entry_by_id(int(entry_id))

    def _open_state_monitor(self) -> None:
        monitor = StateMonitor(self)
        monitor.exec()

    def _show_about(self) -> None:
        QMessageBox.information(
            self,
            "О программе",
            "CryptoSafe Manager\nПростой GUI-шелл на PyQt6.",
        )

    def _open_change_password_dialog(self) -> None:
        dlg = ChangePasswordDialog(self)
        dlg.exec()

    def _on_backup_database(self) -> None:
        from datetime import timezone

        from src.database.db import get_default_database

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        default_name = f"cryptosafe-backup-{stamp}.db"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Резервная копия базы",
            default_name,
            "SQLite (*.db);;All files (*.*)",
        )
        if not path:
            return
        if not str(path).lower().endswith(".db"):
            path = f"{path}.db"

        def work() -> None:
            get_default_database().backup_database(path)
            self._bus.publish(
                "DatabaseBackedUp",
                {"source": "main_window", "destination": str(path)},
            )

        try:
            run_with_progress(self, "Создание резервной копии...", work)
            QMessageBox.information(
                self,
                "Резервная копия",
                f"Копия базы сохранена:\n{path}",
            )
        except Exception as exc:
            show_exception(self, exc, code="backup_failed")

    def _on_restore_database(self) -> None:
        from src.core.audit.audit_logger import reload_chain_state
        from src.database.db import get_default_database

        if not has_master_password():
            show_user_error(self, "setup_failed")
            return

        confirm = QMessageBox.warning(
            self,
            "Восстановление",
            "Текущая база будет заменена выбранной копией.\n"
            "Старая база сохранится рядом с файлом (*.pre-restore-*.db).\n\n"
            "Продолжить?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Восстановить из копии",
            "",
            "SQLite (*.db);;All files (*.*)",
        )
        if not path:
            return

        password, ok = QInputDialog.getText(
            self,
            "Подтверждение",
            "Введите мастер-пароль для восстановления:",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not password:
            return
        if not verify_master_password(password):
            show_user_error(self, "wrong_password")
            return

        def work() -> None:
            self._clipboard_service.force_clear(reason="restore")
            clear_all_keys()
            lock_session()
            get_default_database().restore_database(path)
            reload_chain_state()
            self._bus.drain_async_handlers()
            verify_on_startup()

        try:
            run_with_progress(self, "Восстановление базы...", work)
        except Exception as exc:
            show_exception(self, exc, code="restore_failed")
            return

        self._state_manager.state.locked = True
        self._locked = True
        self._table.set_show_passwords(False)
        self._lock_overlay.show_overlay()
        self._update_lock_label()
        self._update_integrity_label()
        self._load_vault_entries()
        title, hint = USER_HINTS["restore_ok"]
        QMessageBox.information(self, title, f"{hint}\n\nФайл: {path}")

    def _load_vault_entries(self) -> None:
        """Загрузить записи и применить текущий фильтр."""
        if self._locked:
            self._table.set_entries([])
            return
        try:
            self._all_entries_encrypted = self._entry_manager.get_all_entries_encrypted()
        except Exception as exc:
            self._all_entries_encrypted = []
            show_user_error(self, "load_failed", repr(exc))
        self._apply_search_filter(self.search_edit.text() if hasattr(self, "search_edit") else "")

    def _remember_search_query(self) -> None:
        """Сохранить запрос в истории (до 10)."""
        q = (self.search_edit.text() or "").strip()
        if not q:
            return
        # INT-2: поиск в vault — в аудит только анонимизированный запрос
        from src.core.audit.log_entry import anonymize_search_query

        self._bus.publish(
            "VaultSearched",
            {
                "source": "main_window",
                "query_hash": anonymize_search_query(q),
            },
        )
        if q in self._search_history:
            self._search_history.remove(q)
        self._search_history.append(q)
        if len(self._search_history) > 10:
            self._search_history = self._search_history[-10:]

    def _parse_search_query(self, text: str) -> tuple[str, dict]:
        """Разобрать строку поиска и фильтры вида field:value."""
        s = (text or "").strip()
        if not s:
            return "", {}

        tokens: list[str] = []
        buf = ""
        in_quotes = False
        for ch in s:
            if ch == '"':
                in_quotes = not in_quotes
                continue
            if ch.isspace() and not in_quotes:
                if buf:
                    tokens.append(buf)
                    buf = ""
            else:
                buf += ch
        if buf:
            tokens.append(buf)

        field_filters: dict[str, str] = {}
        free_parts: list[str] = []
        for t in tokens:
            if ":" in t:
                k, v = t.split(":", 1)
                k = k.strip().lower()
                v = v.strip()
                if k in {"title", "username", "url", "notes", "category", "tags"} and v:
                    field_filters[k] = v
                else:
                    free_parts.append(t)
            else:
                free_parts.append(t)
        return " ".join(free_parts).strip(), field_filters

    def _fuzzy_match(self, needle: str, hay: str) -> bool:
        """Проверить совпадение с допуском к опечаткам."""
        if not needle:
            return True
        if not hay:
            return False
        needle = needle.lower()
        hay = hay.lower()
        if needle in hay:
            return True
        ratio = SequenceMatcher(None, needle, hay).ratio()
        return ratio >= 0.7

    def _apply_search_filter(self, text: str) -> None:
        """Применить поиск/фильтры к текущему набору записей."""
        free_text, field_filters = self._parse_search_query(text)
        q = (free_text or "").strip().lower()

        source = self._all_entries_encrypted
        total = len(source)
        # UX-4: lazy load без поиска
        if total > _LAZY_VAULT_LIMIT and not q and not field_filters:
            source = source[:_LAZY_VAULT_LIMIT]
            self.statusBar().showMessage(f"Показано {_LAZY_VAULT_LIMIT} из {total}. Уточните поиск.", 8000)
        else:
            self.statusBar().clearMessage()

        use_progress = len(source) > 80
        prog = None
        if use_progress:
            prog = QProgressDialog("Обработка записей...", None, 0, len(source), self)
            prog.setWindowModality(Qt.WindowModality.WindowModal)
            prog.show()

        filtered: list[dict] = []
        for i, e in enumerate(source):
            if prog is not None:
                prog.setValue(i)
                QApplication.processEvents()
            entry_id = int(e.get("id", 0))
            try:
                dec = self._entry_manager.get_entry(entry_id)
            except Exception:
                continue
            title = str(dec.get("title", "") or "")
            username = str(dec.get("username", "") or "")
            url = str(dec.get("url", "") or "")
            notes = str(dec.get("notes", "") or "")
            category = str(dec.get("category", "") or "")
            tags = str(dec.get("tags", "") or "")

            ok = True
            for k, v in field_filters.items():
                val = v.lower()
                field_val = {
                    "title": title,
                    "username": username,
                    "url": url,
                    "notes": notes,
                    "category": category,
                    "tags": tags,
                }.get(k, "")
                if not self._fuzzy_match(val, str(field_val)):
                    ok = False
                    break
            if not ok:
                continue

            if q:
                joined = build_search_text(
                    {
                        "title": title,
                        "username": username,
                        "url": url,
                        "notes": notes,
                        "category": category,
                        "tags": tags,
                    },
                    audit_text="",
                )
                if not self._fuzzy_match(q, joined):
                    continue

            filtered.append(
                {
                    "id": entry_id,
                    "title": title,
                    "username": username,
                    "url": url,
                    "updated_at": str(dec.get("updated_at", "") or ""),
                }
            )

        if prog is not None:
            prog.close()
        self._table.set_entries(filtered)
        if not filtered:
            if total == 0:
                self.statusBar().showMessage(
                    "Хранилище пусто. Правка → Добавить (Ctrl+N) — создать первую запись.",
                    0,
                )
            elif q or field_filters:
                self.statusBar().showMessage("Ничего не найдено по запросу.", 8000)

    def _on_copy_username(self, entry_id: int) -> None:
        """Скопировать username в буфер обмена."""
        if self._locked:
            return
        try:
            data = self._entry_manager.get_entry(int(entry_id))
        except Exception:
            return
        if bool(data.get("never_copy_to_clipboard", False)):
            QMessageBox.information(self, "Информация", "Для этой записи копирование в буфер запрещено.")
            return
        text = str(data.get("username", "") or "")
        try:
            self._clipboard_service.copy_to_clipboard(
                text,
                data_type="username",
                source_entry_id=str(entry_id),
            )
        except Exception:
            show_user_error(self, "clipboard_failed")
            return
        self.reset_clipboard_timer()

    def _on_copy_password(self, entry_id: int) -> None:
        """Скопировать password в буфер обмена."""
        if self._locked:
            return
        try:
            data = self._entry_manager.get_entry(int(entry_id))
        except Exception:
            return
        if bool(data.get("never_copy_to_clipboard", False)):
            QMessageBox.information(self, "Информация", "Для этой записи копирование в буфер запрещено.")
            return
        text = str(data.get("password", "") or "")
        try:
            self._clipboard_service.copy_to_clipboard(
                text,
                data_type="password",
                source_entry_id=str(entry_id),
            )
        except Exception:
            show_user_error(self, "clipboard_failed")
            return
        self.reset_clipboard_timer()

    def _on_copy_all(self, entry_id: int) -> None:
        # UI-1: Copy All в контекстном меню
        if self._locked:
            return
        try:
            data = self._entry_manager.get_entry(int(entry_id))
        except Exception:
            return
        if bool(data.get("never_copy_to_clipboard", False)):
            QMessageBox.information(self, "Информация", "Для этой записи копирование в буфер запрещено.")
            return
        username = str(data.get("username", "") or "")
        password = str(data.get("password", "") or "")
        url = str(data.get("url", "") or "")
        notes = str(data.get("notes", "") or "")
        text = f"username: {username}\npassword: {password}\nurl: {url}\nnotes: {notes}"
        try:
            self._clipboard_service.copy_to_clipboard(
                text,
                data_type="notes",
                source_entry_id=str(entry_id),
            )
        except Exception:
            show_user_error(self, "clipboard_failed")
            return
        self.reset_clipboard_timer()

    def _on_password_toggle_requested(self, entry_id: int, row: int, visible: bool) -> None:
        """Показать/скрыть пароль для строки таблицы."""
        if self._locked:
            return
        if not visible:
            self._table.set_password_display(row, "", False)
            return
        try:
            data = self._entry_manager.get_entry(int(entry_id))
        except Exception:
            return
        pw = str(data.get("password", "") or "")
        self._table.set_password_display(row, pw, True)

    def _on_add_entry(self) -> None:
        if self._locked:
            show_user_error(self, "vault_locked")
            return
        dlg = EntryDialog(self)
        if not dlg.exec():
            return
        title = dlg.get_title()
        if not title:
            QMessageBox.warning(self, "Ошибка", "Введите название записи.")
            return
        data = {
            "title": title,
            "username": dlg.get_username(),
            "password": dlg.get_password(),
            "url": dlg.get_url(),
            "notes": dlg.get_notes(),
            "category": dlg.get_category(),
            "version": 1,
            "tags": dlg.get_tags(),
        }
        self._entry_manager.create_entry(data)
        self._load_vault_entries()
        QMessageBox.information(self, "Готово", "Запись добавлена.")

    def _on_edit_entry(self) -> None:
        ids = self._table.get_selected_entry_ids()
        if not ids:
            show_user_error(self, "no_selection")
            return
        self._on_edit_entry_id(ids[0])

    def _on_delete_entry(self) -> None:
        ids = self._table.get_selected_entry_ids()
        if not ids:
            show_user_error(self, "no_selection")
            return
        self._on_delete_entry_ids(ids)

    def _on_edit_entry_id(self, entry_id: int) -> None:
        if self._locked:
            return
        try:
            data = self._entry_manager.get_entry(int(entry_id))
        except Exception:
            QMessageBox.warning(self, "Ошибка", "Не удалось открыть запись.")
            return

        dlg = EntryDialog(
            self,
            title=str(data.get("title", "") or ""),
            username=str(data.get("username", "") or ""),
            password=str(data.get("password", "") or ""),
            url=str(data.get("url", "") or ""),
            notes=str(data.get("notes", "") or ""),
            category=str(data.get("category", "") or ""),
            tags=str(data.get("tags", "") or ""),
        )
        if not dlg.exec():
            return

        new_data = dict(data)
        new_data["title"] = dlg.get_title()
        new_data["username"] = dlg.get_username()
        new_data["password"] = dlg.get_password()
        new_data["url"] = dlg.get_url()
        new_data["notes"] = dlg.get_notes()
        new_data["category"] = dlg.get_category()
        new_data["tags"] = dlg.get_tags()

        try:
            self._entry_manager.update_entry(int(entry_id), new_data)
        except Exception as exc:
            show_user_error(self, "save_failed", repr(exc))
            return
        self._load_vault_entries()

    def _on_delete_entry_ids(self, ids: list) -> None:
        if self._locked:
            return
        if not ids:
            return
        answer = QMessageBox.question(
            self,
            "Подтверждение",
            f"Удалить выбранные записи ({len(ids)})? Это действие нельзя отменить из интерфейса.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        for entry_id in ids:
            try:
                self._entry_manager.delete_entry(int(entry_id), soft_delete=True)
            except Exception as exc:
                show_user_error(self, "delete_failed", repr(exc))
        self._load_vault_entries()

    def _change_language(self, code: str) -> None:
        self.current_language = code
        self._apply_language()

    def _change_theme(self, code: str) -> None:
        self.current_theme = code
        self._apply_theme()

    def _apply_language(self) -> None:
        self._locked = self._state_manager.state.locked
        if self.current_language == "ru":
            self.setWindowTitle("CryptoSafe Manager")
            self.file_menu.setTitle("Файл")
            self.edit_menu.setTitle("Правка")
            self.view_menu.setTitle("Вид")
            self.settings_menu.setTitle("Настройки")
            self.data_menu.setTitle("Данные")
            self.action_export.setText("Экспорт...")
            self.action_import.setText("Импорт...")
            self.action_share.setText("Обмен записью...")
            self.action_scan_qr.setText("Сканировать QR (камера)...")
            self.help_menu.setTitle("Справка")
            self.action_new.setText("Мастер-пароль / первое создание")
            self.action_backup.setText("Резервная копия...")
            self.action_restore.setText("Восстановить из копии...")
            self.action_exit.setText("Выход")
            self.action_clear_clipboard.setText("Очистить буфер")
            self.action_reveal_clipboard.setText("Показать буфер (пароль)")
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
            self.data_menu.setTitle("Data")
            self.action_export.setText("Export...")
            self.action_import.setText("Import...")
            self.action_share.setText("Share entry...")
            self.action_scan_qr.setText("Scan QR (camera)...")
            self.help_menu.setTitle("Help")
            self.action_new.setText("Master password / first setup")
            self.action_backup.setText("Backup...")
            self.action_restore.setText("Restore from backup...")
            self.action_exit.setText("Exit")
            self.action_clear_clipboard.setText("Clear clipboard")
            self.action_reveal_clipboard.setText("Reveal clipboard (password)")
            self.action_view_logs.setText("Audit Log")
            self.action_state_monitor.setText("State monitor")
            self.action_toggle_lock.setText("Lock" if not self._locked else "Unlock")
            self.action_settings.setText("Preferences...")

        self._update_lock_label()
        self._update_clipboard_label()
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
    """Run app."""
    import sys

    from src.database.db import get_default_database

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    from src.gui.gui_styles import apply_base_styles

    apply_base_styles(app)
    window = MainWindow()
    get_default_database()
    if has_master_password():
        dlg = LoginDialog(window)
        result = dlg.exec()
    else:
        result = window._open_setup_wizard()
    if result != QDialog.DialogCode.Accepted:
        return

    window._locked = False
    window._bus.publish("AppStartup", {"source": "main_window"})
    window._bus.publish("VaultUnlocked", {"source": "main_window"})
    window._bus.publish("UserLoggedIn", {"source": "main_window"})
    window._update_lock_label()
    window._update_tray_icon()
    window._load_vault_entries()

    if window.start_minimized and window.minimize_to_tray:
        window.hide()
    else:
        window.show()
    # UX-4: проверка аудита после показа окна
    QTimer.singleShot(200, window.run_startup_integrity_check)
    sys.exit(app.exec())
