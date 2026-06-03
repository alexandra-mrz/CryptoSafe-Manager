from __future__ import annotations

# GUI-1..GUI-4: просмотр журнала аудита

import json
from datetime import datetime, timedelta, timezone

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QBrush
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from src.gui.ux_helpers import show_exception, show_user_error
from src.core.audit.audit_logger import fetch_all_rows
from src.core.audit.audit_security import require_audit_read_access
from src.core.audit.log_entry import filter_audit_items, parse_log_rows
from src.core.audit.log_export import export_audit_log
from src.core.audit.log_integrity import (
    export_report_to_file,
    get_integrity_status,
    get_last_report,
    verify_manual_full,
)
from src.core.audit.log_verifier import verify_single_row

PAGE_SIZE = 50

VAULT_EVENTS = (
    "EntryCreated",
    "EntryAdded",
    "EntryRead",
    "EntryUpdated",
    "EntryDeleted",
)


class AuditLogViewer(QDialog):

    """Публичный класс AuditLogViewer."""
    vaultEntryRequested = pyqtSignal(int)

    def __init__(self, parent=None) -> None:
        # окно просмотра: таблица, фильтры, детали, экспорт (GUI-1..4)
        super().__init__(parent)
        self.setWindowTitle("Журнал аудита")
        self.resize(1000, 640)

        self._all_items: list[dict] = []
        self._filtered: list[dict] = []
        self._page = 0

        # GUI-3: простая статистика (без графиков)
        self.stats_label = QLabel(self)

        # GUI-1: фильтры
        filter_row = QHBoxLayout()
        self.type_combo = QComboBox(self)
        self.type_combo.addItem("Все типы", "")
        self.severity_combo = QComboBox(self)
        self.severity_combo.addItem("Все уровни", "")
        for level in ("INFO", "WARN", "ERROR", "CRITICAL"):
            self.severity_combo.addItem(level, level)
        self.user_edit = QLineEdit(self)
        self.user_edit.setPlaceholderText("user_id")
        self.date_from_edit = QLineEdit(self)
        self.date_from_edit.setPlaceholderText("дата от (YYYY-MM-DD)")
        self.date_to_edit = QLineEdit(self)
        self.date_to_edit.setPlaceholderText("дата до (YYYY-MM-DD)")
        self.search_edit = QLineEdit(self)
        self.search_edit.setPlaceholderText("поиск по details")
        self.apply_filter_btn = QPushButton("Применить", self)
        self.apply_filter_btn.clicked.connect(self._apply_filters)

        filter_row.addWidget(QLabel("Тип:"))
        filter_row.addWidget(self.type_combo)
        filter_row.addWidget(QLabel("Severity:"))
        filter_row.addWidget(self.severity_combo)
        filter_row.addWidget(self.user_edit)
        filter_row.addWidget(self.date_from_edit)
        filter_row.addWidget(self.date_to_edit)
        filter_row.addWidget(self.search_edit)
        filter_row.addWidget(self.apply_filter_btn)

        # GUI-1: таблица с сортировкой
        self.table = QTableWidget(self)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["Время", "Событие", "Severity", "User", "Источник", "entry_id"]
        )
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._open_context_menu)
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        self.table.cellDoubleClicked.connect(self._on_cell_double_click)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)

        # GUI-1: пагинация
        page_row = QHBoxLayout()
        self.prev_btn = QPushButton("Назад", self)
        self.next_btn = QPushButton("Вперёд", self)
        self.page_label = QLabel(self)
        self.prev_btn.clicked.connect(self._prev_page)
        self.next_btn.clicked.connect(self._next_page)
        page_row.addWidget(self.prev_btn)
        page_row.addWidget(self.next_btn)
        page_row.addWidget(self.page_label)
        page_row.addStretch(1)

        # GUI-2: панель деталей
        self.verify_label = QLabel(self)
        self.chain_label = QLabel(self)
        self.chain_label.setWordWrap(True)
        self.json_edit = QTextEdit(self)
        self.json_edit.setReadOnly(True)
        self.login_info_label = QLabel(self)

        details = QWidget(self)
        details_layout = QVBoxLayout(details)
        details_layout.addWidget(QLabel("Детали записи"))
        details_layout.addWidget(self.verify_label)
        details_layout.addWidget(self.chain_label)
        details_layout.addWidget(self.login_info_label)
        details_layout.addWidget(self.json_edit)

        left = QWidget(self)
        left_layout = QVBoxLayout(left)
        left_layout.addLayout(filter_row)
        left_layout.addWidget(self.table)
        left_layout.addLayout(page_row)

        splitter = QSplitter(self)
        splitter.addWidget(left)
        splitter.addWidget(details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        # кнопки проверки (VER-3)
        btn_row = QHBoxLayout()
        self.verify_button = QPushButton("Проверить журнал", self)
        self.export_log_button = QPushButton("Экспорт журнала", self)
        self.export_button = QPushButton("Экспорт отчёта", self)
        self.close_button = QPushButton("Закрыть", self)
        self.verify_button.clicked.connect(self._on_verify_all)
        self.export_log_button.clicked.connect(self._on_export_log)
        self.export_button.clicked.connect(self._on_export)
        self.close_button.clicked.connect(self.accept)
        btn_row.addWidget(self.verify_button)
        btn_row.addWidget(self.export_log_button)
        btn_row.addWidget(self.export_button)
        btn_row.addStretch(1)
        btn_row.addWidget(self.close_button)

        layout = QVBoxLayout(self)
        layout.addWidget(self.stats_label)
        layout.addWidget(splitter)
        layout.addLayout(btn_row)

        try:
            require_audit_read_access()
        except PermissionError:
            show_user_error(self, "audit_access_denied")
            self.reject()
            return
        self._load_data()

    def _load_data(self) -> None:
        # загрузить журнал из БД и заполнить фильтр типов
        rows = fetch_all_rows()
        self._all_items = parse_log_rows(rows)
        types = sorted({item["event_type"] for item in self._all_items})
        for event_type in types:
            self.type_combo.addItem(event_type, event_type)
        self._update_stats()
        self._apply_filters()

    def _update_stats(self) -> None:
        # GUI-3: метрики текстом
        now = datetime.now(timezone.utc)
        counts = {7: 0, 30: 0, 90: 0}
        failed = 0
        suspicious = 0
        for item in self._all_items:
            ts = item.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                dt = None
            if dt is not None:
                age = now - dt
                if age <= timedelta(days=7):
                    counts[7] += 1
                if age <= timedelta(days=30):
                    counts[30] += 1
                if age <= timedelta(days=90):
                    counts[90] += 1
            if item["event_type"] == "LoginFailed":
                failed += 1
            if item["event_type"] in ("ClipboardSnoopingDetected", "ClipboardCopyBlocked"):
                suspicious += 1
        status = get_integrity_status()
        self.stats_label.setText(
            f"Записей: {len(self._all_items)} | "
            f"7д: {counts[7]} | 30д: {counts[30]} | 90д: {counts[90]} | "
            f"Неудачные входы: {failed} | Подозрительно: {suspicious} | "
            f"Целостность: {status}"
        )

    def _apply_filters(self) -> None:
        # PERF-3: отфильтровать и показать первую страницу
        self._filtered = filter_audit_items(
            self._all_items,
            str(self.type_combo.currentData() or ""),
            str(self.severity_combo.currentData() or ""),
            self.user_edit.text(),
            self.date_from_edit.text().strip(),
            self.date_to_edit.text().strip(),
            self.search_edit.text(),
        )
        self._page = 0
        self._show_page()

    def _total_pages(self) -> int:
        # число страниц по PAGE_SIZE
        if not self._filtered:
            return 1
        pages = len(self._filtered) // PAGE_SIZE
        if len(self._filtered) % PAGE_SIZE:
            pages += 1
        return max(pages, 1)

    def _show_page(self) -> None:
        # GUI-1: вывести текущую страницу в таблицу
        self.table.setSortingEnabled(False)
        start = self._page * PAGE_SIZE
        page_items = self._filtered[start : start + PAGE_SIZE]
        self.table.setRowCount(len(page_items))
        for row, item in enumerate(page_items):
            values = [
                item["timestamp"],
                item["event_type"],
                item["severity"],
                item["user_id"],
                item["source"],
                str(item.get("entry_id") or ""),
            ]
            for col, text in enumerate(values):
                cell = QTableWidgetItem(text)
                cell.setData(Qt.ItemDataRole.UserRole, item)
                self.table.setItem(row, col, cell)
        self.table.setSortingEnabled(True)
        self.page_label.setText(f"Страница {self._page + 1} / {self._total_pages()}")

    def _prev_page(self) -> None:
        # предыдущая страница
        if self._page > 0:
            self._page -= 1
            self._show_page()

    def _next_page(self) -> None:
        # следующая страница
        if self._page + 1 < self._total_pages():
            self._page += 1
            self._show_page()

    def _selected_item(self) -> dict | None:
        # выбранная строка таблицы (полный dict записи)
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        cell = self.table.item(rows[0].row(), 0)
        if cell is None:
            return None
        data = cell.data(Qt.ItemDataRole.UserRole)
        if isinstance(data, dict):
            return data
        return None

    def _on_row_selected(self) -> None:
        # клик по строке — показать детали
        item = self._selected_item()
        if item is None:
            return
        self._show_details(item)

    def _show_details(self, item: dict) -> None:
        # GUI-2: JSON, подпись, цепочка
        pretty = json.dumps(item.get("stored", {}), ensure_ascii=False, indent=2)
        self.json_edit.setPlainText(pretty)

        ok, msg = verify_single_row(
            item["event_type"],
            item["timestamp"],
            item.get("entry_id"),
            item["details_text"],
            item.get("signature", ""),
        )
        if ok:
            self.verify_label.setText("Подпись: OK")
        else:
            self.verify_label.setText(f"Подпись: ОШИБКА ({msg})")

        prev_short = str(item.get("previous_hash", ""))[:16]
        hash_short = str(item.get("entry_hash", ""))[:16]
        seq = item.get("sequence_number", "?")
        self.chain_label.setText(
            f"Цепочка (#{seq}):\n{prev_short}...  ->  {hash_short}..."
        )

        # GUI-4: детали неудачного входа
        if item["event_type"] == "LoginFailed":
            details = item.get("details", {})
            if not isinstance(details, dict):
                details = {}
            ip = details.get("ip", details.get("address", "не указан"))
            attempts = details.get("attempts", "?")
            self.login_info_label.setText(
                f"Неудачный вход | время: {item['timestamp']} | IP: {ip} | попыток: {attempts}"
            )
        else:
            self.login_info_label.setText("")

    def _on_cell_double_click(self, row: int, _col: int) -> None:
        # GUI-4: двойной клик по операции vault
        cell = self.table.item(row, 0)
        if cell is None:
            return
        item = cell.data(Qt.ItemDataRole.UserRole)
        if not isinstance(item, dict):
            return
        self._open_vault_context(item)

    def _open_vault_context(self, item: dict) -> None:
        event_type = item.get("event_type", "")
        entry_id = item.get("entry_id")
        if event_type in VAULT_EVENTS and entry_id is not None:
            try:
                eid = int(entry_id)
            except (TypeError, ValueError):
                return
            self.vaultEntryRequested.emit(eid)
            parent = self.parent()
            if parent is not None and hasattr(parent, "highlight_vault_entry"):
                parent.highlight_vault_entry(eid)

    def _open_context_menu(self, pos) -> None:
        # GUI-4: контекстное меню
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        cell = self.table.item(row, 0)
        if cell is None:
            return
        item = cell.data(Qt.ItemDataRole.UserRole)
        if not isinstance(item, dict):
            return

        menu = QMenu(self)
        action_vault = None
        action_login = None
        if item.get("event_type") in VAULT_EVENTS and item.get("entry_id"):
            action_vault = menu.addAction("Показать запись в хранилище")
        if item.get("event_type") == "LoginFailed":
            action_login = menu.addAction("Детали неудачного входа")
        action_copy = menu.addAction("Копировать JSON")
        action_check = menu.addAction("Проверить подпись")

        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen == action_vault:
            self._open_vault_context(item)
        elif chosen == action_login:
            self._show_details(item)
            QMessageBox.information(self, "Вход", self.login_info_label.text())
        elif chosen == action_copy:
            self.json_edit.selectAll()
            self.json_edit.copy()
        elif chosen == action_check:
            self._show_details(item)

    def _on_verify_all(self) -> None:
        # VER-3: полная проверка целостности
        result = verify_manual_full()
        self._update_stats()
        if not result["ok"]:
            parent = self.parent()
            if parent is not None and hasattr(parent, "_handle_tampering"):
                parent._handle_tampering(result)
            else:
                QMessageBox.warning(self, "Целостность", result["report"])

    def _on_export_log(self) -> None:
        # EXP-1/EXP-4: диалог экспорта с диапазоном дат
        dlg = QDialog(self)
        dlg.setWindowTitle("Экспорт журнала")
        form = QFormLayout(dlg)
        fmt_combo = QComboBox(dlg)
        fmt_combo.addItem("Signed JSON", "json")
        fmt_combo.addItem("CSV", "csv")
        fmt_combo.addItem("PDF", "pdf")
        exp_from = QLineEdit(dlg)
        exp_from.setPlaceholderText("YYYY-MM-DD")
        exp_to = QLineEdit(dlg)
        exp_to.setPlaceholderText("YYYY-MM-DD")
        pwd_edit = QLineEdit(dlg)
        pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Формат", fmt_combo)
        form.addRow("Дата от", exp_from)
        form.addRow("Дата до", exp_to)
        form.addRow("Мастер-пароль", pwd_edit)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            dlg,
        )
        form.addRow(buttons)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        fmt = str(fmt_combo.currentData())
        filters = {
            "json": "JSON (*.json)",
            "csv": "CSV (*.csv)",
            "pdf": "PDF (*.pdf)",
        }
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить экспорт", f"audit_export.{fmt}", filters.get(fmt, ""))
        if not path:
            return
        try:
            out = export_audit_log(
                fmt,
                path,
                pwd_edit.text(),
                exp_from.text().strip(),
                exp_to.text().strip(),
                encrypt=True,
            )
            QMessageBox.information(self, "Экспорт", f"Сохранено: {out}")
            self._load_data()
        except ValueError as exc:
            show_exception(self, exc, code="audit_export_failed")
        except Exception as exc:
            show_exception(self, exc, code="audit_export_failed")

    def _on_export(self) -> None:
        # VER-3: сохранить текстовый отчёт проверки
        report = get_last_report()
        if not report:
            result = verify_manual_full()
            report = result.get("report", "")
        if not report:
            QMessageBox.information(self, "Экспорт", "Нет отчёта.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить отчёт",
            "audit_verify_report.txt",
            "Text (*.txt)",
        )
        if path:
            export_report_to_file(path, report)
            QMessageBox.information(self, "Экспорт", "Отчёт сохранён.")
