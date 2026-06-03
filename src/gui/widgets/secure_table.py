
from __future__ import annotations

# Sprint 7 / UX-1: клавиатурная навигация в таблице vault

from urllib.parse import urlparse

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QBrush
from PyQt6.QtWidgets import QHeaderView, QMenu, QTableWidget, QTableWidgetItem


class SecureTable(QTableWidget):
    """Таблица записей vault."""

    editRequested = pyqtSignal(int)
    deleteRequested = pyqtSignal(list)
    copyUsernameRequested = pyqtSignal(int)
    copyPasswordRequested = pyqtSignal(int)
    copyAllRequested = pyqtSignal(int)
    passwordToggleRequested = pyqtSignal(int, int, bool)  # entry_id, row, visible

    def __init__(self, parent=None) -> None:
        """Создать таблицу и подключить сигналы."""
        super().__init__(parent)
        self._show_passwords = False
        self._clipboard_entry_id: int | None = None
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(["Title", "Username", "Domain", "Updated", "Password"])
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(False)
        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionsMovable(True)
        self._entry_ids: list[int | None] = []
        self.setRowCount(0)

        # Выделение нескольких строк и контекстное меню.
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._open_context_menu)
        self.setSortingEnabled(True)
        self.cellClicked.connect(self._on_cell_clicked)
        self.setAccessibleName("Таблица записей")
        self.setAccessibleDescription("Стрелки — выбор, Enter — изменить, Delete — удалить")

    def keyPressEvent(self, event) -> None:
        # UX-1: Enter / Delete
        """Keypressevent."""
        key = event.key()
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            ids = self.get_selected_entry_ids()
            if ids:
                self.editRequested.emit(int(ids[0]))
                return
        if key == Qt.Key.Key_Delete:
            ids = self.get_selected_entry_ids()
            if ids:
                self.deleteRequested.emit(ids)
                return
        super().keyPressEvent(event)

    def set_entries(self, entries: list[dict]) -> None:
        """Заполнить таблицу данными."""
        self.setSortingEnabled(False)
        self.setUpdatesEnabled(False)
        try:
            self._entry_ids = [int(e.get("id")) if e.get("id") is not None else None for e in entries]
            self.setRowCount(len(entries))
            for row, e in enumerate(entries):
                entry_id = int(e.get("id")) if e.get("id") is not None else None
                title = str(e.get("title", "") or "")
                username = str(e.get("username", "") or "")
                url = str(e.get("url", "") or "")
                updated_at = str(e.get("updated_at", "") or "")

                self.setItem(row, 0, QTableWidgetItem(title))
                self.setItem(row, 1, QTableWidgetItem(self._mask_after_4(username)))
                self.setItem(row, 2, QTableWidgetItem(self._domain_from_url(url)))
                self.setItem(row, 3, QTableWidgetItem(updated_at))

                # Пароль в item не храним, только маску.
                pw_item = QTableWidgetItem(self._mask_password("********"))
                pw_item.setData(Qt.ItemDataRole.UserRole + 1, False)  # visible flag
                pw_item.setToolTip("Кликните, чтобы показать/скрыть пароль")
                self.setItem(row, 4, pw_item)

                if entry_id is not None:
                    self.item(row, 0).setData(Qt.ItemDataRole.UserRole, entry_id)
            self._apply_clipboard_row_highlight()
        finally:
            self.setUpdatesEnabled(True)
            self.setSortingEnabled(True)

    def get_entry_id_at_row(self, row: int) -> int | None:
        """Вернуть id записи для строки."""
        if 0 <= row < len(self._entry_ids):
            return self._entry_ids[row]
        return None

    def get_selected_entry_ids(self) -> list[int]:
        """Вернуть id выделенных строк."""
        ids: list[int] = []
        for idx in self.selectionModel().selectedRows():
            entry_id = self.get_entry_id_at_row(idx.row())
            if entry_id is not None and entry_id not in ids:
                ids.append(entry_id)
        return ids

    def set_show_passwords(self, enabled: bool) -> None:
        """Глобально переключить видимость паролей."""
        self._show_passwords = bool(enabled)
        for row in range(self.rowCount()):
            entry_id = self.get_entry_id_at_row(row)
            if entry_id is None:
                continue
            self.passwordToggleRequested.emit(int(entry_id), row, self._show_passwords)

    def set_language(self, code: str) -> None:
        """Обновить заголовки колонок по языку."""
        if code == "ru":
            labels = ["Название", "Логин", "Домен", "Изменено", "Пароль"]
        else:
            labels = ["Title", "Username", "Domain", "Updated", "Password"]
        self.setHorizontalHeaderLabels(labels)

    def _mask_after_4(self, text: str) -> str:
        """Маска логина после 4 символов."""
        if not text:
            return ""
        if len(text) <= 4:
            return text
        return text[:4] + "•" * (len(text) - 4)

    def _mask_password(self, text: str) -> str:
        """Вернуть маску пароля."""
        if not text:
            return ""
        return "•" * max(6, min(10, len(text)))

    def _domain_from_url(self, url: str) -> str:
        """Извлечь домен из URL."""
        if not url:
            return ""
        try:
            parsed = urlparse(url if "://" in url else ("https://" + url))
            host = parsed.netloc or ""
            return host.split(":")[0]
        except Exception:
            return ""

    def _on_cell_clicked(self, row: int, column: int) -> None:
        """Обработать клик по ячейке."""
        if column != 4:
            return
        item = self.item(row, column)
        if item is None:
            return
        entry_id = self.get_entry_id_at_row(row)
        if entry_id is None:
            return
        current = bool(item.data(Qt.ItemDataRole.UserRole + 1))
        visible = not current
        item.setData(Qt.ItemDataRole.UserRole + 1, visible)
        self.passwordToggleRequested.emit(int(entry_id), row, bool(visible or self._show_passwords))

    def set_password_display(self, row: int, password: str, visible: bool) -> None:
        """Показать или скрыть пароль в строке."""
        item = self.item(row, 4)
        if item is None:
            return
        if visible:
            item.setText(password)
        else:
            item.setText(self._mask_password(password))

    def set_clipboard_source_entry_id(self, entry_id: int | None) -> None:
        # подсветка строки, у которой данные сейчас в буфере
        """Set clipboard source entry id."""
        self._clipboard_entry_id = int(entry_id) if entry_id is not None else None
        self._apply_clipboard_row_highlight()

    def highlight_entry_by_id(self, entry_id: int) -> None:
        # GUI-4: подсветка записи из журнала аудита
        """Highlight entry by id."""
        target = int(entry_id)
        normal_brush = self.palette().base()
        found_row = -1
        for row in range(self.rowCount()):
            rid = self.get_entry_id_at_row(row)
            active = rid is not None and int(rid) == target
            if active:
                found_row = row
            for col in range(self.columnCount()):
                it = self.item(row, col)
                if it is None:
                    continue
                if active:
                    it.setBackground(QColor("#fff9c4"))
                else:
                    it.setBackground(QBrush(normal_brush))
        if found_row >= 0:
            self.selectRow(found_row)
            self.scrollToItem(self.item(found_row, 0))

    def _apply_clipboard_row_highlight(self) -> None:
        # легкая подсветка всей строки
        normal_brush = self.palette().base()
        for row in range(self.rowCount()):
            rid = self.get_entry_id_at_row(row)
            active = rid is not None and self._clipboard_entry_id is not None and int(rid) == int(self._clipboard_entry_id)
            for col in range(self.columnCount()):
                it = self.item(row, col)
                if it is None:
                    continue
                if active:
                    it.setBackground(QColor("#e3f2fd"))
                else:
                    # возвращаем стандартный фон таблицы
                    it.setBackground(QBrush(normal_brush))

    def _open_context_menu(self, pos) -> None:
        """Открыть контекстное меню для строки."""
        row = self.rowAt(pos.y())
        if row < 0:
            return

        entry_id = self.get_entry_id_at_row(row)
        if entry_id is None:
            return

        menu = QMenu(self)
        action_edit = menu.addAction("Редактировать")
        action_delete = menu.addAction("Удалить")
        action_copy_user = menu.addAction("Копировать логин")
        action_copy_pw = menu.addAction("Копировать пароль")
        action_copy_all = menu.addAction("Копировать всё")

        chosen = menu.exec(self.viewport().mapToGlobal(pos))
        if chosen is None:
            return

        if chosen == action_edit:
            self.editRequested.emit(int(entry_id))
        elif chosen == action_delete:
            ids = self.get_selected_entry_ids()
            if not ids:
                ids = [int(entry_id)]
            self.deleteRequested.emit(ids)
        elif chosen == action_copy_user:
            self.copyUsernameRequested.emit(int(entry_id))
        elif chosen == action_copy_pw:
            self.copyPasswordRequested.emit(int(entry_id))
        elif chosen == action_copy_all:
            self.copyAllRequested.emit(int(entry_id))
