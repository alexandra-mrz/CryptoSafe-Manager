# SecureTable — таблица для записей хранилища

from PyQt5.QtWidgets import QWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QHeaderView, QAbstractItemView


class SecureTable(QWidget):
    """Таблица для отображения записей vault (title, username, url и т.д.)."""

    COLUMNS = ("title", "username", "url", "updated_at")

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._table = QTableWidget()
        self._table.setColumnCount(len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels([c.replace("_", " ").title() for c in self.COLUMNS])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        layout.addWidget(self._table)
        self._row_to_id = {}

    def clear(self):
        self._table.setRowCount(0)
        self._row_to_id.clear()

    def add_row(self, entry_id, title, username, url, updated_at):
        row = self._table.rowCount()
        self._table.insertRow(row)
        for c, val in enumerate((title or "", username or "", url or "", updated_at or "")):
            self._table.setItem(row, c, QTableWidgetItem(str(val)))
        self._row_to_id[row] = entry_id
        return row

    def get_selected_id(self):
        row = self._table.currentRow()
        return self._row_to_id.get(row) if row >= 0 else None

    def get_selected_iid(self):
        return self._table.currentRow()
