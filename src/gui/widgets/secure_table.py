from __future__ import annotations

from PyQt6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem


# таблица записей из vault_entries
class SecureTable(QTableWidget):

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(["Title", "Username", "URL"])
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(False)
        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._entry_ids: list[int | None] = []
        self.setRowCount(0)

    def set_entries(self, entries: list[tuple[int | None, str, str, str]]) -> None:
        self._entry_ids = [e[0] for e in entries]
        self.setRowCount(len(entries))
        for row, (entry_id, title, username, url) in enumerate(entries):
            self.setItem(row, 0, QTableWidgetItem(title or ""))
            self.setItem(row, 1, QTableWidgetItem(username or ""))
            self.setItem(row, 2, QTableWidgetItem(url or ""))

    def get_entry_id_at_row(self, row: int) -> int | None:
        if 0 <= row < len(self._entry_ids):
            return self._entry_ids[row]
        return None

    def set_language(self, code: str) -> None:
        if code == "ru":
            labels = ["Название", "Пользователь", "URL"]
        else:
            labels = ["Title", "Username", "URL"]
        self.setHorizontalHeaderLabels(labels)

