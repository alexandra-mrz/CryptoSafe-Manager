from __future__ import annotations

from PyQt6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem


# простая таблица-заглушка для записей хранилища
class SecureTable(QTableWidget):

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(["Title", "Username", "URL"])
        # убираем светлую нумерацию строк слева
        self.verticalHeader().setVisible(False)
        # не используем чередование цветов
        self.setAlternatingRowColors(False)
        # растягиваем столбцы на всю ширину
        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._fill_placeholder_rows()

    def _fill_placeholder_rows(self) -> None:
        self.setRowCount(3)
        demo = [
            ("Example 1", "user1", "https://example.com"),
            ("Example 2", "user2", "https://wallet.com"),
            ("Example 3", "user3", "https://crypto.com"),
        ]
        for row, (title, username, url) in enumerate(demo):
            self.setItem(row, 0, QTableWidgetItem(title))
            self.setItem(row, 1, QTableWidgetItem(username))
            self.setItem(row, 2, QTableWidgetItem(url))

    def set_language(self, code: str) -> None:
        # простая смена заголовков таблицы в зависимости от языка
        if code == "ru":
            labels = ["Название", "Пользователь", "URL"]
        else:
            labels = ["Title", "Username", "URL"]
        self.setHorizontalHeaderLabels(labels)

