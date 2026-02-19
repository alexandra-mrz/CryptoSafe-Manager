# PasswordEntry — поле ввода с маскировкой и кнопкой показа (кнопка с фиксированной шириной, всегда видна)

from PyQt5.QtWidgets import QWidget, QLineEdit, QPushButton, QHBoxLayout


class PasswordEntry(QWidget):
    """Поле ввода пароля с маскировкой и кнопкой показа/скрытия."""

    def __init__(self, parent=None, show_char="*"):
        super().__init__(parent)
        self._show_char = show_char
        self._visible = False
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._entry = QLineEdit()
        self._entry.setEchoMode(QLineEdit.Password)
        self._entry.setPlaceholderText("")
        layout.addWidget(self._entry, 1)
        self._btn = QPushButton("Показать")
        self._btn.setMaximumWidth(90)
        self._btn.clicked.connect(self._toggle)
        layout.addWidget(self._btn, 0)
        self.setFocusProxy(self._entry)

    def _toggle(self):
        self._visible = not self._visible
        if self._visible:
            self._entry.setEchoMode(QLineEdit.Normal)
            self._btn.setText("Скрыть")
        else:
            self._entry.setEchoMode(QLineEdit.Password)
            self._btn.setText("Показать")

    def text(self):
        return self._entry.text()

    def setText(self, value: str):
        self._entry.setText(value)

    def get(self):
        return self._entry.text()

    def set(self, value: str):
        self._entry.setText(value)
