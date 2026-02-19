# AuditLogViewer — просмотр логов аудита

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit


class AuditLogViewer(QWidget):
    """Окно просмотра логов аудита."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Журнал аудита"))
        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setPlaceholderText("Здесь выводятся записи журнала аудита.")
        layout.addWidget(self._text)

    def append_log(self, line: str):
        self._text.append(line)
