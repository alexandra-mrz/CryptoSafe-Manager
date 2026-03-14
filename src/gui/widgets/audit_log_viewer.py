
from __future__ import annotations

from PyQt6.QtWidgets import QLabel, QVBoxLayout, QDialog


# заглушка для будущего просмотра журнала аудита
class AuditLogViewer(QDialog):

    def __init__(self, parent: QDialog | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Журнал аудита")
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("AuditLogViewer: здесь будут логи аудита."))
