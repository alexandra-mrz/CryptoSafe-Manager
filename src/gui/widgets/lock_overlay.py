from __future__ import annotations

# Sprint 7 / ACT-3, ACT-4: overlay блокировки vault

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget


class LockOverlay(QWidget):
    """ACT-3 / ACT-4: экран блокировки поверх vault."""

    unlockRequested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setStyleSheet("background-color: rgba(30, 30, 30, 220);")
        layout = QVBoxLayout(self)
        label = QLabel("Хранилище заблокировано", self)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet("color: white; font-size: 18px;")
        btn = QPushButton("Разблокировать", self)
        btn.clicked.connect(self.unlockRequested.emit)
        layout.addStretch(1)
        layout.addWidget(label)
        layout.addWidget(btn, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch(1)
        self.hide()

    def show_overlay(self) -> None:
        """Show overlay."""
        if self.parentWidget() is not None:
            self.setGeometry(self.parentWidget().rect())
        self.raise_()
        self.show()

    def hide_overlay(self) -> None:
        """Hide overlay."""
        self.hide()

    def resizeEvent(self, event) -> None:
        """Resizeevent."""
        if self.parentWidget() is not None:
            self.setGeometry(self.parentWidget().rect())
        super().resizeEvent(event)
