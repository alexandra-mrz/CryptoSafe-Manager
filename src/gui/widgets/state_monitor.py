
from __future__ import annotations

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QDialog

from src.core.state_manager import get_state_manager


# простое окно-монитор для просмотра текущего состояния
class StateMonitor(QDialog):

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Монитор состояний")

        self._state_manager = get_state_manager()

        self._session_label = QLabel(self)
        self._clipboard_label = QLabel(self)
        self._inactivity_label = QLabel(self)

        layout = QVBoxLayout(self)
        layout.addWidget(self._session_label)
        layout.addWidget(self._clipboard_label)
        layout.addWidget(self._inactivity_label)

        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

        self._refresh()

    def _refresh(self) -> None:
        state = self._state_manager.state
        self._session_label.setText(f"Сессия: {'заблокирована' if state.locked else 'разблокирована'}")
        self._clipboard_label.setText(f"Буфер: {state.clipboard_seconds_left} с до очистки")
        self._inactivity_label.setText(f"Неактивность: {state.inactivity_seconds} с")
