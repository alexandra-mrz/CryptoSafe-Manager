
from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLineEdit, QPushButton, QWidget


class PasswordEntry(QWidget):
    """Поле пароля с кнопкой показать/скрыть."""

    textChanged = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Создать виджет."""
        super().__init__(parent)

        self._edit = QLineEdit(self)
        self._edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._edit.textChanged.connect(self.textChanged.emit)

        self._toggle_button = QPushButton("👁", self)
        self._toggle_button.setCheckable(True)
        self._toggle_button.clicked.connect(self._on_toggle_clicked)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._edit)
        layout.addWidget(self._toggle_button)

    def _on_toggle_clicked(self) -> None:
        """Переключить видимость пароля."""
        if self._toggle_button.isChecked():
            self._edit.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self._edit.setEchoMode(QLineEdit.EchoMode.Password)

    def text(self) -> str:
        """Вернуть текст пароля."""
        return self._edit.text()

    def setText(self, text: str) -> None:  # noqa: N802
        """Установить текст пароля."""
        self._edit.setText(text)

    def clear(self) -> None:
        """Очистить поле пароля."""
        self._edit.clear()

    def setEnabled(self, enabled: bool) -> None:  # noqa: N802
        """Включить/выключить поле и кнопку показа."""
        super().setEnabled(enabled)
        self._edit.setEnabled(enabled)
        self._toggle_button.setEnabled(enabled)

    def setFocusToEdit(self) -> None:
        """Поставить фокус в поле ввода."""
        self._edit.setFocus()
