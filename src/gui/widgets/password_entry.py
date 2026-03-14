from __future__ import annotations

from PyQt6.QtWidgets import QHBoxLayout, QLineEdit, QPushButton, QWidget


# простое поле ввода пароля с кнопкой показать/скрыть
class PasswordEntry(QWidget):

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._edit = QLineEdit(self)
        self._edit.setEchoMode(QLineEdit.EchoMode.Password)

        self._toggle_button = QPushButton("👁", self)
        self._toggle_button.setCheckable(True)
        self._toggle_button.clicked.connect(self._on_toggle_clicked)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._edit)
        layout.addWidget(self._toggle_button)

    def _on_toggle_clicked(self) -> None:
        if self._toggle_button.isChecked():
            self._edit.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self._edit.setEchoMode(QLineEdit.EchoMode.Password)

    def text(self) -> str:
        return self._edit.text()

    def setText(self, text: str) -> None:  # noqa: N802
        self._edit.setText(text)

