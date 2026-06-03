from __future__ import annotations

# Sprint 7 / UX-2, UX-3; Sprint 8 / POL-2: единые стили GUI

BASE_STYLESHEET = """
QWidget {
    font-family: "Segoe UI", "Roboto", "Helvetica Neue", Arial, sans-serif;
    font-size: 10pt;
}
QPushButton {
    min-height: 28px;
    padding: 4px 14px;
    border-radius: 4px;
}
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox {
    min-height: 26px;
    padding: 2px 8px;
}
QGroupBox {
    margin-top: 10px;
    padding-top: 10px;
    font-weight: 600;
}
QDialogButtonBox QPushButton {
    min-width: 88px;
}
QTableWidget, QTreeWidget {
    gridline-color: #dadce0;
    alternate-background-color: #f8f9fa;
}
QStatusBar {
    padding: 2px 8px;
}
"""

DIALOG_LAYOUT_SPACING = 10
DIALOG_MARGIN = 12


def apply_base_styles(app) -> None:
    """POL-2: базовые шрифты, отступы и кнопки для всего приложения."""
    current = app.styleSheet() or ""
    if BASE_STYLESHEET.strip() not in current:
        app.setStyleSheet(BASE_STYLESHEET + current)


def tune_dialog_layout(layout) -> None:
    """POL-2: единые margins/spacing для диалогов."""
    if layout is not None:
        layout.setSpacing(DIALOG_LAYOUT_SPACING)
        layout.setContentsMargins(DIALOG_MARGIN, DIALOG_MARGIN, DIALOG_MARGIN, DIALOG_MARGIN)
