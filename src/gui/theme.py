# Применение темы и языка из настроек

def apply_theme(app, theme_name: str):
    """Применяет тему к QApplication. theme_name: 'Светлая' | 'Тёмная'."""
    if theme_name == "Тёмная" or theme_name == "Dark":
        app.setStyleSheet("""
            QWidget { background-color: #2d2d2d; color: #e0e0e0; }
            QMenuBar { background-color: #252525; }
            QMenuBar::item:selected { background-color: #404040; }
            QMenu { background-color: #2d2d2d; }
            QMenu::item:selected { background-color: #404040; }
            QTableWidget { background-color: #2d2d2d; gridline-color: #404040; }
            QHeaderView::section { background-color: #353535; color: #e0e0e0; }
            QLineEdit, QComboBox { background-color: #353535; color: #e0e0e0; border: 1px solid #505050; }
            QPushButton { background-color: #404040; color: #e0e0e0; border: 1px solid #505050; }
            QPushButton:hover { background-color: #505050; }
            QTabWidget::pane { background-color: #2d2d2d; border: 1px solid #505050; }
            QTabBar::tab { background-color: #353535; color: #e0e0e0; padding: 6px 12px; }
            QTabBar::tab:selected { background-color: #404040; }
            QTextEdit { background-color: #252525; color: #e0e0e0; }
            QLabel { color: #e0e0e0; }
        """)
    else:
        app.setStyleSheet("")


def apply_saved_theme(app):
    """Читает тему из настроек и применяет. Вызывать при старте и после сохранения настроек."""
    try:
        from src.core.settings_store import get_setting
        theme = get_setting("theme", "Светлая")
        apply_theme(app, theme)
    except Exception:
        pass
