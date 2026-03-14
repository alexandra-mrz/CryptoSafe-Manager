import os
import unittest

from PyQt6.QtWidgets import QApplication

from src.core.config import ConfigManager
from src.gui.main_window import MainWindow
from src.gui.widgets.setup_wizard import SetupWizard


class TestIntegrationApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # один qapplication на все тесты
        cls._app = QApplication.instance() or QApplication([])

    def test_config_loading_roundtrip(self) -> None:
        cfg_path = "test_config.json"
        if os.path.exists(cfg_path):
            os.remove(cfg_path)

        cm = ConfigManager(cfg_path)
        cm.set("clipboard_timeout_seconds", 45)
        cm.set("auto_lock_minutes", 10)

        cm2 = ConfigManager(cfg_path)
        self.assertEqual(cm2.get("clipboard_timeout_seconds"), 45)
        self.assertEqual(cm2.get("auto_lock_minutes"), 10)

        os.remove(cfg_path)

    def test_main_window_launches(self) -> None:
        window = MainWindow()
        # просто проверяем, что можно показать и скрыть без ошибок
        window.show()
        window.hide()

    def test_setup_wizard_shows(self) -> None:
        wizard = SetupWizard()
        wizard.show()
        wizard.hide()


if __name__ == "__main__":
    unittest.main()

