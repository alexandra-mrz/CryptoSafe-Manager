import os
import sys
import unittest
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

class TestIntegration(unittest.TestCase):
    def test_config_load(self):
        from src.core.config import get_config, ENV
        cfg = get_config()
        self.assertTrue(hasattr(cfg, "db_path"))
        self.assertTrue(hasattr(cfg, "encryption_params"))
        self.assertTrue(hasattr(cfg, "user_prefs"))
    def test_main_window_import_and_create(self):
        from PyQt5.QtWidgets import QApplication
        from src.gui.main_window import MainWindow
        app = QApplication.instance() or QApplication(sys.argv)
        win = MainWindow()
        self.assertTrue(win.isWidgetType())
        self.assertIsNotNone(win._table)
        win.close()
    def test_setup_wizard_import(self):
        from PyQt5.QtWidgets import QApplication
        from src.gui.setup_wizard import SetupWizard
        app = QApplication.instance() or QApplication(sys.argv)
        w = SetupWizard(parent=None)
        w.close()
