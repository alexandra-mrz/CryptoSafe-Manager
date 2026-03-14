
import os
import unittest

import pyautogui


@unittest.skipUnless(os.getenv("RUN_GUI_TESTS") == "1", "GUI tests are optional")
class TestGuiWithPyAutoGUI(unittest.TestCase):
    def test_screen_size_non_zero(self) -> None:
        # простейшая проверка, что pyautogui видит экран
        # в будущих спринтах сюда можно добавить
        # открытие окна cryptosafe manager и проверки по заголовку
        width, height = pyautogui.size()
        self.assertGreater(width, 0)
        self.assertGreater(height, 0)


if __name__ == "__main__":
    unittest.main()
