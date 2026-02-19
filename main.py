# Точка входа CryptoSafe Manager

import os
import sys

# Добавляем корень проекта в путь для импорта src
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.gui.main_window import main

if __name__ == "__main__":
    main()
