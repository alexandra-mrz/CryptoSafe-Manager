
from __future__ import annotations

# вспомогательные функции для работы с чувствительными данными в памяти (cry-4)

from src.core.security.memory_guard import secure_wipe


def zero_bytearray(data: bytearray) -> None:
    # MEM-2: secure wipe через memory_guard
    """Zero bytearray."""
    secure_wipe(data)
