
from __future__ import annotations

# вспомогательные функции для работы с чувствительными данными в памяти (cry-4)

import ctypes


def zero_bytearray(data: bytearray) -> None:
    # записать нули поверх существующих байтов, чтобы не держать чувствительные данные в памяти
    length = len(data)
    if length == 0:
        return

    buf = (ctypes.c_char * length).from_buffer(data)
    ctypes.memset(buf, 0, length)
