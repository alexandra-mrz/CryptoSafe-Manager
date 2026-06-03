from __future__ import annotations

# Sprint 7 / SC-1, SC-2: constant-time сравнения

import secrets
from typing import Union


def constant_time_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """Compare strings or bytes without early exit (SC-1)."""
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return secrets.compare_digest(a, b)


def constant_time_equal_int(a: int, b: int) -> bool:
    """Compare integers without secret-dependent branches (SC-2)."""
    return (a ^ b) == 0
