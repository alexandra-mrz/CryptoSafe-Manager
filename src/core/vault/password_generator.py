from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import List


AMBIGUOUS = set("Il1O0")
SYMBOLS = "!@#$%^&*"


@dataclass
class PasswordGenOptions:
    # Параметры генерации пароля.
    """Публичный класс PasswordGenOptions."""
    length: int = 16
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = True


_history: List[str] = []


def _letters_upper() -> str:
    """Вернуть A-Z."""
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _letters_lower() -> str:
    """Вернуть a-z."""
    return "abcdefghijklmnopqrstuvwxyz"


def _digits() -> str:
    """Вернуть 0-9."""
    return "0123456789"


def _symbols() -> str:
    """Вернуть набор символов."""
    return SYMBOLS


def _filter_ambiguous(chars: str, exclude: bool) -> str:
    """Убрать неоднозначные символы при необходимости."""
    if not exclude:
        return chars
    return "".join(c for c in chars if c not in AMBIGUOUS)


def _clamp_length(n: int) -> int:
    """Ограничить длину пароля в диапазоне 8..64."""
    if n < 8:
        return 8
    if n > 64:
        return 64
    return int(n)


def _shuffle(chars: List[str]) -> None:
    """Перемешать символы через безопасный random."""
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]


def _strength_score(pw: str) -> int:
    """Вернуть простую оценку силы 0..4."""
    score = 0
    if len(pw) >= 12:
        score += 1
    if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
        score += 1
    if any(c.isdigit() for c in pw):
        score += 1
    if any(c in SYMBOLS for c in pw):
        score += 1
    return score


def generate_password(options: PasswordGenOptions | None = None) -> str:
    """Сгенерировать пароль по настройкам."""
    opts = options or PasswordGenOptions()
    length = _clamp_length(opts.length)

    pools: List[str] = []
    required: List[str] = []

    if opts.use_uppercase:
        p = _filter_ambiguous(_letters_upper(), opts.exclude_ambiguous)
        pools.append(p)
        required.append(secrets.choice(p))
    if opts.use_lowercase:
        p = _filter_ambiguous(_letters_lower(), opts.exclude_ambiguous)
        pools.append(p)
        required.append(secrets.choice(p))
    if opts.use_digits:
        p = _filter_ambiguous(_digits(), opts.exclude_ambiguous)
        pools.append(p)
        required.append(secrets.choice(p))
    if opts.use_symbols:
        p = _symbols()
        pools.append(p)
        required.append(secrets.choice(p))

    if not pools:
        raise ValueError("нужно выбрать хотя бы один набор символов")

    alphabet = "".join(pools)

    # Длина не может быть меньше числа обязательных групп.
    if length < len(required):
        length = len(required)

    for _ in range(200):
        chars: List[str] = []
        chars.extend(required)
        while len(chars) < length:
            chars.append(secrets.choice(alphabet))
        _shuffle(chars)
        pw = "".join(chars)

        if pw in _history:
            continue

        if _strength_score(pw) < 3:
            continue

        _history.append(pw)
        if len(_history) > 20:
            del _history[0 : len(_history) - 20]
        return pw

    # Запасной путь: вернуть валидный пароль без доп. фильтров.
    chars2: List[str] = []
    chars2.extend(required)
    while len(chars2) < length:
        chars2.append(secrets.choice(alphabet))
    _shuffle(chars2)
    pw2 = "".join(chars2)
    _history.append(pw2)
    if len(_history) > 20:
        del _history[0 : len(_history) - 20]
    return pw2

