# SEC-2: Валидация и очистка пользовательского ввода

def sanitize_string(value: str, max_len: int = 2000) -> str:
    """Очистка строки: обрезка пробелов и длины."""
    if value is None:
        return ""
    s = str(value).strip()
    return s[:max_len] if len(s) > max_len else s


def validate_password_length(password: str, min_len: int = 4) -> bool:
    """Проверка минимальной длины пароля."""
    return password is not None and len(password) >= min_len
