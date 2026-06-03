from __future__ import annotations

# Sprint 6: безопасность импорта (SEC-4..SEC-5)

import re
from typing import Union

from src.core.security.memory_guard import secure_wipe
from src.core.security.side_channel_protection import constant_time_compare

# SEC-5: простые шаблоны (скрипты, исполняемый код в тексте импорта)
_MALWARE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("script_tag", re.compile(r"<\s*script\b", re.IGNORECASE)),
    ("javascript_uri", re.compile(r"javascript\s*:", re.IGNORECASE)),
    ("vbscript_uri", re.compile(r"vbscript\s*:", re.IGNORECASE)),
    ("html_event_handler", re.compile(r"\bon\w+\s*=", re.IGNORECASE)),
    ("php_tag", re.compile(r"<\?php", re.IGNORECASE)),
    ("exec_call", re.compile(r"\bexec\s*\(", re.IGNORECASE)),
    ("eval_call", re.compile(r"\beval\s*\(", re.IGNORECASE)),
    ("powershell", re.compile(r"powershell\s+(-enc|-e\s)", re.IGNORECASE)),
    ("cmd_shell", re.compile(r"\bcmd\.exe\b", re.IGNORECASE)),
]


def scan_import_text(text: str) -> None:
    # SEC-5: до разбора JSON/CSV — отклонить опасное содержимое
    """Scan import text."""
    if not text:
        return
    for name, pattern in _MALWARE_PATTERNS:
        if pattern.search(text):
            raise ValueError(f"импорт отклонён: обнаружен опасный шаблон ({name})")


def wipe_sensitive(data: Union[bytes, bytearray]) -> None:
    # INT-4: secure wipe (Sprint 7)
    """Wipe sensitive."""
    if not data:
        return
    secure_wipe(data if isinstance(data, bytearray) else bytearray(data))


def keys_differ(vault_key: bytes, io_key: bytes) -> bool:
    # SEC-3: ключи export/import не должны совпадать с vault
    """Keys differ."""
    if len(vault_key) != len(io_key):
        return True
    return not constant_time_compare(vault_key, io_key)
