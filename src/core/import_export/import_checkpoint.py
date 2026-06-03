from __future__ import annotations

# Sprint 6: контрольная точка импорта (ERR-2)

import json
from pathlib import Path
from typing import Any


def default_checkpoint_path(file_path: str) -> str:
    # рядом с импортируемым файлом
    """Default checkpoint path."""
    src = Path(file_path)
    return str(src.with_suffix(src.suffix + ".import.ckpt.json"))


def save_checkpoint(
    path: str,
    *,
    file_path: str,
    fmt: str,
    mode: str,
    next_index: int,
    result: dict[str, Any],
    failed: bool = False,
) -> None:
    # ERR-2: сохранить прогресс на диск
    """Save checkpoint."""
    data = {
        "version": 1,
        "file_path": str(file_path),
        "format": str(fmt),
        "mode": str(mode),
        "next_index": int(next_index),
        "failed": bool(failed),
        "result": {
            "added": int(result.get("added", 0)),
            "updated": int(result.get("updated", 0)),
            "skipped": int(result.get("skipped", 0)),
            "removed": int(result.get("removed", 0)),
        },
    }
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_checkpoint(path: str) -> dict[str, Any]:
    # ERR-2: прочитать checkpoint для resume
    """Load checkpoint."""
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("checkpoint должен быть JSON-объектом")
    return data


def delete_checkpoint(path: str) -> None:
    # ERR-2: удалить файл после успешного импорта
    """Delete checkpoint."""
    p = Path(path)
    if p.exists():
        p.unlink()
