from __future__ import annotations

# Sprint 6: упаковка share в QR (package_b64)

import base64
import json
import zlib
from typing import Any

# один QR (version 40, EC-L): ~2953 байт полезной нагрузки; запас под JSON-обёртку
MAX_SINGLE_QR_COMPRESSED_BYTES = 2000


def encode_share_package_b64(package: dict[str, Any]) -> str:
    """Encode share package b64."""
    raw = json.dumps(package, ensure_ascii=False, sort_keys=True).encode("utf-8")
    compressed = zlib.compress(raw, level=9)
    if len(compressed) > MAX_SINGLE_QR_COMPRESSED_BYTES:
        raise ValueError(
            "пакет share слишком большой для одного QR — выберите «Файл» или «Ссылка»"
        )
    return base64.b64encode(compressed).decode("ascii")


def decode_share_package_b64(value: str) -> dict[str, Any]:
    """Decode share package b64."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("пустой package_b64")
    try:
        raw = zlib.decompress(base64.b64decode(text))
    except Exception as exc:
        raise ValueError("не удалось разобрать package_b64") from exc
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("package_b64 должен быть JSON-объектом")
    return data
