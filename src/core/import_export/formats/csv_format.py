from __future__ import annotations

# Sprint 6: CSV миграции (FMT-3)

import csv
import io
from typing import Any

# FMT-3: стандартные поля (URL как в ТЗ)
_CSV_FIELDS = ["title", "username", "password", "URL", "notes"]
_CSV_META_PREFIX = "# cryptosafe-csv"


def _normalize_row(item: dict[str, Any]) -> dict[str, str]:
    # url и URL — одно поле
    return {
        "title": str(item.get("title", "") or ""),
        "username": str(item.get("username", "") or ""),
        "password": str(item.get("password", "") or ""),
        "URL": str(item.get("URL", item.get("url", "")) or ""),
        "notes": str(item.get("notes", "") or ""),
    }


def entries_to_csv_text(
    entries: list[dict],
    *,
    include_metadata_header: bool = True,
    exported_at: str = "",
    source_app: str = "CryptoSafe Manager",
) -> str:
    # FMT-3: csv.DictWriter экранирует кавычки и переносы строк
    """Entries to csv text."""
    lines: list[str] = []
    if include_metadata_header:
        ts = exported_at or ""
        lines.append(f"{_CSV_META_PREFIX} version=1.0 exported_at={ts} source={source_app}")
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore", quoting=csv.QUOTE_MINIMAL)
    writer.writeheader()
    for item in entries:
        writer.writerow(_normalize_row(item))
    lines.append(buf.getvalue())
    return "\n".join(lines)


def _strip_metadata_lines(text: str) -> tuple[list[str], dict[str, str]]:
    # FMT-3: опциональные строки # cryptosafe-csv ...
    meta: dict[str, str] = {}
    body_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith(_CSV_META_PREFIX):
            parts = line[len(_CSV_META_PREFIX) :].strip().split()
            for part in parts:
                if "=" in part:
                    key, val = part.split("=", 1)
                    meta[key.strip()] = val.strip()
            continue
        body_lines.append(line)
    return body_lines, meta


def parse_csv_text(text: str, *, delimiter: str = ",") -> list[dict]:
    # прочитать CSV в список dict
    """Parse csv text."""
    body_lines, _meta = _strip_metadata_lines(text)
    body = "\n".join(body_lines)
    buf = io.StringIO(body)
    reader = csv.DictReader(buf, delimiter=delimiter)
    result: list[dict] = []
    for row in reader:
        if not row:
            continue
        item = {
            "title": str(row.get("title", "") or ""),
            "username": str(row.get("username", "") or ""),
            "password": str(row.get("password", "") or ""),
            "url": str(row.get("URL", row.get("url", "")) or ""),
            "notes": str(row.get("notes", "") or ""),
            "tags": "",
        }
        result.append(item)
    return result


def parse_csv_text_multi_dialect(text: str) -> list[dict]:
    # запятая или точка с запятой
    """Parse csv text multi dialect."""
    rows = parse_csv_text(text, delimiter=",")
    if rows:
        return rows
    body_lines, _ = _strip_metadata_lines(text)
    first_line = ""
    for line in body_lines:
        if line.strip():
            first_line = line
            break
    if ";" in first_line and "," not in first_line:
        return parse_csv_text(text, delimiter=";")
    return rows


def get_csv_metadata(text: str) -> dict[str, str]:
    # метаданные из заголовка CSV
    """Get csv metadata."""
    _lines, meta = _strip_metadata_lines(text)
    return meta
