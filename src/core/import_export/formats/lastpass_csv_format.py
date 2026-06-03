from __future__ import annotations

# Sprint 6: CSV LastPass (IMP-1)

import csv
import io
from typing import Any


def entries_to_lastpass_csv(entries: list[dict]) -> str:
    # EXP-1: экспорт в CSV LastPass (name, url, username, password, extra, grouping)
    """Entries to lastpass csv."""
    buf = io.StringIO()
    fieldnames = ["name", "url", "username", "password", "extra", "grouping"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for item in entries:
        writer.writerow(
            {
                "name": str(item.get("title", "") or ""),
                "url": str(item.get("url", "") or ""),
                "username": str(item.get("username", "") or ""),
                "password": str(item.get("password", "") or ""),
                "extra": str(item.get("notes", "") or ""),
                "grouping": str(item.get("tags", "") or item.get("category", "") or ""),
            }
        )
    return buf.getvalue()


def parse_lastpass_csv(text: str) -> list[dict]:
    # типичные колонки LastPass: name, url, username, password, extra, grouping
    """Parse lastpass csv."""
    buf = io.StringIO(text)
    reader = csv.DictReader(buf)
    result: list[dict] = []
    for row in reader:
        if not row:
            continue
        title = row.get("name") or row.get("Name") or row.get("title") or ""
        url = row.get("url") or row.get("URL") or ""
        username = row.get("username") or row.get("Username") or ""
        password = row.get("password") or row.get("Password") or ""
        notes = row.get("extra") or row.get("Extra") or row.get("notes") or ""
        tags = row.get("grouping") or row.get("Group") or row.get("tags") or ""
        result.append(
            {
                "title": str(title or ""),
                "username": str(username or ""),
                "password": str(password or ""),
                "url": str(url or ""),
                "notes": str(notes or ""),
                "tags": str(tags or ""),
            }
        )
    return result
