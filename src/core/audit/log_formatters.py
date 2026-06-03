from __future__ import annotations

# экспорт журнала: JSON, CSV, PDF

import csv
import json
from pathlib import Path
from typing import Any


def _rows_to_dicts(rows: list[tuple]) -> list[dict[str, Any]]:
    # строки БД → словари для JSON
    result = []
    for row in rows:
        action, timestamp, entry_id, details_text, signature_hex = row
        item = {
            "action": action,
            "timestamp": timestamp,
            "entry_id": entry_id,
            "details": details_text,
            "signature": signature_hex,
        }
        result.append(item)
    return result


def export_json(rows: list[tuple], file_path: str | Path) -> None:
    # ARC-1: экспорт в JSON
    """Export json."""
    data = _rows_to_dicts(rows)
    path = Path(file_path)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def export_cef(rows: list[tuple], file_path: str | Path) -> None:
    # COMP-1: экспорт в CEF
    """Export cef."""
    from src.core.audit.audit_compliance import format_cef_from_row

    lines = [format_cef_from_row(row) for row in rows]
    path = Path(file_path)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def export_csv(rows: list[tuple], file_path: str | Path) -> None:
    # ARC-1: экспорт в CSV
    """Export csv."""
    path = Path(file_path)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["action", "timestamp", "entry_id", "details", "signature"])
        for row in rows:
            writer.writerow(list(row))


def export_pdf(rows: list[tuple], file_path: str | Path) -> None:
    # простой текстовый PDF без внешних библиотек
    """Export pdf."""
    lines = ["Audit Log Export", ""]
    for row in rows:
        action, timestamp, entry_id, details_text, signature_hex = row
        line = f"{timestamp} | {action} | entry_id={entry_id}"
        lines.append(line)
        lines.append(f"  details: {details_text[:200]}")
        lines.append(f"  signature: {signature_hex[:32]}...")
        lines.append("")

    text = "\n".join(lines)
    pdf_bytes = _build_simple_pdf(text)
    Path(file_path).write_bytes(pdf_bytes)


def _build_simple_pdf(text: str) -> bytes:
    # минимальный одностраничный PDF
    safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    content = f"BT /F1 10 Tf 50 750 Td ({safe}) Tj ET"
    content_bytes = content.encode("latin-1", errors="replace")

    objects = []
    objects.append(b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
    objects.append(b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n")
    objects.append(
        b"3 0 obj<< /Type /Page /Parent 2 0 R "
        b"/MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources<< /Font<< /F1 5 0 R >> >> >>endobj\n"
    )
    objects.append(
        b"4 0 obj<< /Length " + str(len(content_bytes)).encode() + b" >>stream\n"
        + content_bytes
        + b"\nendstream endobj\n"
    )
    objects.append(b"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n")

    header = b"%PDF-1.4\n"
    body = b""
    offsets = [0]
    pos = len(header)
    for obj in objects:
        offsets.append(pos)
        body += obj
        pos += len(obj)

    xref_start = len(header) + len(body)
    xref = b"xref\n0 " + str(len(offsets)).encode() + b"\n"
    xref += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        xref += f"{off:010d} 00000 n \n".encode()

    trailer = (
        b"trailer<< /Size " + str(len(offsets)).encode()
        + b" /Root 1 0 R >>\nstartxref\n" + str(xref_start).encode()
        + b"\n%%EOF"
    )
    return header + body + xref + trailer
