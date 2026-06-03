from __future__ import annotations

# CRY-3/CRY-4: проверка подписи и цепочки хешей

import hashlib
import json
from typing import Any

from src.core.audit.log_signer import verify_bytes


def compute_entry_hash(entry_json: str) -> str:
    # CRY-4: SHA-256 хеш тела записи для цепочки
    """Compute entry hash."""
    return hashlib.sha256(entry_json.encode("utf-8")).hexdigest()


def build_signed_payload_bytes(stored: dict[str, Any]) -> bytes:
    # CRY-3: подпись по entry_data + sequence_number + previous_hash + entry_hash
    """Build signed payload bytes."""
    payload = {
        "entry_data": stored["entry_data"],
        "sequence_number": stored["sequence_number"],
        "previous_hash": stored["previous_hash"],
        "entry_hash": stored["entry_hash"],
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def parse_stored_details(details_text: str) -> dict[str, Any]:
    # JSON из колонки entry_data
    """Parse stored details."""
    if not details_text:
        return {}
    try:
        data = json.loads(details_text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    return {"raw": details_text}


def verify_single_row(
    action: str,
    timestamp: str,
    entry_id: int | None,
    details_text: str,
    signature: str,
) -> tuple[bool, str]:
    # CRY-3: подпись и хеш одной записи
    """Verify single row."""
    stored = parse_stored_details(details_text)

    # новый формат CRY-3
    if "entry_data" in stored:
        entry_data = stored.get("entry_data")
        seq = stored.get("sequence_number")
        prev_hash = stored.get("previous_hash")
        entry_hash = stored.get("entry_hash")
    else:
        # старые записи ARC
        entry_data = stored
        seq = stored.get("sequence_number")
        prev_hash = stored.get("previous_hash")
        entry_hash = stored.get("entry_hash")

    if entry_data is None or seq is None or prev_hash is None or entry_hash is None:
        return False, "нет полей CRY-3"

    record = {
        "entry_data": entry_data,
        "sequence_number": seq,
        "previous_hash": prev_hash,
        "entry_hash": entry_hash,
    }

    if not verify_bytes(build_signed_payload_bytes(record), signature):
        return False, "неверная подпись"

    hash_source = json.dumps(
        {
            "entry_data": entry_data,
            "sequence_number": seq,
            "previous_hash": prev_hash,
        },
        sort_keys=True,
    )
    if compute_entry_hash(hash_source) != entry_hash:
        return False, "хеш записи не совпадает"

    if str(entry_data.get("event_type", action)) != action:
        return False, "event_type не совпадает с action"

    return True, "ok"


def verify_chain(rows: list[tuple]) -> tuple[bool, list[str]]:
    # CRY-4: проверить всю цепочку sequence_number и previous_hash
    """Verify chain."""
    errors: list[str] = []
    last_hash = "0" * 64
    last_seq = -1

    for index, row in enumerate(rows):
        action, timestamp, entry_id, details_text, signature = row
        ok, msg = verify_single_row(action, timestamp, entry_id, details_text, signature)
        if not ok:
            errors.append(f"запись {index + 1}: {msg}")
            continue

        stored = parse_stored_details(details_text)
        seq = int(stored.get("sequence_number", -1))
        prev_hash = str(stored.get("previous_hash", ""))

        if seq != last_seq + 1:
            errors.append(f"запись {index + 1}: нарушен sequence_number")

        if prev_hash != last_hash:
            errors.append(f"запись {index + 1}: разрыв цепочки previous_hash")

        last_hash = str(stored.get("entry_hash", last_hash))
        last_seq = seq

    if errors:
        return False, errors
    return True, ["цепочка целостна"]
