from __future__ import annotations

# аудит: БД (DB), цепочка, подпись, EventBus

import json
import threading
from typing import Any

from src.core.security.memory_guard import wipe_local

from src.core.audit.audit_security import ensure_signed, require_audit_read_access
from src.core.audit.log_entry import build_log_entry
from src.core.audit import log_signer
from src.core.audit.log_storage import apply_log_rotation
from src.core.audit.log_verifier import build_signed_payload_bytes, compute_entry_hash
from src.core.events import EventBus, get_event_bus
from src.database.db import get_default_database
_sequence_number = 0
_previous_hash = "0" * 64
_subscribers_ready = False
_writes_since_rotation = 0
_audit_write_lock = threading.Lock()

# PERF-5: критичные события пишем сразу, остальные через очередь EventBus
_SYNC_AUDIT_EVENTS = {
    "LoginFailed",
    "ClipboardSnoopingDetected",
    "ClipboardCopyBlocked",
    "VaultLocked",
    "UserLoggedIn",
    "UserLoggedOut",
    "AppStartup",
    "AppShutdown",
    "VaultUnlocked",
}

# INT-1: подписка на события безопасности из EventBus (Sprint 1)
_LOG_EVENT_NAMES = [
    "UserLoggedIn",
    "UserLoggedOut",
    "LoginFailed",
    "PasswordChanged",
    "EntryCreated",
    "EntryAdded",
    "EntryRead",
    "EntryUpdated",
    "EntryDeleted",
    "VaultSearched",
    "ClipboardCopied",
    "ClipboardCleared",
    "ClipboardAutoCleared",
    "ClipboardSnoopingDetected",
    "ClipboardCopyBlocked",
    "ClipboardError",
    "ClipboardMonitorStarted",
    "ClipboardMonitorStopped",
    "AppStartup",
    "AppShutdown",
    "VaultLocked",
    "VaultUnlocked",
    "SettingsChanged",
    "AuditExported",
    # INT-4 (Should): готовность к будущим событиям
    "VaultImported",
    "VaultExported",
    "VaultShared",
    "PanicModeActivated",
    "SecurityHardening",
    "TotpCodeGenerated",
]


def _load_chain_state() -> None:
    # читаем из БД номер следующей записи и хеш предыдущей (для цепочки CRY-4)
    global _sequence_number, _previous_hash
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT sequence_number, entry_data
            FROM audit_log
            ORDER BY sequence_number DESC
            LIMIT 1
            """
        )
        row = cur.fetchone()
        if not row:
            _sequence_number = 0
            _previous_hash = "0" * 64
            return

        seq_in_db = int(row[0])
        try:
            raw = row[1]
            if isinstance(raw, memoryview):
                raw = raw.tobytes()
            stored = json.loads(raw.decode("utf-8"))
        except Exception:
            _sequence_number = seq_in_db + 1
            _previous_hash = "0" * 64
            return

        _sequence_number = seq_in_db + 1
        _previous_hash = str(stored.get("entry_hash", "0" * 64))
    finally:
        conn.close()


def reload_chain_state() -> None:
    # сбросить счётчик цепочки из БД (после очистки журнала или смены БД)
    """Reload chain state."""
    _load_chain_state()


def _append_record(event_name: str, payload: Any) -> None:
    # одна запись: структура LOG, хеш, подпись, INSERT в audit_log
    global _sequence_number, _previous_hash, _writes_since_rotation

    # без ключа подписи запись не пишем (иначе «съедается» номер 0 и ломается цепочка)
    if log_signer.get_audit_signing_key() is None:
        return

    with _audit_write_lock:
        entry_data = build_log_entry(event_name, payload)
        event_type = entry_data["event_type"]
        seq = _sequence_number
        prev_hash = _previous_hash

        hash_source = json.dumps(
            {
                "entry_data": entry_data,
                "sequence_number": seq,
                "previous_hash": prev_hash,
            },
            sort_keys=True,
        )
        entry_hash = compute_entry_hash(hash_source)

        stored = {
            "entry_data": entry_data,
            "sequence_number": seq,
            "previous_hash": prev_hash,
            "entry_hash": entry_hash,
        }

        signature = log_signer.sign_bytes(build_signed_payload_bytes(stored))
        ensure_signed(signature)
        entry_blob = bytearray(json.dumps(stored, ensure_ascii=False, sort_keys=True).encode("utf-8"))
        timestamp = entry_data["timestamp"]
        entry_id = entry_data.get("entry_id")

        conn = get_default_database().create_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO audit_log
                (sequence_number, timestamp, event_type, entry_id, previous_hash, entry_data, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (seq, timestamp, event_type, entry_id, prev_hash, bytes(entry_blob), signature),
            )
            conn.commit()
        finally:
            conn.close()
            wipe_local(entry_blob)

        _sequence_number = seq + 1
        _previous_hash = entry_hash
        _writes_since_rotation += 1
        if _writes_since_rotation >= 50:
            _writes_since_rotation = 0
            apply_log_rotation()


def _handle_event(event_name: str, payload: Any) -> None:
    # обработчик подписки EventBus (INT-1)
    _append_record(event_name, payload)


class AuditLogger:
    # контроллер записи в журнал (ARC-1)

    """Публичный класс AuditLogger."""
    def log_event(self, event_type: str, details: dict[str, Any] | None = None) -> None:
        # записать событие в журнал вручную (экспорт, тесты)
        """Log event."""
        _append_record(event_type, details or {})


def setup_audit_subscribers(bus: EventBus | None = None) -> None:
    # подписаться на все события из _LOG_EVENT_NAMES (ARC-2, INT-1)
    """Setup audit subscribers."""
    global _subscribers_ready
    if _subscribers_ready:
        return

    _load_chain_state()

    if bus is None:
        bus = get_event_bus()

    for name in _LOG_EVENT_NAMES:
        is_async = name not in _SYNC_AUDIT_EVENTS
        bus.subscribe(name, _handle_event, async_handler=is_async)

    _subscribers_ready = True


def fetch_all_rows() -> list[tuple]:
    # все строки журнала по порядку sequence_number (SEC-4, COMP-4)
    """Fetch all rows."""
    require_audit_read_access()
    conn = get_default_database().create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT event_type, timestamp, entry_id, entry_data, signature
            FROM audit_log
            ORDER BY sequence_number ASC
            """
        )
        rows = []
        for event_type, timestamp, entry_id, entry_data, signature in cur.fetchall():
            if isinstance(entry_data, memoryview):
                entry_data = entry_data.tobytes()
            details_text = entry_data.decode("utf-8")
            rows.append((event_type, timestamp, entry_id, details_text, signature))
        return rows
    finally:
        conn.close()
