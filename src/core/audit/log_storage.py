from __future__ import annotations

# DB-4: ротация и архив записей аудита

from datetime import datetime, timedelta, timezone

from src.database.db import get_default_database

DEFAULT_MAX_ENTRIES = 10000
DEFAULT_MAX_AGE_DAYS = 365

SETTING_MAX_ENTRIES = "audit_max_entries"
SETTING_MAX_AGE_DAYS = "audit_max_age_days"


def _utc_now_iso() -> str:
    # время архивации
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_setting(conn, key: str, default: str) -> str:
    # значение из settings
    cur = conn.cursor()
    cur.execute(
        "SELECT setting_value FROM settings WHERE setting_key = ?",
        (key,),
    )
    row = cur.fetchone()
    if row is None or row[0] is None:
        return default
    return str(row[0])


def get_max_entries(conn) -> int:
    # COMP-3 / DB-4: лимит записей в активном журнале
    """Get max entries."""
    raw = _read_setting(conn, SETTING_MAX_ENTRIES, str(DEFAULT_MAX_ENTRIES))
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_MAX_ENTRIES


def get_max_age_days(conn) -> int:
    # COMP-3 / DB-4: срок хранения в днях
    """Get max age days."""
    raw = _read_setting(conn, SETTING_MAX_AGE_DAYS, str(DEFAULT_MAX_AGE_DAYS))
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_MAX_AGE_DAYS


def get_retention_policy() -> dict:
    # COMP-3: политика хранения из settings
    """Get retention policy."""
    db = get_default_database()
    conn = db.create_connection()
    try:
        return {
            "max_entries": get_max_entries(conn),
            "max_age_days": get_max_age_days(conn),
        }
    finally:
        conn.close()


def set_rotation_policy(max_entries: int, max_age_days: int) -> None:
    # COMP-3: сохранить политику хранения в settings
    """Set rotation policy."""
    db = get_default_database()
    conn = db.create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO settings (setting_key, setting_value, encrypted)
            VALUES (?, ?, 0)
            ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value
            """,
            (SETTING_MAX_ENTRIES, str(max_entries)),
        )
        cur.execute(
            """
            INSERT INTO settings (setting_key, setting_value, encrypted)
            VALUES (?, ?, 0)
            ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value
            """,
            (SETTING_MAX_AGE_DAYS, str(max_age_days)),
        )
        conn.commit()
    finally:
        conn.close()


def _archive_rows(cur, rows) -> None:
    # перенести строки в audit_log_archive
    archived_at = _utc_now_iso()
    for row in rows:
        data = tuple(row) + (archived_at,)
        cur.execute(
            """
            INSERT OR REPLACE INTO audit_log_archive
            (sequence_number, timestamp, event_type, entry_id, previous_hash, entry_data, signature, archived_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            data,
        )


def apply_log_rotation() -> None:
    # DB-4: перенос старых записей в архив
    """Apply log rotation."""
    from src.core.audit.audit_security import set_audit_maintenance

    db = get_default_database()
    conn = db.create_connection()
    set_audit_maintenance(True)
    try:
        cur = conn.cursor()
        max_entries = get_max_entries(conn)
        max_age_days = get_max_age_days(conn)

        cur.execute("SELECT COUNT(*) FROM audit_log")
        total = int(cur.fetchone()[0])
        if total > max_entries:
            extra = total - max_entries
            cur.execute(
                """
                SELECT sequence_number, timestamp, event_type, entry_id, previous_hash, entry_data, signature
                FROM audit_log
                ORDER BY sequence_number ASC
                LIMIT ?
                """,
                (extra,),
            )
            old_rows = cur.fetchall()
            _archive_rows(cur, old_rows)
            for row in old_rows:
                cur.execute(
                    "DELETE FROM audit_log WHERE sequence_number = ?",
                    (row[0],),
                )

        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        cutoff_text = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        cur.execute(
            """
            SELECT sequence_number, timestamp, event_type, entry_id, previous_hash, entry_data, signature
            FROM audit_log
            WHERE timestamp < ?
            """,
            (cutoff_text,),
        )
        aged_rows = cur.fetchall()
        if aged_rows:
            _archive_rows(cur, aged_rows)
            for row in aged_rows:
                cur.execute(
                    "DELETE FROM audit_log WHERE sequence_number = ?",
                    (row[0],),
                )

        conn.commit()
    finally:
        set_audit_maintenance(False)
        conn.close()
