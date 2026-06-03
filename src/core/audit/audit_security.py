from __future__ import annotations

# SEC-1..SEC-5: требования безопасности аудита

import json
from datetime import datetime, timezone

from src.core.crypto.authentication import is_session_unlocked
from src.database.db import get_default_database

# SEC-2: разрешить DELETE только при обслуживании (ротация/восстановление)
_audit_maintenance = False


def _utc_now_iso() -> str:
    # время UTC для security_log
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def set_audit_maintenance(allow: bool) -> None:
    # SEC-2: разрешить DELETE при ротации или восстановлении
    """Set audit maintenance."""
    global _audit_maintenance
    _audit_maintenance = allow
    # флаг в БД для триггеров SEC-2
    db = get_default_database()
    conn = db.create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_maintenance_flag (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        cur.execute(
            "INSERT OR IGNORE INTO audit_maintenance_flag (id, enabled) VALUES (1, 0)"
        )
        cur.execute(
            "UPDATE audit_maintenance_flag SET enabled = ? WHERE id = 1",
            (1 if allow else 0,),
        )
        conn.commit()
    finally:
        conn.close()


def is_audit_maintenance() -> bool:
    # включён ли режим обслуживания журнала
    """Is audit maintenance."""
    return _audit_maintenance


def require_audit_read_access() -> None:
    # SEC-4: чтение журнала только после входа
    """Require audit read access."""
    if not is_session_unlocked():
        raise PermissionError("требуется авторизация для доступа к журналу аудита")


def log_protection_event(action: str, details: dict) -> None:
    # SEC-5: попытки отключить/изменить лог пишем в audit_security_log
    """Log protection event."""
    db = get_default_database()
    conn = db.create_connection()
    try:
        payload = json.dumps({"action": action, "details": details}, ensure_ascii=False)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_security_log (timestamp, event_type, details)
            VALUES (?, ?, ?)
            """,
            (_utc_now_iso(), "AUDIT_LOG_PROTECTION", payload),
        )
        conn.commit()
    finally:
        conn.close()


def check_append_only_sql(sql: str) -> bool:
    # SEC-2: запрет UPDATE/DELETE для audit_log
    """Check append only sql."""
    text = sql.strip().upper()
    if "AUDIT_LOG" not in text:
        return True
    if text.startswith("INSERT"):
        return True
    if text.startswith("UPDATE") or text.startswith("DELETE"):
        if _audit_maintenance:
            return True
        log_protection_event(
            "blocked_modify",
            {"sql": sql[:200]},
        )
        return False
    return True


def ensure_signed(signature: str) -> None:
    # SEC-1: без подписи запись не допускается
    """Ensure signed."""
    if signature:
        return
    log_protection_event("unsigned_entry_blocked", {})
    raise ValueError("запись без подписи запрещена")


def install_audit_security_triggers(conn) -> None:
    # SEC-2: триггеры append-only (DELETE только при maintenance)
    """Install audit security triggers."""
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_maintenance_flag (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    cur.execute(
        "INSERT OR IGNORE INTO audit_maintenance_flag (id, enabled) VALUES (1, 0)"
    )
    cur.execute(
        """
        CREATE TRIGGER IF NOT EXISTS audit_log_block_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'SEC-2: audit_log append-only');
        END;
        """
    )
    cur.execute(
        """
        CREATE TRIGGER IF NOT EXISTS audit_log_block_delete
        BEFORE DELETE ON audit_log
        WHEN COALESCE((SELECT enabled FROM audit_maintenance_flag WHERE id = 1), 0) = 0
        BEGIN
            SELECT RAISE(ABORT, 'SEC-2: audit_log append-only');
        END;
        """
    )
    conn.commit()
