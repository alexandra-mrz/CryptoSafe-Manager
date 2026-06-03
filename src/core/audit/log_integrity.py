from __future__ import annotations

# VER-1..VER-4: проверка целостности журнала аудита

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.core.audit.audit_logger import fetch_all_rows
from src.core.audit.log_verifier import verify_chain
from src.database.db import get_default_database

STATUS_OK = "ok"
STATUS_FAIL = "tampered"
STATUS_UNKNOWN = "unknown"

STARTUP_SAMPLE_LIMIT = 5000
PERIODIC_CHECK_COUNT = 1000
DEFAULT_INTERVAL_HOURS = 24

SETTING_INTERVAL_HOURS = "audit_verify_interval_hours"
SETTING_LOCK_ON_TAMPER = "audit_lock_on_tamper"

_integrity_status = STATUS_UNKNOWN
_last_report = ""


def _utc_now_iso() -> str:
    # время для audit_security_log
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_integrity_status() -> str:
    # ok / tampered / unknown — для статус-бара GUI
    """Get integrity status."""
    return _integrity_status


def get_last_report() -> str:
    # текст последнего отчёта проверки
    """Get last report."""
    return _last_report


def _set_result(ok: bool, report: str) -> dict[str, Any]:
    # сохранить результат проверки в памяти
    global _integrity_status, _last_report
    _integrity_status = STATUS_OK if ok else STATUS_FAIL
    _last_report = report
    return {"ok": ok, "report": report}


def _read_setting(key: str, default: str) -> str:
    # настройка из таблицы settings
    db = get_default_database()
    conn = db.create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT setting_value FROM settings WHERE setting_key = ?",
            (key,),
        )
        row = cur.fetchone()
        if row is None or row[0] is None:
            return default
        return str(row[0])
    finally:
        conn.close()


def get_verify_interval_hours() -> int:
    # VER-2: интервал периодической проверки (часы)
    """Get verify interval hours."""
    raw = _read_setting(SETTING_INTERVAL_HOURS, str(DEFAULT_INTERVAL_HOURS))
    try:
        value = int(raw)
    except ValueError:
        value = DEFAULT_INTERVAL_HOURS
    if value < 1:
        value = 1
    return value


def write_security_log(message: str, errors: list[str]) -> None:
    # VER-4: отдельный защищённый журнал (не audit_log)
    """Write security log."""
    db = get_default_database()
    conn = db.create_connection()
    try:
        details = json.dumps({"message": message, "errors": errors}, ensure_ascii=False)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_security_log (timestamp, event_type, details)
            VALUES (?, ?, ?)
            """,
            (_utc_now_iso(), "TAMPERING_DETECTED", details),
        )
        conn.commit()
    finally:
        conn.close()


def build_report(mode: str, ok: bool, checked: int, total: int, sampled: bool, errors: list[str]) -> str:
    # текстовый отчёт для GUI и экспорта (VER-3)
    """Build report."""
    lines = [
        f"Режим: {mode}",
        f"Проверено записей: {checked} из {total}",
        f"Выборка: {'да' if sampled else 'нет'}",
        f"Результат: {'OK' if ok else 'ОБНАРУЖЕНО ВМЕШАТЕЛЬСТВО'}",
        "",
    ]
    if errors:
        lines.append("Ошибки:")
        for item in errors:
            lines.append(f"- {item}")
    else:
        lines.append("Ошибок не найдено.")
    return "\n".join(lines)


def _run_check(rows: list[tuple], mode: str, total: int, sampled: bool) -> dict[str, Any]:
    # общая логика проверки: цепочка, отчёт, security_log при ошибке
    ok, messages = verify_chain(rows)
    errors = [] if ok else messages
    report = build_report(mode, ok, len(rows), total, sampled, errors)
    result = _set_result(ok, report)
    result["errors"] = errors
    result["checked"] = len(rows)
    result["total"] = total
    result["sampled"] = sampled
    result["mode"] = mode
    if not ok:
        write_security_log("tampering detected", errors)
    return result


def verify_on_startup() -> dict[str, Any]:
    # VER-1: при старте все записи или выборка
    """Verify on startup."""
    rows = fetch_all_rows()
    total = len(rows)
    sampled = False
    if total > STARTUP_SAMPLE_LIMIT:
        rows = rows[-STARTUP_SAMPLE_LIMIT:]
        sampled = True
    return _run_check(rows, "startup", total, sampled)


def verify_periodic() -> dict[str, Any]:
    # VER-2: последние 1000 записей
    """Verify periodic."""
    rows = fetch_all_rows()
    total = len(rows)
    if total > PERIODIC_CHECK_COUNT:
        rows = rows[-PERIODIC_CHECK_COUNT:]
    return _run_check(rows, "periodic", total, False)


def verify_manual_full() -> dict[str, Any]:
    # VER-3: полная проверка
    """Verify manual full."""
    rows = fetch_all_rows()
    total = len(rows)
    return _run_check(rows, "manual", total, False)


def export_report_to_file(file_path: str | Path, report: str | None = None) -> None:
    # VER-3: экспорт отчёта
    """Export report to file."""
    text = report if report is not None else _last_report
    Path(file_path).write_text(text, encoding="utf-8")


def should_lock_on_tamper() -> bool:
    # блокировать приложение при обнаружении вмешательства
    """Should lock on tamper."""
    return _read_setting(SETTING_LOCK_ON_TAMPER, "0") == "1"


def safe_verify_manual_full() -> dict[str, Any]:
    # TEST-4: проверка без падения при ошибке БД
    """Safe verify manual full."""
    try:
        return verify_manual_full()
    except Exception as exc:
        report = f"ошибка проверки: {exc}"
        return _set_result(False, report)


def recover_audit_log_clear() -> None:
    # TEST-4: восстановление — очистка повреждённого журнала
    """Recover audit log clear."""
    from src.core.audit.audit_logger import reload_chain_state
    from src.core.audit.audit_security import log_protection_event, set_audit_maintenance

    log_protection_event("recovery_clear", {"reason": "admin_recovery"})
    set_audit_maintenance(True)
    db = get_default_database()
    conn = db.create_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM audit_log")
        conn.commit()
    finally:
        set_audit_maintenance(False)
        conn.close()
    reload_chain_state()


def check_audit_table_exists() -> bool:
    # TEST-4/TEST-5: таблица на месте
    """Check audit table exists."""
    db = get_default_database()
    conn = db.create_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
        )
        return cur.fetchone() is not None
    finally:
        conn.close()
