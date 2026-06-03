from __future__ import annotations

# Sprint 6: ошибки импорта (ERR-1..ERR-4)

from dataclasses import dataclass, field
from typing import Any, Optional

# варианты восстановления (ERR-1)
RECOVERY_RETRY = "retry"
RECOVERY_MANUAL_FORMAT = "manual_format"
RECOVERY_RESUME_CHECKPOINT = "resume_checkpoint"
RECOVERY_CHECK_PASSWORD = "check_password"
RECOVERY_DRY_RUN = "dry_run"

# форматы для ручного выбора (ERR-3)
MANUAL_IMPORT_FORMATS = [
    "encrypted_json",
    "csv",
    "csv_semicolon",
    "bitwarden_json",
    "lastpass_csv",
    "lastpass_csv_encrypted",
    "share_encrypted",
]


@dataclass
class ImportErrorReport:
    # ERR-1: подробный отчёт + что можно сделать дальше
    """Публичный класс ImportErrorReport."""
    success: bool = False
    error_code: str = ""
    message: str = ""
    recovery_options: list[str] = field(default_factory=list)
    checkpoint_path: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        # ERR-1: словарь для GUI и логов
        """To dict."""
        return {
            "success": self.success,
            "error_code": self.error_code,
            "message": self.message,
            "recovery_options": list(self.recovery_options),
            "checkpoint_path": self.checkpoint_path,
            "details": dict(self.details),
        }


class FormatDetectionError(Exception):
    # ERR-3: автоопределение не удалось — нужен ручной формат
    """Публичный класс FormatDetectionError."""
    def __init__(self, message: str, *, candidates: Optional[list[str]] = None) -> None:
        super().__init__(message)
        self.candidates = list(candidates or MANUAL_IMPORT_FORMATS)


class EncryptionDecryptError(Exception):
    # ERR-4: ошибка расшифровки (частичные данные уже обнулены)
    """Публичный класс EncryptionDecryptError."""
    def __init__(self, message: str, *, cause: str = "") -> None:
        super().__init__(message)
        self.cause = cause


class CorruptedImportError(Exception):
    # ERR-1: повреждённый файл
    """Публичный класс CorruptedImportError."""
    def __init__(self, message: str, *, stage: str = "") -> None:
        super().__init__(message)
        self.stage = stage


class PartialImportError(Exception):
    # ERR-2: импорт прерван, есть checkpoint
    """Публичный класс PartialImportError."""
    def __init__(self, message: str, *, checkpoint_path: str = "", applied: int = 0) -> None:
        super().__init__(message)
        self.checkpoint_path = checkpoint_path
        self.applied = applied


def build_error_report(
    exc: Exception,
    *,
    checkpoint_path: str = "",
    extra: Optional[dict[str, Any]] = None,
) -> ImportErrorReport:
    # ERR-1: собрать отчёт из исключения
    """Build error report."""
    details = dict(extra or {})
    if isinstance(exc, FormatDetectionError):
        return ImportErrorReport(
            success=False,
            error_code="format_detection_failed",
            message=str(exc),
            recovery_options=[RECOVERY_MANUAL_FORMAT, RECOVERY_RETRY, RECOVERY_DRY_RUN],
            details={"candidates": getattr(exc, "candidates", MANUAL_IMPORT_FORMATS)},
        )
    if isinstance(exc, EncryptionDecryptError):
        return ImportErrorReport(
            success=False,
            error_code="encryption_failed",
            message=str(exc),
            recovery_options=[RECOVERY_CHECK_PASSWORD, RECOVERY_RETRY],
            details={"cause": getattr(exc, "cause", "")},
        )
    if isinstance(exc, CorruptedImportError):
        return ImportErrorReport(
            success=False,
            error_code="corrupted_file",
            message=str(exc),
            recovery_options=[RECOVERY_RETRY, RECOVERY_MANUAL_FORMAT],
            details={"stage": getattr(exc, "stage", "")},
        )
    if isinstance(exc, PartialImportError):
        return ImportErrorReport(
            success=False,
            error_code="partial_import",
            message=str(exc),
            recovery_options=[RECOVERY_RESUME_CHECKPOINT, RECOVERY_RETRY],
            checkpoint_path=checkpoint_path or getattr(exc, "checkpoint_path", ""),
            details={"applied": getattr(exc, "applied", 0)},
        )
    return ImportErrorReport(
        success=False,
        error_code="import_failed",
        message=str(exc),
        recovery_options=[RECOVERY_RETRY, RECOVERY_DRY_RUN],
        checkpoint_path=checkpoint_path,
        details=details,
    )
