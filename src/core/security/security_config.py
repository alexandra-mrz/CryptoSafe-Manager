from __future__ import annotations

# Sprint 7 / ARC-2, CFG-1..CFG-3: профили и валидация настроек

from dataclasses import dataclass, field
from typing import Any

PROFILE_STANDARD = "standard"
PROFILE_ENHANCED = "enhanced"
PROFILE_PARANOID = "paranoid"

SETTING_SECURITY_PROFILE = "security_profile"
SETTING_ACTIVITY_SENSITIVITY = "activity_sensitivity"
SETTING_DEVICE_TYPE = "device_type"
SETTING_MINIMIZE_TO_TRAY = "minimize_to_tray"
SETTING_START_MINIMIZED = "start_minimized"
SETTING_PANIC_STEALTH = "panic_stealth_mode"
SETTING_PANIC_QUIT = "panic_quit_app"
SETTING_MEMORY_WIPE_PASSES = "memory_wipe_passes"


@dataclass
class SecuritySettings:
    """Публичный класс SecuritySettings."""
    profile: str = PROFILE_STANDARD
    auto_lock_minutes: int = 5
    activity_sensitivity: str = "medium"  # low | medium | high
    device_type: str = "desktop"  # desktop | laptop
    clipboard_timeout_seconds: int = 30
    clipboard_security_level: str = "basic"
    minimize_to_tray: bool = True
    start_minimized: bool = False
    panic_stealth_mode: bool = False
    panic_quit_app: bool = False
    memory_wipe_passes: int = 1
    extra: dict[str, Any] = field(default_factory=dict)

    def to_activity_config(self) -> dict[str, Any]:
        """To activity config."""
        return {
            "lock_timeout_minutes": self.auto_lock_minutes,
            "activity_sensitivity": self.activity_sensitivity,
            "device_type": self.device_type,
            "check_interval": 1.0,
        }

    def to_panic_config(self) -> dict[str, Any]:
        """To panic config."""
        return {
            "stealth_mode": self.panic_stealth_mode,
            "stealth_actions": {"show_fake_error": self.panic_stealth_mode},
            "quit_app": self.panic_quit_app,
        }


_PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    PROFILE_STANDARD: {
        "auto_lock_minutes": 5,
        "clipboard_timeout_seconds": 30,
        "clipboard_security_level": "basic",
        "activity_sensitivity": "medium",
        "memory_wipe_passes": 1,
        "panic_stealth_mode": False,
    },
    PROFILE_ENHANCED: {
        "auto_lock_minutes": 3,
        "clipboard_timeout_seconds": 15,
        "clipboard_security_level": "advanced",
        "activity_sensitivity": "high",
        "memory_wipe_passes": 2,
        "panic_stealth_mode": False,
    },
    PROFILE_PARANOID: {
        "auto_lock_minutes": 1,
        "clipboard_timeout_seconds": 5,
        "clipboard_security_level": "paranoid",
        "activity_sensitivity": "high",
        "memory_wipe_passes": 3,
        "panic_stealth_mode": True,
    },
}


def apply_profile(profile: str, current: SecuritySettings) -> SecuritySettings:
    # CFG-2: переключение профиля
    """Apply profile."""
    key = profile if profile in _PROFILE_DEFAULTS else PROFILE_STANDARD
    data = _PROFILE_DEFAULTS[key]
    return SecuritySettings(
        profile=key,
        auto_lock_minutes=int(data["auto_lock_minutes"]),
        activity_sensitivity=str(data["activity_sensitivity"]),
        device_type=current.device_type,
        clipboard_timeout_seconds=int(data["clipboard_timeout_seconds"]),
        clipboard_security_level=str(data["clipboard_security_level"]),
        minimize_to_tray=current.minimize_to_tray,
        start_minimized=current.start_minimized,
        panic_stealth_mode=bool(data["panic_stealth_mode"]),
        panic_quit_app=current.panic_quit_app,
        memory_wipe_passes=int(data["memory_wipe_passes"]),
    )


def validate_settings(settings: SecuritySettings) -> tuple[bool, list[str]]:
    # CFG-3: проверка перед применением
    """Validate settings."""
    errors: list[str] = []
    if settings.auto_lock_minutes < 1 or settings.auto_lock_minutes > 480:
        errors.append("auto_lock_minutes: 1..480")
    if settings.clipboard_timeout_seconds < 0 or settings.clipboard_timeout_seconds > 300:
        errors.append("clipboard_timeout_seconds: 0..300")
    if settings.activity_sensitivity not in ("low", "medium", "high"):
        errors.append("activity_sensitivity: low/medium/high")
    if settings.device_type not in ("desktop", "laptop"):
        errors.append("device_type: desktop/laptop")
    if settings.memory_wipe_passes < 1 or settings.memory_wipe_passes > 5:
        errors.append("memory_wipe_passes: 1..5")
    if settings.clipboard_timeout_seconds == 0 and settings.clipboard_security_level == "paranoid":
        errors.append("paranoid + clipboard never clear — небезопасно")
    return (len(errors) == 0, errors)


def profile_changes_text(old: SecuritySettings, new: SecuritySettings) -> str:
    # CFG-2: объяснить изменения
    """Profile changes text."""
    lines = [f"Профиль: {old.profile} → {new.profile}"]
    if old.auto_lock_minutes != new.auto_lock_minutes:
        lines.append(f"Автоблокировка: {old.auto_lock_minutes} → {new.auto_lock_minutes} мин")
    if old.clipboard_timeout_seconds != new.clipboard_timeout_seconds:
        lines.append(f"Буфер: {old.clipboard_timeout_seconds} → {new.clipboard_timeout_seconds} с")
    if old.clipboard_security_level != new.clipboard_security_level:
        lines.append(f"Уровень буфера: {old.clipboard_security_level} → {new.clipboard_security_level}")
    if old.activity_sensitivity != new.activity_sensitivity:
        lines.append(f"Чувствительность: {old.activity_sensitivity} → {new.activity_sensitivity}")
    return "\n".join(lines)


def non_default_warnings(settings: SecuritySettings) -> list[str]:
    # CFG-3: предупреждения о нестандартных значениях
    """Non default warnings."""
    standard = apply_profile(PROFILE_STANDARD, SecuritySettings())
    warns: list[str] = []
    if settings.profile != PROFILE_STANDARD:
        warns.append(f"Профиль безопасности: {settings.profile}")
    if settings.clipboard_timeout_seconds == 0:
        warns.append("Буфер не очищается автоматически (таймаут 0).")
    if settings.auto_lock_minutes != standard.auto_lock_minutes:
        warns.append("Автоблокировка отличается от Standard.")
    if settings.clipboard_security_level != standard.clipboard_security_level:
        warns.append("Уровень безопасности буфера отличается от Standard.")
    if settings.panic_quit_app:
        warns.append("После паники приложение закрывается.")
    return warns
