from __future__ import annotations

# Sprint 7 / PLAT-1..PLAT-3: платформо-специфичные функции безопасности
# Статусы и заглушки — docs/PLAT_PLATFORM_FEATURES.md

import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional, TypeVar

T = TypeVar("T")

_DOCS_PATH = "docs/PLAT_PLATFORM_FEATURES.md"


class FeatureImplementation(str, Enum):
    """Публичный класс FeatureImplementation."""
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    STUB = "stub"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class PlatformFeatureInfo:
    """Публичный класс PlatformFeatureInfo."""
    feature_id: str
    title: str
    implementation: FeatureImplementation
    available: bool
    notes: str
    documentation: str = _DOCS_PATH


def _system() -> str:
    return platform.system()


# ---------------------------------------------------------------------------
# PLAT-1: Windows
# ---------------------------------------------------------------------------

def windows_virtual_lock_available() -> bool:
    """PLAT-1: доступен ли Win32 API VirtualLock на этой системе."""
    if _system() != "Windows":
        return False
    try:
        import ctypes

        return hasattr(ctypes.windll.kernel32, "VirtualLock")
    except Exception:
        return False


def windows_credential_guard_enabled() -> bool:
    """PLAT-1: включён ли Device Guard / Credential Guard (реестр Windows)."""
    if _system() != "Windows":
        return False
    try:
        import winreg

        key_path = r"SYSTEM\CurrentControlSet\Control\DeviceGuard"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            enabled, _ = winreg.QueryValueEx(key, "EnableVirtualizationBasedSecurity")
            return int(enabled) == 1
    except OSError:
        return False
    except Exception:
        return False


def windows_credential_guard_available() -> bool:
    """PLAT-1: best-effort — VirtualLock API или Credential Guard в реестре."""
    return windows_virtual_lock_available() or windows_credential_guard_enabled()


def windows_virtual_lock(buf: bytearray) -> bool:
    """PLAT-1: Заблокировать страницу памяти через VirtualLock."""
    if _system() != "Windows" or not buf:
        return False
    try:
        import ctypes

        ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
        return bool(ctypes.windll.kernel32.VirtualLock(ptr, len(buf)))
    except Exception:
        return False


def windows_virtual_unlock(buf: bytearray) -> bool:
    """PLAT-1: Разблокировать страницу памяти через VirtualUnlock."""
    if _system() != "Windows" or not buf:
        return False
    try:
        import ctypes

        ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
        return bool(ctypes.windll.kernel32.VirtualUnlock(ptr, len(buf)))
    except Exception:
        return False


def windows_secure_desktop_available() -> bool:
    """PLAT-1: можно ли создать изолированный рабочий стол для ввода пароля."""
    if _system() != "Windows":
        return False
    try:
        import ctypes

        user32 = ctypes.windll.user32
        desktop_all = 0x01FF
        probe = user32.CreateDesktopW("CryptoSafeSecureDesktopProbe", None, None, 0, desktop_all, None)
        if probe:
            user32.CloseDesktop(probe)
            return True
        return False
    except Exception:
        return False


def _run_on_secure_desktop(action: Callable[[], T]) -> tuple[bool, Optional[T]]:
    """PLAT-1 (partial): выполнить callback на отдельном Win32 desktop."""
    if _system() != "Windows" or not windows_secure_desktop_available():
        return False, None
    try:
        import ctypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        desktop_all = 0x01FF
        desktop_name = "CryptoSafeSecureDesktop"

        h_desktop = user32.CreateDesktopW(desktop_name, None, None, 0, desktop_all, None)
        if not h_desktop:
            return False, None

        thread_id = kernel32.GetCurrentThreadId()
        h_old = user32.GetThreadDesktop(thread_id)
        if not user32.SetThreadDesktop(h_desktop):
            user32.CloseDesktop(h_desktop)
            return False, None

        try:
            return True, action()
        finally:
            user32.SetThreadDesktop(h_old)
            user32.CloseDesktop(h_desktop)
    except Exception:
        return False, None


def prompt_with_secure_desktop_fallback(dialog_exec: Callable[[], int]) -> tuple[bool, int]:
    """
    PLAT-1: попытка показать диалог на Secure Desktop; иначе обычный Qt-диалог.
    Возвращает (used_secure_desktop, dialog_code).
    """
    used, code = _run_on_secure_desktop(dialog_exec)
    if used and code is not None:
        return True, code
    return False, dialog_exec()


def windows_hello_available() -> bool:
    """PLAT-1 (bonus): Windows Hello — заглушка с проверкой WinBio API."""
    if _system() != "Windows":
        return False
    try:
        import ctypes

        winbio = getattr(ctypes.windll, "winbio", None)
        return winbio is not None and hasattr(winbio, "WinBioEnumBiometricUnits")
    except Exception:
        return False


# ---------------------------------------------------------------------------
# PLAT-2 / PLAT-3: cross-platform keychain (OS Keychain / keyring)
# ---------------------------------------------------------------------------

_KEYRING_SERVICE = "CryptoSafeManager"

try:
    import keyring as _keyring_lib

    _keyring_available = True
except Exception:
    _keyring_available = False


def store_secret_in_keychain(key_id: str, secret: str) -> bool:
    """PLAT-2/3: Сохранить секрет в ОС-хранилище (Keychain / keyring)."""
    if not _keyring_available:
        return False
    try:
        _keyring_lib.set_password(_KEYRING_SERVICE, key_id, secret)
        return True
    except Exception:
        return False


def load_secret_from_keychain(key_id: str) -> Optional[str]:
    """PLAT-2/3: Загрузить секрет из ОС-хранилища."""
    if not _keyring_available:
        return None
    try:
        return _keyring_lib.get_password(_KEYRING_SERVICE, key_id)
    except Exception:
        return None


def delete_secret_from_keychain(key_id: str) -> bool:
    """PLAT-2/3: Удалить секрет из ОС-хранилища."""
    if not _keyring_available:
        return False
    try:
        _keyring_lib.delete_password(_KEYRING_SERVICE, key_id)
        return True
    except Exception:
        return False


def macos_touch_id_available() -> bool:
    """PLAT-2 (bonus): Touch ID — заглушка (LocalAuthentication недоступен из pure Python)."""
    if _system() != "Darwin":
        return False
    # LocalAuthentication.framework требует pyobjc/нативный биндинг — не реализовано.
    return False


def macos_gatekeeper_notarization_status(app_path: Optional[str] = None) -> str:
    """
    PLAT-2: Gatekeeper / notarization — best-effort через `spctl`.
    Возвращает: accepted | rejected | unknown | stub.
    """
    if _system() != "Darwin":
        return "not_applicable"
    target = app_path or sys.executable
    try:
        proc = subprocess.run(
            ["spctl", "-a", "-vv", target],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            return "accepted"
        if "rejected" in (proc.stdout + proc.stderr).lower():
            return "rejected"
        return "unknown"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return "stub"


# ---------------------------------------------------------------------------
# PLAT-3: Linux — mlock / kernel keyring / systemd / LSM
# ---------------------------------------------------------------------------

def linux_mlock(buf: bytearray) -> bool:
    """PLAT-3: Заблокировать страницу памяти через mlock (Linux)."""
    if _system() != "Linux" or not buf:
        return False
    try:
        import ctypes

        libc = ctypes.CDLL(None)
        ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
        return int(libc.mlock(ptr, len(buf))) == 0
    except Exception:
        return False


def linux_munlock(buf: bytearray) -> bool:
    """PLAT-3: Разблокировать страницу памяти через munlock (Linux)."""
    if _system() != "Linux" or not buf:
        return False
    try:
        import ctypes

        libc = ctypes.CDLL(None)
        ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
        return int(libc.munlock(ptr, len(buf))) == 0
    except Exception:
        return False


def linux_systemd_available() -> bool:
    """PLAT-3: systemd как init / доступен systemctl."""
    if _system() != "Linux":
        return False
    try:
        with open("/proc/1/comm", encoding="utf-8") as fh:
            init_name = fh.read().strip().lower()
        if init_name == "systemd":
            return True
    except OSError:
        pass
    try:
        proc = subprocess.run(
            ["systemctl", "--version"],
            capture_output=True,
            timeout=3,
            check=False,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def linux_systemd_user_service_supported() -> bool:
    """PLAT-3 (stub): интеграция user-unit — только проверка окружения."""
    if not linux_systemd_available():
        return False
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    return bool(runtime_dir and os.path.isdir(runtime_dir))


def linux_selinux_enabled() -> bool:
    """PLAT-3: SELinux включён (best-effort)."""
    if _system() != "Linux":
        return False
    enforce_path = "/sys/fs/selinux/enforce"
    if os.path.isfile(enforce_path):
        try:
            with open(enforce_path, encoding="utf-8") as fh:
                return fh.read().strip() == "1"
        except OSError:
            return False
    try:
        proc = subprocess.run(["getenforce"], capture_output=True, text=True, timeout=3, check=False)
        return proc.stdout.strip().lower() in {"enforcing", "permissive"}
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def linux_apparmor_enabled() -> bool:
    """PLAT-3: AppArmor активен (best-effort)."""
    if _system() != "Linux":
        return False
    if os.path.isdir("/sys/kernel/security/apparmor"):
        return True
    try:
        proc = subprocess.run(["aa-status", "--enabled"], capture_output=True, timeout=3, check=False)
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def linux_kernel_keyring_available() -> bool:
    """PLAT-3: keyring backend через Python keyring (делегирует в ОС)."""
    if _system() != "Linux":
        return False
    return keychain_available()


# ---------------------------------------------------------------------------
# Unified: lock_memory — вызывает нужную платформенную функцию
# ---------------------------------------------------------------------------

def lock_memory(buf: bytearray) -> bool:
    """Заблокировать буфер в RAM (не пагинировать). Best-effort."""
    sys_name = _system()
    if sys_name == "Windows":
        return windows_virtual_lock(buf)
    if sys_name == "Linux":
        return linux_mlock(buf)
    if sys_name == "Darwin":
        try:
            import ctypes

            libc = ctypes.CDLL(None)
            ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
            return int(libc.mlock(ptr, len(buf))) == 0
        except Exception:
            return False
    return False


def unlock_memory(buf: bytearray) -> bool:
    """Разблокировать буфер из RAM."""
    sys_name = _system()
    if sys_name == "Windows":
        return windows_virtual_unlock(buf)
    if sys_name in ("Linux", "Darwin"):
        try:
            import ctypes

            libc = ctypes.CDLL(None)
            ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
            return int(libc.munlock(ptr, len(buf))) == 0
        except Exception:
            return False
    return False


def keychain_available() -> bool:
    """Доступно ли ОС-хранилище ключей на текущей платформе."""
    return _keyring_available


def describe_platform_features() -> list[PlatformFeatureInfo]:
    """Сводка PLAT-1..3: что реализовано, что заглушка, что доступно на текущей ОС."""
    sys_name = _system()
    features: list[PlatformFeatureInfo] = []

    if sys_name == "Windows":
        features.extend(
            [
                PlatformFeatureInfo(
                    "PLAT-1-virtual-lock",
                    "Windows VirtualLock",
                    FeatureImplementation.IMPLEMENTED,
                    windows_virtual_lock_available(),
                    "Блокировка страниц RAM через kernel32.VirtualLock.",
                ),
                PlatformFeatureInfo(
                    "PLAT-1-credential-guard",
                    "Windows Credential Guard",
                    FeatureImplementation.PARTIAL,
                    windows_credential_guard_enabled(),
                    "Проверка реестра DeviceGuard; полный VBS API не используется.",
                ),
                PlatformFeatureInfo(
                    "PLAT-1-secure-desktop",
                    "Windows Secure Desktop",
                    FeatureImplementation.PARTIAL,
                    windows_secure_desktop_available(),
                    "CreateDesktop + SetThreadDesktop перед LoginDialog; fallback на обычный Qt.",
                ),
                PlatformFeatureInfo(
                    "PLAT-1-windows-hello",
                    "Windows Hello",
                    FeatureImplementation.STUB,
                    windows_hello_available(),
                    "Обнаружение winbio.dll; биометрический вход не подключён.",
                ),
            ]
        )
    elif sys_name == "Darwin":
        features.extend(
            [
                PlatformFeatureInfo(
                    "PLAT-2-keychain",
                    "macOS Keychain Services",
                    FeatureImplementation.IMPLEMENTED if keychain_available() else FeatureImplementation.PARTIAL,
                    keychain_available(),
                    "Через пакет keyring → Keychain Services.",
                ),
                PlatformFeatureInfo(
                    "PLAT-2-touch-id",
                    "macOS Touch ID",
                    FeatureImplementation.STUB,
                    macos_touch_id_available(),
                    "Требует LocalAuthentication / pyobjc — не реализовано.",
                ),
                PlatformFeatureInfo(
                    "PLAT-2-gatekeeper",
                    "macOS Gatekeeper / Notarization",
                    FeatureImplementation.PARTIAL,
                    macos_gatekeeper_notarization_status() == "accepted",
                    "Проверка spctl -a; подпись/нотаризация сборки — ответственность CI.",
                ),
            ]
        )
    elif sys_name == "Linux":
        features.extend(
            [
                PlatformFeatureInfo(
                    "PLAT-3-mlock",
                    "Linux mlock",
                    FeatureImplementation.IMPLEMENTED,
                    True,
                    "libc.mlock / munlock для буферов.",
                ),
                PlatformFeatureInfo(
                    "PLAT-3-kernel-keyring",
                    "Linux kernel keyring",
                    FeatureImplementation.PARTIAL,
                    linux_kernel_keyring_available(),
                    "Через keyring backend; прямой keyctl не используется.",
                ),
                PlatformFeatureInfo(
                    "PLAT-3-systemd",
                    "systemd integration",
                    FeatureImplementation.STUB,
                    linux_systemd_user_service_supported(),
                    "Проверка init/systemctl; user-unit сервис не создаётся.",
                ),
                PlatformFeatureInfo(
                    "PLAT-3-selinux",
                    "SELinux policies",
                    FeatureImplementation.STUB,
                    linux_selinux_enabled(),
                    "Только детекция; политики не поставляются.",
                ),
                PlatformFeatureInfo(
                    "PLAT-3-apparmor",
                    "AppArmor policies",
                    FeatureImplementation.STUB,
                    linux_apparmor_enabled(),
                    "Только детекция; профили не поставляются.",
                ),
            ]
        )
    else:
        features.append(
            PlatformFeatureInfo(
                "PLAT-unknown",
                "Platform-specific security",
                FeatureImplementation.NOT_APPLICABLE,
                False,
                f"ОС {sys_name!r} не входит в PLAT-1..3.",
            )
        )

    return features
