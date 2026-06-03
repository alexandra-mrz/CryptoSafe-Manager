# PLAT — платформенная безопасность (Sprint 7, §13)

ТЗ: `sprints/sprint7.md`, раздел **13. Platform-Specific Considerations**.

Модуль реализации: `src/core/security/platform_security.py`  
API статуса: `describe_platform_features()`

---

## Сводка по платформам

| ID | Требование ТЗ | Статус | Функции |
|----|---------------|--------|---------|
| **PLAT-1** | Credential Guard API | **Partial** | `windows_credential_guard_enabled()` — реестр DeviceGuard; полный VBS API не вызывается |
| **PLAT-1** | VirtualLock / RAM | **Implemented** | `windows_virtual_lock`, `windows_virtual_unlock`, `lock_memory` |
| **PLAT-1** | Secure Desktop для пароля | **Partial** | `windows_secure_desktop_available`, `prompt_with_secure_desktop_fallback` → `LoginDialog.exec` |
| **PLAT-1** | Windows Hello | **Stub** | `windows_hello_available()` — только проверка `winbio.dll` |
| **PLAT-2** | Keychain Services | **Implemented** | `store/load/delete_secret_in_keychain` через `keyring` |
| **PLAT-2** | Touch ID | **Stub** | `macos_touch_id_available()` — всегда `False`, нужен LocalAuthentication |
| **PLAT-2** | Gatekeeper / notarization | **Partial** | `macos_gatekeeper_notarization_status()` — `spctl -a` |
| **PLAT-3** | kernel keyring | **Partial** | тот же `keyring`; прямой `keyctl` не используется |
| **PLAT-3** | mlock | **Implemented** | `linux_mlock`, `linux_munlock` |
| **PLAT-3** | systemd | **Stub** | `linux_systemd_available`, `linux_systemd_user_service_supported` — детекция без unit-файла |
| **PLAT-3** | SELinux / AppArmor | **Stub** | `linux_selinux_enabled`, `linux_apparmor_enabled` — детекция без профилей |

**Implemented** — используется в runtime.  
**Partial** — best-effort или делегирование через стороннюю библиотеку.  
**Stub** — явная заглушка: API есть, полная интеграция не сделана (см. `notes` в `describe_platform_features()`).

---

## Secure Desktop (Windows)

**Цель ТЗ:** ввод мастер-пароля на изолированном рабочем столе, чтобы снизить риск keylogger overlay на обычном desktop.

**Реализация:**

1. `windows_secure_desktop_available()` — пробное создание desktop `CryptoSafeSecureDesktopProbe`.
2. `prompt_with_secure_desktop_fallback(dialog_exec)` — `CreateDesktop` + `SetThreadDesktop` на текущем потоке, затем вызов Qt `QDialog.exec()`.
3. При ошибке или на не-Windows — обычный `LoginDialog` без изоляции.

**Ограничения (Partial):**

- Qt уже инициализирован в процессе; полная изоляция как у `winlogon` недостижима без отдельного процесса.
- `SetThreadDesktop` может не сработать, если поток уже привязан к desktop с окнами — тогда срабатывает fallback.
- Для production-grade решения нужен отдельный helper-процесс или CredUI / Windows Hello.

**Интеграция:** `src/gui/widgets/login_dialog.py` → `LoginDialog.exec()`.

---

## Credential Guard vs VirtualLock

| API | Назначение |
|-----|------------|
| `windows_virtual_lock_available()` | Есть ли `kernel32.VirtualLock` |
| `windows_credential_guard_enabled()` | VBS / Device Guard в реестре |
| `windows_credential_guard_available()` | Объединение для обратной совместимости |

VirtualLock **не равен** Credential Guard; в документации и статусах они разделены.

---

## Заглушки — что нужно для полной реализации

| Заглушка | Что добавить позже |
|----------|-------------------|
| Windows Hello | WebAuthn / WinBio API, UI в `LoginDialog` |
| Touch ID | `pyobjc` + LocalAuthentication |
| Gatekeeper | Подпись и notarization в CI (`codesign`, `notarytool`) |
| systemd | Unit `cryptosafe-manager.service` + `systemctl --user enable` |
| SELinux | Файл политики `.te` / пакет `selinux-policy` |
| AppArmor | Профиль `usr.bin.cryptosafe-manager` |
| kernel keyring | Прямой `keyctl` / `keyutils` вместо только `keyring` |

---

## Проверка

```bash
py -3 -m unittest tests.test_sprint7_platform -v
```

Программно:

```python
from src.core.security.platform_security import describe_platform_features

for item in describe_platform_features():
    print(item.feature_id, item.implementation.value, item.available, item.notes)
```

---

*Sprint 7 — блок PLAT.*
