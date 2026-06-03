# Sprint 7 — журнал реализации (CryptoSafe Manager)

Документ заполняется по ходу работы: **что делаем**, **какие решения принимаем**, **где лежит код**, **насколько закрыто ТЗ**.  
ТЗ: `sprints/sprint7.md`.

**Цель спринта:** усиление безопасности (side-channel, память), auto-lock, system tray, panic mode, профили настроек — без поломки Sprint 3–6.

---

## Сводка соответствия ТЗ

| Категория | Must | Should | Optional | Комментарий |
|-----------|------|--------|----------|-------------|
| Блоки 1–8 (ARC…CFG) | ~95% | ~70% | — | Основной функционал в GUI и `src/core/security/` |
| §9 TEST | 4/5 автотестов | — | — | TEST-5 только вручную |
| §10–13 INT/PERF/SEC/PLAT | ~90% | — | bonus/stub | PLAT: partial + `docs/PLAT_PLATFORM_FEATURES.md` |

**Автотесты Sprint 7 (32 теста, 6 skip на Windows — ожидаемо):**

```bash
py -3 -m unittest tests.test_sprint7_security_validation tests.test_sprint7_integration tests.test_sprint7_security_principles tests.test_sprint7_platform tests.test_perf_sprint7 -v
```

| Skip | Причина |
|------|---------|
| TEST-5 | ручной usability (5+ человек) |
| PLAT-2 / PLAT-3 (5 тестов) | только macOS / Linux |

---

## Содержание

| Блок | Статус | Основные файлы |
|------|--------|----------------|
| 1. ARC — архитектура | ✅ готово | `src/core/security/` |
| 2. SC — side-channel | ⚠️ partial | `side_channel_protection.py`, интеграции |
| 3. MEM — память | ⚠️ partial | `memory_guard.py`, `platform_security.py` |
| 4. ACT — auto-lock | ⚠️ partial | `activity_monitor.py`, `main_window.py` |
| 5. TRAY — системный трей | ✅ готово | `main_window.py` |
| 6. PANIC — режим паники | ⚠️ partial | `panic_mode.py`, `main_window.py` |
| 7. UX — полировка | ⚠️ partial | `ux_helpers.py`, `main_window.py` |
| 8. CFG — профили | ✅ готово | `security_config.py`, `settings_dialog.py` |
| 9. TEST — валидация | ⚠️ partial | `tests/test_sprint7_security_validation.py` |
| 10. INT — интеграция | ✅ готово | `integration.py`, vault/clipboard/audit/io |
| 11. PERF — производительность | ✅ готово | `tests/test_perf_sprint7.py` |
| 12. SEC — принципы | ✅ готово | `tests/test_sprint7_security_principles.py` |
| 13. PLAT — платформа | ⚠️ partial | `platform_security.py`, `docs/PLAT_PLATFORM_FEATURES.md` |

---

## Блок 1 — ARC (Architecture & Security Hardening Framework)

### Соответствие примерам из ТЗ (преподаватель)

| Пример в `sprint7.md` | Наш код |
|------------------------|---------|
| `SecureMemory`, `SecretHolder` | `memory_guard.py` — по образцу ТЗ |
| `ActivityMonitor` + platform detectors | `activity_monitor.py` — упрощённо: Qt events + `GetLastInputInfo` |
| `PanicMode._register_default_handlers()` | `panic_mode.py` — default handlers + делегирование через config |

### ARC-1 — каталог `src/core/security/`

**Требование (Must):** `side_channel_protection.py`, `memory_guard.py`, `activity_monitor.py`, `panic_mode.py`.

**Решение:** создан пакет + дополнительно:

| Файл | Назначение |
|------|------------|
| `security_config.py` | профили, валидация (CFG) |
| `integration.py` | INT-1..4 |
| `platform_security.py` | PLAT-1..3 |
| `__init__.py` | публичный API |

**Статус:** ✅ **DONE**

### ARC-2 — настройки с безопасными дефолтами

**Требование (Must):** все hardening-функции настраиваются, дефолты безопасные.

**Решение:** `SecuritySettings`, `apply_profile()`, `validate_settings()`, `non_default_warnings()`; связка с `SettingsDialog` и `StateManager` (ключи `security_profile`, `activity_sensitivity`, `device_type`, panic, tray).

**Статус:** ✅ **DONE**

### ARC-3 — обратная совместимость

**Требование (Must):** Sprint 3–6 не ломаются.

**Решение:** новые вызовы точечные (`wipe_local`, `constant_time_compare`, `secure_contains`, `check_io_aborted`); EventBus и API vault/clipboard/import без breaking changes.

**Статус:** ✅ **DONE**

---

## Блок 2 — SC (Side-Channel Attack Protection)

| ID | Priority | Статус | Реализация | Замечание |
|----|----------|--------|------------|-----------|
| SC-1 | Must | ⚠️ PARTIAL | `constant_time_compare` в auth, import, share, audit, search | Шифрование/Argon2 — через `cryptography` (стандартные примитивы), не свой CT-код |
| SC-2 | Should | ⚠️ PARTIAL | `constant_time_equal_int`, `secrets.compare_digest` | Secret-independent ветки в compare; полный cache-timing hardening не делали |
| SC-3 | Optional | — N/A | — | Не реализовано |
| SC-4 | Optional | — N/A | — | Не реализовано |

**Ключевые файлы:** `side_channel_protection.py`, `authentication.py`, `import_security.py`, `importer.py`, `share_crypto.py`, `log_signer.py`, `entry_manager.py` (`secure_contains`).

---

## Блок 3 — MEM (Secure Memory Management)

| ID | Priority | Статус | Реализация | Замечание |
|----|----------|--------|------------|-----------|
| MEM-1 | Must | ⚠️ PARTIAL | `SecureMemory.allocate_secure` — VirtualLock / mlock | `MAP_LOCKED` явно не используется |
| MEM-2 | Must | ✅ DONE | `secure_wipe`, `wipe_local`, wipe после encrypt/decrypt, clipboard | passes ≥ 1 в настройках |
| MEM-3 | Should | ❌ NOT DONE | — | Нет secure heap / guard pages / canary heap |
| MEM-4 | Must | ⚠️ PARTIAL | `stack_canary_ok`, `wipe_local` в auth | Полные stack canaries не везде |

**Ключевые файлы:** `memory_guard.py`, `encryption_service.py`, `clipboard_service.py`, `audit_logger.py`.

---

## Блок 4 — ACT (Activity Monitoring & Auto-Lock)

| ID | Priority | Статус | Реализация | Замечание |
|----|----------|--------|------------|-----------|
| ACT-1 | Must | ⚠️ PARTIAL | `eventFilter` (mouse/key/focus) + `GetLastInputInfo` (Windows) | Нет `platform/windows_activity.py` как в примере ТЗ; **screen saver / OS screen lock** — только косвенно через system idle |
| ACT-2 | Must | ✅ DONE | 1–480 мин, sensitivity, laptop/desktop | `ActivityMonitor._effective_timeout`, settings |
| ACT-3 | Must | ✅ DONE | `_do_auto_lock`: keys, clipboard, overlay, hide passwords | `LockOverlay` |
| ACT-4 | Must | ✅ DONE | `LoginDialog` + audit integrity + restore search | `Secure Desktop` на Windows — см. PLAT-1 |

**Ключевые файлы:** `activity_monitor.py`, `main_window.py`, `lock_overlay.py`, `login_dialog.py`.

---

## Блок 5 — TRAY (System Tray & Background Operation)

| ID | Priority | Статус | Реализация |
|----|----------|--------|------------|
| TRAY-1 | Must | ✅ DONE | Цвет lock/unlock/busy, мигание при crypto (`_set_tray_crypto_busy`) |
| TRAY-2 | Must | ✅ DONE | Lock, show, **быстрый поиск**, clipboard, panic, settings, exit |
| TRAY-3 | Must | ✅ DONE | Clipboard monitor + auto-lock в фоне; `showMessage` на lock/unlock |
| TRAY-4 | Must | ✅ DONE | Minimize-to-tray, restore geometry, start minimized, `setQuitOnLastWindowClosed(False)` |

**Ключевой файл:** `main_window.py` (`_create_tray_icon`, `_tray_quick_search`, `_quit_application`).

---

## Блок 6 — PANIC (Panic Mode)

| ID | Priority | Статус | Реализация | Замечание |
|----|----------|--------|------------|-----------|
| PANIC-1 | Must | ⚠️ PARTIAL | Hotkey `Ctrl+Shift+Esc`, tray, shake окна | Hardware token — Optional, нет |
| PANIC-2 | Must | ✅ DONE | Default handlers: clipboard, lock, close windows, wipe, hide, quit | `panic_mode.py` |
| PANIC-3 | Should | ⚠️ PARTIAL | Fake error (`stealth_mode`) | Decoy app / URL — нет |
| PANIC-4 | Must | ✅ DONE | Unlock, restore search, audit `PanicModeActivated` | `set_io_aborted` сброс при unlock |

### Соответствие примеру PanicMode из ТЗ

| Пример | Наш код |
|--------|---------|
| `_register_default_handlers()` | ✅ в `__init__` |
| `_clear_clipboard` | ✅ → `ClipboardService` / platform adapter |
| `_lock_vault` | ✅ → `lock_callback` → `_do_auto_lock` |
| `_close_windows` | ✅ → `close_windows_callback` |
| `_wipe_memory` | ✅ → `SecureMemory` + wipe clipboard buffers |
| `_log_panic_event` | ✅ → EventBus + audit + `log_security_hardening` |

**Ключевые файлы:** `panic_mode.py`, `main_window.py` (`_panic_config` передаёт сервисы).

---

## Блок 7 — UX (Usability Enhancements)

| ID | Priority | Статус | Реализация | Замечание |
|----|----------|--------|------------|-----------|
| UX-1 | Must | ⚠️ PARTIAL | Tab/Enter/Delete в таблице; `Ctrl+F/L/N`, `Ctrl+Shift+P` | Screen reader / полная a11y — минимально |
| UX-2 | Must | ✅ DONE | `run_with_progress`, confirm delete, цвета tray/lock/audit |
| UX-3 | Must | ✅ DONE | `show_user_error` + `USER_HINTS`, `log_error` |
| UX-4 | Must | ✅ DONE | Lazy load 200 записей, отложенный integrity, PERF-4 startup |

**Ключевые файлы:** `ux_helpers.py`, `main_window.py`, `secure_table.py`.

---

## Блок 8 — CFG (Configuration Management)

| ID | Priority | Статус | Реализация |
|----|----------|--------|------------|
| CFG-1 | Must | ✅ DONE | Standard / Enhanced / Paranoid |
| CFG-2 | Must | ✅ DONE | `profile_changes_text` + confirm; откат `old_settings` при Exception |
| CFG-3 | Must | ✅ DONE | `validate_settings`, `non_default_warnings` перед apply |

**Ключевые файлы:** `security_config.py`, `settings_dialog.py`, `main_window._open_settings_dialog`.

---

## Блок 9 — TEST (Security Validation)

| ID | Priority | Статус | Тест / действие |
|----|----------|--------|-----------------|
| TEST-1 | Must | ✅ DONE | `TestSprint7TimingAttack` — ratio compare |
| TEST-2 | Must | ⚠️ PARTIAL | wipe + SecretHolder | Полный memory dump в тесте не симулируется (упрощённая проверка) |
| TEST-3 | Must | ✅ DONE | 24× activity + lock после idle |
| TEST-4 | Must | ✅ DONE | panic cycles + mid-operation recovery |
| TEST-5 | Must | ❌ MANUAL | `@unittest.skip` — чеклист ниже |

```bash
py -3 -m unittest tests.test_sprint7_security_validation -v
```

### TEST-5 — ручной чеклист (обязателен по ТЗ)

1. **Участники:** ≥ 5 человек.  
2. **Задачи:** вход, добавление записи, поиск, экспорт, срабатывание auto-lock.  
3. **Метрики:** время выполнения, число ошибок, замечания по tray/panic.  
4. **Артефакт:** таблица результатов (дата, участник, задача, время, ошибки).

---

## Блок 10 — INT (Integration Points)

| ID | Priority | Статус | Реализация |
|----|----------|--------|------------|
| INT-1 | Must | ✅ DONE | `encryption_service.wipe_local`; `secure_contains` в поиске |
| INT-2 | Must | ✅ DONE | `SecureClipboardItem.secure_wipe`; panic `force_clear` |
| INT-3 | Must | ✅ DONE | `log_security_hardening`; wipe audit blob |
| INT-4 | Must | ✅ DONE | `wipe_sensitive`; `check_io_aborted` в import/export |

**Модуль:** `src/core/security/integration.py`

```bash
py -3 -m unittest tests.test_sprint7_integration -v
```

---

## Блок 11 — PERF (Performance)

| ID | Priority | Статус | Проверка |
|----|----------|--------|----------|
| PERF-1 | Must | ✅ DONE | CT overhead < 10% |
| PERF-2 | Must | ✅ DONE | memory protection ≤ 105% baseline |
| PERF-3 | Must | ✅ DONE | ActivityMonitor idle CPU < 1% |
| PERF-4 | Must | ✅ DONE | startup < 3 s (PyQt6) |

```bash
py -3 -m unittest tests.test_perf_sprint7 -v
```

Без PyQt6: PERF-4 skip.

---

## Блок 12 — SEC (Security Requirements)

| ID | Priority | Статус | Реализация |
|----|----------|--------|------------|
| SEC-1 | Must | ✅ DONE | Defense in depth — тест `TestSec1DefenseInDepth` |
| SEC-2 | Must | ✅ DONE | Fail secure defaults — `TestSec2FailSecureDefaults` |
| SEC-3 | Must | ✅ DONE | Стандартные примитивы, документированные профили — без скрытых параметров |
| SEC-4 | Must | ✅ DONE | Isolated panic handlers; integrity fail secure |

```bash
py -3 -m unittest tests.test_sprint7_security_principles -v
```

---

## Блок 13 — PLAT (Platform-Specific)

Подробно: **`docs/PLAT_PLATFORM_FEATURES.md`**.

| ID | Priority | Статус | Реализация | Замечание |
|----|----------|--------|------------|-----------|
| PLAT-1 Credential Guard | Must | ⚠️ PARTIAL | реестр DeviceGuard + VirtualLock | Не полный VBS API |
| PLAT-1 Secure Desktop | Must | ⚠️ PARTIAL | `prompt_with_secure_desktop_fallback` → `LoginDialog` | Best-effort; fallback на Qt |
| PLAT-1 Windows Hello | bonus | STUB | `windows_hello_available()` | |
| PLAT-2 Keychain | Must | ✅ DONE | `keyring` | |
| PLAT-2 Touch ID | bonus | STUB | `macos_touch_id_available()` | |
| PLAT-2 Gatekeeper | Must | ⚠️ PARTIAL | `macos_gatekeeper_notarization_status()` | spctl; notarization — CI |
| PLAT-3 mlock/keyring | Must | ⚠️ PARTIAL | `linux_mlock`, keyring | keyctl напрямую нет |
| PLAT-3 systemd/LSM | Must | STUB | детекция only | unit-файлы / профили не поставляются |

```bash
py -3 -m unittest tests.test_sprint7_platform -v
```

API статуса: `describe_platform_features()`.

---

## Комментарии в коде (как в Sprint 4–6)

**Соглашение:** в начале файла — `# Sprint 7 / <блоки ТЗ>: …`; у ключевых мест — метки `# ACT-1:`, `# PANIC-2:`, `# INT-1:` и т.д.

| Область | Файлы с заголовком Sprint 7 |
|---------|----------------------------|
| Core security | `src/core/security/*.py` |
| GUI | `main_window.py`, `ux_helpers.py`, `lock_overlay.py`, `login_dialog.py`, `settings_dialog.py`, `secure_table.py` |
| Интеграции | `integration.py`, `encryption_service.py`, `authentication.py`, `clipboard_service.py`, `entry_manager.py` |
| Тесты | `tests/test_sprint7_*.py`, `tests/test_perf_sprint7.py` |

Подробный аудит — в таблицах блоков выше; PLAT-заглушки — в `docs/PLAT_PLATFORM_FEATURES.md`.

---

| Спринт | Что используем в Sprint 7 |
|--------|---------------------------|
| 2 | `authentication`, Argon2/PBKDF2, constant-time password compare |
| 3 | `VaultEncryptionService`, `EntryManager`, lazy load |
| 4 | `ClipboardService`, tray clipboard status |
| 5 | `AuditLogger`, integrity on unlock |
| 6 | import/export + `check_io_aborted` при panic |

---

## Что **не** в scope / остаточные пробелы

| Пункт | Priority | Статус |
|-------|----------|--------|
| MEM-3 heap protection | Should | ❌ |
| SC-3, SC-4 | Optional | — |
| ACT-1 screen lock / platform/*_activity.py | Must | ⚠️ упрощено |
| PANIC-3 decoy app / URL | Should | ❌ |
| PANIC-1 hardware token | Optional | — |
| TEST-5 usability study | Must | ❌ ручной |
| UX-1 full a11y | Must | ⚠️ частично |
| PLAT полная интеграция (systemd unit, SELinux profile) | Must | STUB |

---

## Файлы Sprint 7 (основные)

```text
src/core/security/
├── __init__.py
├── activity_monitor.py      # ACT
├── integration.py           # INT
├── memory_guard.py          # MEM
├── panic_mode.py            # PANIC (default handlers)
├── platform_security.py     # PLAT
├── security_config.py       # ARC-2 / CFG
└── side_channel_protection.py  # SC

src/gui/
├── main_window.py           # ACT, TRAY, PANIC, UX-4
├── ux_helpers.py            # UX-3
└── widgets/
    ├── lock_overlay.py      # ACT-3
    ├── login_dialog.py      # ACT-4 / PLAT Secure Desktop
    └── settings_dialog.py   # CFG

docs/
├── SPRINT7_IMPLEMENTATION.md   # этот файл
└── PLAT_PLATFORM_FEATURES.md # PLAT заглушки и Secure Desktop

tests/
├── test_sprint7_security_validation.py  # TEST-1..4
├── test_sprint7_integration.py          # INT
├── test_sprint7_security_principles.py  # SEC
├── test_sprint7_platform.py             # PLAT
└── test_perf_sprint7.py                   # PERF
```

---

## Итоговая оценка

**Must-требования Sprint 7 закрыты примерно на 88–92%** для сдачи с пояснениями по partial/stub.  
**Автотесты по §9–§13 проходят** (32 OK, 6 skip).  
**Для формальной полноты остаётся:** ручной TEST-5, при желании — MEM-3, PANIC-3 decoy, platform activity modules, полноценный Secure Desktop в отдельном процессе.

---

*Обновлено: полный аудит Sprint 7 — блоки ARC … PLAT, PanicMode default handlers, PLAT Secure Desktop + заглушки.*
