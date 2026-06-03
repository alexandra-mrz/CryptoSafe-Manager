# CryptoSafe Manager

Кроссплатформенный **локальный менеджер паролей** с графическим интерфейсом (PyQt6), зашифрованной SQLite-базой, защищённым буфером обмена, аудитом, import/export и обменом записей.

- **Назначение:** хранить логины, пароли, URL и заметки только на машине пользователя, без облака.
- **Безопасность:** Argon2id для мастер-пароля, AES-256-GCM для записей, автоочистка буфера, panic mode, подписанный audit log.
- **ТЗ спринтов:** [sprints/project_outline.md](sprints/project_outline.md)

---

## Быстрый старт

### 1. Установка

```bash
git clone <repo-url> crypto
cd crypto
python -m venv .venv
.venv\Scripts\activate          # Windows PowerShell
# source .venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
```

### 2. Запуск приложения

```bash
python run.py
```

Альтернативы: `python -m src`, `python main.py`.

### 3. Тесты

```bash
pytest                                    # быстрый прогон (~15 с)
python tests/generate_test_report.py      # полный отчёт + coverage ≥ 80%
```

Отчёты: `tests/report/summary.md`, `tests/report/coverage_html/index.html`.

### 4. Сборка executable (PyInstaller)

```powershell
pip install -r requirements-build.txt
.\scripts\build_exe.ps1
.\dist\CryptoSafeManager\CryptoSafeManager.exe
```

Подробнее: [docs/user_guide.md](docs/user_guide.md), [docs/technical.md](docs/technical.md).

---

## Основные функции (кратко)

| Функция | Описание |
|---------|----------|
| **Vault** | CRUD записей, поиск, теги, генератор паролей |
| **Мастер-пароль** | Argon2id, смена пароля, автоблокировка |
| **Буфер обмена** | Копирование с таймаутом и автоочисткой |
| **Import/Export** | JSON, CSV, Bitwarden, LastPass, зашифрованные пакеты |
| **Share / QR** | Обмен одной записью, QR, ссылки `cryptosafe://` |
| **Audit log** | Подписанный журнал, экспорт, проверка целостности |
| **Panic mode** | Ctrl+Shift+P — экстренная блокировка |

---

## Скриншоты

### Главное окно и список записей

![Главное окно](docs/screenshots/main_window.png)

### Разблокировка vault

![Диалог входа](docs/screenshots/login_dialog.png)

### Экспорт данных

![Экспорт](docs/screenshots/export_dialog.png)

### Настройки безопасности

![Настройки](docs/screenshots/settings_dialog.png)

> Подробные пошаговые инструкции: **[docs/user_guide.md](docs/user_guide.md)**.

---

## Структура проекта

```
src/
  bootstrap.py      # инициализация приложения
  core/             # crypto, vault, clipboard, import_export, audit, security
  database/         # SQLite, миграции, io_storage
  gui/              # PyQt6 UI
tests/              # pytest, coverage, отчёты
docs/
  user_guide.md     # руководство пользователя (DOC-2)
  technical.md      # архитектура и криптография (DOC-3)
  screenshots/      # иллюстрации для README
run.py              # запуск из исходников (PKG-3)
cryptosafe.spec     # PyInstaller (PKG-1)
```

---

## Документация

| Документ | Содержание |
|----------|------------|
| [docs/user_guide.md](docs/user_guide.md) | Установка, vault, clipboard, import/export |
| [docs/technical.md](docs/technical.md) | Архитектура, AES-GCM, Argon2, схема БД |
| [docs/SPRINT8_IMPLEMENTATION.md](docs/SPRINT8_IMPLEMENTATION.md) | Журнал реализации Sprint 8 |

---

## Известные ограничения

- **Локальное хранение** — нет синхронизации между устройствами (заглушки cloud в `future_integrations.py`).
- **Одна платформа на сборку** — PyInstaller-бинарник собирается под ОС разработчика.
- **QR / камера** — требуют `pyzbar`, Pillow, opencv; на части систем камера недоступна.
- **Keyring** — при недоступности OS keyring ключ vault держится только в RAM сессии.
- **GUI-тесты** — `pyautogui` опционален; не входят в быстрый pytest-прогон.
- **Мастер-пароль** — восстановление невозможно; потеря пароля = потеря данных.

## Планы развития

- TOTP / 2FA для записей (заготовки в коде).
- Облачная синхронизация и сетевой share (Sprint 6+ future).
- Улучшение UX (тёмная тема, локализация EN полностью).
- Mobile / browser extension (вне scope Sprint 8).

---

## Лицензия и сдача

Учебный проект CryptoSafe Manager (8 спринтов).  
Полное ТЗ: [sprints/sprint8.md](sprints/sprint8.md).

---

## История спринтов (кратко)

| Sprint | Фокус |
|--------|--------|
| 1 | Архитектура, config, events, GUI-каркас |
| 2 | SQLite, Argon2, PBKDF2, key_store |
| 3 | Vault CRUD, AES-GCM, GUI таблица |
| 4 | Clipboard, мониторинг, автоочистка |
| 5 | Audit log, Ed25519, целостность |
| 6 | Import/export, share, QR |
| 7 | Panic mode, tray, activity monitor, UX |
| 8 | Интеграция, тесты ≥80%, PyInstaller, документация |

Детали ранних спринтов — в `docs/SPRINT6_IMPLEMENTATION.md`, `docs/SPRINT7_IMPLEMENTATION.md`.
