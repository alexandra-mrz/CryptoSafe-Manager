# CryptoSafe Manager

Кроссплатформенный **локальный менеджер паролей** с графическим интерфейсом (PyQt6), 
зашифрованной SQLite-базой, защищённым буфером обмена, аудитом, import/export и обменом 
записей.

| | |
|---|---|
| **Назначение** | Хранить логины, пароли, URL и заметки **только на компьютере пользователя**, без облака |
| **Безопасность** | Argon2id (мастер-пароль), AES-256-GCM (записи), подписанный audit log, auto-lock, panic mode |
| **Полное ТЗ** | [sprints/project_outline.md](sprints/project_outline.md) · [sprints/sprint8.md](sprints/sprint8.md) |

---

## Содержание

1. [Как запускать (шпаргалка)](#как-запускать-шпаргалка)
2. [Архитектура](#архитектура)
3. [Дорожная карта спринтов](#дорожная-карта-спринтов)
4. [Установка и первый запуск](#установка-и-первый-запуск)
5. [Основные функции](#основные-функции)
6. [Скриншоты](#скриншоты)
7. [Документация](#документация)
8. [Для проверяющего](#для-проверяющего)
9. [Ограничения и планы](#известные-ограничения)

---

## Архитектура

Слои (MVC-подобное разделение, Sprint 1 / ARC-3):

```
┌─────────────────────────────────────────────────────────────┐
│  View — src/gui/          PyQt6, диалоги, главное окно      │
└───────────────────────────────┬─────────────────────────────┘
                                │ EventBus, вызовы API
┌───────────────────────────────▼─────────────────────────────┐
│  Controller / Core — src/core/                              │
│  crypto · vault · clipboard · import_export · audit ·       │
│  security · state_manager · config                          │
└───────────────────────────────┬─────────────────────────────┘
                                │ SQL, миграции
┌───────────────────────────────▼─────────────────────────────┐
│  Model — src/database/    SQLite (cryptosafe.db)            │
└─────────────────────────────────────────────────────────────┘
```

Подробная диаграмма (Mermaid), криптография и схема БД: **[docs/technical.md](docs/technical.md)**.

---

## Дорожная карта спринтов

| Sprint | Цель | Ключевые результаты |
|--------|------|---------------------|
| **1** | Фундамент | Схема SQLite, GUI-каркас, config, EventBus |
| **2** | Ключи | Argon2id, PBKDF2, `key_store`, смена пароля |
| **3** | Vault | AES-GCM, CRUD, поиск, генератор паролей |
| **4** | Clipboard | Автоочистка, мониторинг, платформенные адаптеры |
| **5** | Audit | Hash-chain, Ed25519, просмотр и экспорт журнала |
| **6** | IO / Share | Import/export, QR, контакты, share-пакеты |
| **7** | Hardening | Panic mode, tray, activity monitor, UX |
| **8** | Релиз | Интеграция, pytest ≥80%, PyInstaller, документация |

---

## Как запускать (шпаргалка)

Все команды ниже выполняются **из корня репозитория** — папки, где лежат `run.py`, `requirements.txt` и каталог `src/`:

```text
crypto/          ← сюда перейти: cd crypto
├── run.py       ← основной запуск GUI
├── src/
├── tests/
└── scripts/
```

| Что нужно | Где (терминал / IDE) | Команда или файл |
|-----------|----------------------|------------------|
| **GUI из исходников** | корень `crypto/` | `python run.py` |
| То же (альтернатива) | корень `crypto/` | `python -m src` или `python main.py` |
| **Быстрые тесты** (~20 с) | корень `crypto/` | `pytest` |
| **Полный отчёт + coverage ≥80%** | корень `crypto/` | `python tests/generate_test_report.py` |
| **Сборка .exe (Windows)** | корень `crypto/`, PowerShell | `.\scripts\build_exe.ps1` |
| **Запуск собранного .exe** | папка `dist\CryptoSafeManager\` | `CryptoSafeManager.exe` |
| **Без Python (сдача)** | любая папка после распаковки ZIP | `CryptoSafeManager\CryptoSafeManager.exe` |

После первого запуска приложение создаёт **локальные данные в корне проекта** (не коммитятся в git):

| Файл / папка | Назначение |
|--------------|------------|
| `data/cryptosafe.db` | зашифрованное хранилище |
| `config.json` | путь к БД, таймаут буфера, auto-lock |

> **Важно:** запускайте `run.py` с рабочей директорией = корень репозитория.  
> Если запустить из другой папки, `data/` и `config.json` появятся **там**, а не в проекте.

**PyCharm:** Run → `run.py`, Working directory = `$ProjectFileDir$` (корень проекта).

---

## Установка и первый запуск

### Требования

- **Python 3.10+** — запуск из исходников и тесты
- **Windows 10+** — для готового `.exe` (сборка PyInstaller)
- macOS / Linux — только `python run.py` или сборка `./scripts/build_exe.sh` на своей ОС

### Шаг 1. Клонирование и окружение

**Windows (PowerShell):**

```powershell
git clone https://github.com/alexandra-mrz/CryptoSafe-Manager.git crypto
cd crypto

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**macOS / Linux:**

```bash
git clone https://github.com/alexandra-mrz/CryptoSafe-Manager.git crypto
cd crypto

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Дополнительно для QR (опционально):

- **macOS:** `brew install zbar`
- **Linux:** `sudo apt install libzbar0 xclip` (или `xsel`)

### Шаг 2. Запуск приложения (GUI)

Из **корня** `crypto/` (с активированным `.venv`):

```bash
python run.py
```

Откроется PyQt6: при первом запуске — мастер настройки и создание мастер-пароля, затем главное окно.

Цепочка вызова: `run.py` → `src/bootstrap.py` (инициализация БД, аудита, security) → `src/gui/main_window.py`.

### Шаг 3. Тесты

Тоже из **корня** `crypto/`:

```bash
# Быстрая проверка (без perf/slow, см. pytest.ini)
pytest

# Sprint 8: HTML-отчёт, coverage, summary.md
python tests/generate_test_report.py
```

Результаты появятся в `tests/report/`:

| Файл | Содержимое |
|------|------------|
| `summary.md` | краткая сводка и % покрытия |
| `pytest_report.html` | список тестов pass/fail |
| `coverage_html/index.html` | покрытие по модулям (открыть в браузере) |

### Шаг 4. Сборка executable (Windows)

Из **корня** `crypto/` в PowerShell (скрипт сам подхватит `.venv\Scripts\python.exe`, если есть):

```powershell
.\scripts\build_exe.ps1
```

Готовый файл:

```powershell
.\dist\CryptoSafeManager\CryptoSafeManager.exe
```

Для сдачи курса скрипт также создаёт **`dist/CryptoSafeManager-Windows.zip`** — архив с `exe` и зависимостями (`_internal`).

> Собранный Windows-exe **не работает** на macOS/Linux. Там — только `python run.py` или пересборка на целевой ОС.

---

## Основные функции

| Функция | Меню / действие | Подробнее |
|---------|-----------------|-----------|
| **Vault** | Правка → Добавить / Изменить / Удалить | [user_guide §3](docs/user_guide.md#3-записи-vault) |
| **Мастер-пароль** | Мастер первого запуска, диалог входа | [user_guide §2](docs/user_guide.md#2-мастер-пароль-и-vault) |
| **Буфер обмена** | Копировать из таблицы, автоочистка | [user_guide §4](docs/user_guide.md#4-защищённый-буфер-обмена) |
| **Import / Export** | Данные → Импорт / Экспорт | [user_guide §5](docs/user_guide.md#5-импорт-экспорт-и-резервное-копирование) |
| **Share / QR** | Данные → Обмен / Сканировать QR | [user_guide §5](docs/user_guide.md#5-импорт-экспорт-и-резервное-копирование) |
| **Audit log** | Вид → Журнал аудита | [user_guide §6](docs/user_guide.md#6-журнал-аудита-и-настройки) |
| **Backup** | Файл → Резервная копия / Восстановить | [user_guide §5](docs/user_guide.md#резервная-копия-и-восстановление) |
| **Panic mode** | Ctrl+Shift+P | [user_guide §2](docs/user_guide.md#блокировка) |

---

## Скриншоты

Иллюстрации основных экранов (DOC-1). Пошаговые инструкции — в [docs/user_guide.md](docs/user_guide.md).

| Функция | Скриншот |
|---------|----------|
| Главное окно, список записей, поиск | ![Главное окно](docs/screenshots/main_window.png) |
| Разблокировка vault (мастер-пароль) | ![Вход](docs/screenshots/login_dialog.png) |
| Экспорт данных | ![Экспорт](docs/screenshots/export_dialog.png) |
| Настройки безопасности (буфер, auto-lock, профиль) | ![Настройки](docs/screenshots/settings_dialog.png) |

*Копирование в буфер и журнал аудита выполняются из главного окна и меню «Вид» — см. user guide.*

---

## Документация

| Документ | Назначение (Sprint 8) |
|----------|------------------------|
| [docs/user_guide.md](docs/user_guide.md) | **DOC-2** — руководство пользователя |
| [docs/technical.md](docs/technical.md) | **DOC-3** — архитектура, криптография, БД |
| [docs/SPRINT8_IMPLEMENTATION.md](docs/SPRINT8_IMPLEMENTATION.md) | Журнал реализации Sprint 8 |
| [docs/SPRINT6_IMPLEMENTATION.md](docs/SPRINT6_IMPLEMENTATION.md) | Import/export, share |
| [docs/SPRINT7_IMPLEMENTATION.md](docs/SPRINT7_IMPLEMENTATION.md) | Security hardening, UX |

### Структура репозитория

```
crypto/                          ← рабочая директория для всех команд
├── run.py                       ← PKG-3: запуск GUI (предпочтительно)
├── main.py                      ← то же, что run.py
├── requirements.txt             ← PKG-2: зависимости runtime + pytest
├── requirements-build.txt       ← PyInstaller (только для сборки exe)
├── cryptosafe.spec              ← PKG-1: конфиг PyInstaller
├── config.json                  ← создаётся при работе (в .gitignore)
├── data/cryptosafe.db           ← создаётся при работе (в .gitignore)
├── src/
│   ├── bootstrap.py             ← инициализация подсистем (Sprint 8)
│   ├── __main__.py              ← python -m src
│   ├── core/                    # crypto, vault, clipboard, audit, IO
│   ├── database/                # SQLite, миграции
│   └── gui/                     # PyQt6
├── tests/
│   ├── test_*.py                # pytest
│   ├── generate_test_report.py  # полный отчёт Sprint 8
│   └── report/                  # артефакты после generate_test_report.py
├── scripts/
│   ├── build_exe.ps1            # сборка Windows (из корня crypto/)
│   └── build_exe.sh             # сборка Linux/macOS
├── docs/                        # user_guide, technical, screenshots
└── sprints/                     # ТЗ по спринтам
```

---

## Для проверяющего

Минимальный сценарий проверки (подробности — в [шпаргалке](#как-запускать-шпаргалка)):

**Вариант A — из исходников (рекомендуется):**

```powershell
git clone https://github.com/alexandra-mrz/CryptoSafe-Manager.git crypto
cd crypto
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python tests/generate_test_report.py   # ожидается coverage ≥ 80%, отчёт в tests/report/
python run.py                          # GUI, данные в crypto/data/
```

**Вариант B — только .exe (Windows, без Python):**

1. Распаковать `CryptoSafeManager-Windows.zip` в любую папку.
2. Запустить `CryptoSafeManager\CryptoSafeManager.exe` (не перемещать отдельно `exe` без папки `_internal`).
3. При первом запуске — мастер настройки и мастер-пароль; БД появится рядом с exe (в каталоге запуска).

### Контакт

**Автор:** Морозова Александра Эдуардовна  
**Группа:** ИСБ-124  
**Email:** [morozovaalexandera3@gmail.com](mailto:morozovaalexandera3@gmail.com)  
**Репозиторий:** [github.com/alexandra-mrz/CryptoSafe-Manager](https://github.com/alexandra-mrz/CryptoSafe-Manager.git)

---

## Известные ограничения

- **Локальное хранение** — нет синхронизации между устройствами.
- **Одна ОС на сборку** — Windows-exe не переносится на macOS/Linux.
- **QR / камера** — нужны `pyzbar`, системная библиотека `zbar`; камера не на всех системах.
- **Мастер-пароль** — восстановление невозможно; без пароля данные недоступны.
- **Мягкое удаление** — записи сохраняются в `deleted_entries`; отдельного UI «корзины» нет.

## Планы развития

- TOTP / 2FA для записей.
- Облачная синхронизация (заготовки в `future_integrations.py`).
- Полная локализация EN, тёмная тема.
- UI восстановления записей из корзины.
- Browser extension (вне scope Sprint 8).

---

## Лицензия

Учебный проект (Applied Cryptography). Исходный код и документация предоставляются для оценки в рамках курса.
