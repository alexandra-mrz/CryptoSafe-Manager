# Sprint 8 — журнал реализации (CryptoSafe Manager)

Документ заполняется по ходу работы: **что делаем**, **какие решения принимаем**, **где лежит код**.  
ТЗ: `sprints/sprint8.md`.

**Цель спринта:** финальная интеграция, тесты, упаковка, документация — готовый password manager.

---

## Содержание

| Блок | Статус | Файлы |
|------|--------|--------|
| 1. INT — интеграция и cleanup | ✅ готово | `src/bootstrap.py`, `run.py`, `main.py` |
| 2. TEST | ✅ готово | `tests/test_sprint8*.py`, `tests/generate_test_report.py`, `pytest.ini`, `.coveragerc` |
| 3. PKG | ✅ готово | `cryptosafe.spec`, `scripts/build_exe.ps1`, `requirements-build.txt` |
| 4. DOC | ✅ готово | `README.md`, `docs/user_guide.md`, `docs/technical.md`, `docs/screenshots/` |
| 5. POL | ✅ готово | `src/gui/ux_helpers.py`, `src/gui/gui_styles.py`, `tests/test_sprint8_polish.py` |

---

## Блок 1 — Final Integration & Code Cleanup

> В §1 ТЗ **нет** отдельных автотестов — только интеграция и запуск.  
> Тесты — **блок 2** (pytest, coverage).

### INT-1 — все модули Sprints 1–7 в одном приложении

**Требование (Must):** модули работают вместе как одно приложение.

**Решение:**

- `src/bootstrap.py` → `initialize_application()` — единая инициализация перед GUI.
- Порядок: config/events → audit subscribers → state manager → security integration.
- GUI (`MainWindow`) использует vault, clipboard, audit, import/export, security — как в Sprints 3–7.

**Как проверить (вручную):** запустить приложение, войти, добавить запись, копировать в буфер, экспорт/импорт, auto-lock, panic.

### INT-2 — структура `src/` и импорты

**Требование (Must):** понятные слои, без циклических зависимостей.

**Слои (сверху вниз):**

| Слой | Пакет |
|------|--------|
| 1 | `src.database` |
| 2 | `src.core.events`, `src.core.config` |
| 3 | `src.core.crypto` |
| 4 | `src.core.security` |
| 5 | `src.core.vault`, `clipboard`, `import_export`, `audit` |
| 6 | `src.core.state_manager` |
| 7 | `src.gui` |

Lazy import внутри функций (например `key_storage` → `is_session_unlocked`) — чтобы не было циклов при загрузке модулей.

### INT-3 — TODO / FIXME

**Требование (Must):** в `src/` нет `TODO` / `FIXME`.

**Статус:** ✅ в исходниках `src/` таких комментариев нет.

### INT-4 — запуск с чистого clone

**Требование (Must):** старт без ошибок после clone + `pip install -r requirements.txt`.

**Точки входа:**

| Команда | Файл |
|---------|------|
| `python -m src` | `src/__main__.py` |
| `python run.py` | `run.py` |
| `python main.py` | `main.py` |

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m src
```

**Быстрая проверка инициализации без GUI:**

```bash
python -c "from src.bootstrap import initialize_application; initialize_application(); print('OK')"
```

---

## Файлы блока 1

```text
src/bootstrap.py    # INT-1 / INT-4
src/__main__.py
run.py
main.py
```

---

*Обновлено: блок 1 INT + блок 2 TEST (Sprint 8).*

---

## Блок 2 — Testing & Verification

### TEST-1 — pytest-сьют (Must)

**Файлы:**

| Область | Файл |
|---------|------|
| Crypto, vault, clipboard, import/export | `tests/test_sprint8.py` |
| Доп. покрытие форматов | `tests/test_sprint8_coverage.py` |
| Import/export (расширенные) | `tests/test_sprint8_io.py` (slow — только полный отчёт) |
| Наследие спринтов 3–7 | `tests/test_*.py` |

**Быстрый прогон (TEST-4, < 30 с):**

```bash
pytest
```

По умолчанию: `-m "not perf and not slow"`, без GUI/pyautogui.

**Полный прогон (без perf-тестов):**

```bash
pytest -m "not perf"
```

### TEST-2 — coverage ≥ 80% (Must)

```bash
python tests/generate_test_report.py
# или напрямую:
pytest -m "not perf" -o addopts= --cov=src --cov-config=.coveragerc
```

- Конфиг: `.coveragerc` — `pytest --cov=src`, в `omit` только GUI, точки входа, OS/QR-заглушки (см. комментарии в файле).
- **Core-модули TEST-1 не исключаются** (`entry_manager`, `exporter`, `importer`, `clipboard_service`, …).
- Полный прогон: все functional-тесты, кроме 2 perf-микробенчмарков; slow-тесты включаются (`-o addopts=` сбрасывает фильтр из `pytest.ini`).
- Скрипт отчёта завершается с кодом **1**, если coverage &lt; 80%.

**Файлы покрытия (дополнительно к `test_sprint8*.py`):**

| Файл | Назначение |
|------|------------|
| `test_sprint8_src_coverage.py` | io_storage, panic, state_manager, QR (slow) |
| `test_sprint8_extended.py` | форматы export, sharing, audit rotation (slow) |
| `test_sprint8_io_integration.py` | io_integration + sharing link (slow) |
| `test_sprint8_coverage_boost.py` | clipboard, import/export, panic, audit (slow) |
| `test_sprint8_clipboard_full.py` | clipboard (быстрый прогон) |
| `test_sprint8_models.py` | миграции БД (быстрый прогон) |

### TEST-3 — отчёт в `tests/report/` (Must)

Скрипт `tests/generate_test_report.py` создаёт:

| Файл | Содержимое |
|------|------------|
| `summary.md` | passed/failed/skipped + coverage по модулям |
| `pytest_report.html` | HTML pytest |
| `coverage_html/index.html` | интерактивный coverage |
| `coverage.json` | JSON coverage |
| `pytest_console.txt` | полный лог |

### TEST-4 — < 30 с (Should)

Маркировка в `tests/conftest.py`: `perf` / `slow`.  
Типичный `pytest` на ноутбуке: **~16 с**, 66 passed.

### Итог блока 2 (честный прогон)

| Метрика | Значение |
|---------|----------|
| Coverage (`--cov=src`) | **80.2%** |
| Полный прогон | 143 passed, 0 failed (~2 мин) |
| Быстрый прогон | 66 passed, &lt; 30 с |

### Зависимости

`requirements.txt`: `pytest`, `pytest-cov`, `pytest-html`.

---

## Блок 3 — Packaging & Distribution

### PKG-1 — PyInstaller one-folder (Must)

**Файлы:**

| Файл | Назначение |
|------|------------|
| `cryptosafe.spec` | конфиг PyInstaller (onedir) |
| `scripts/build_exe.ps1` | сборка на Windows |
| `scripts/build_exe.sh` | сборка на macOS / Linux |
| `requirements-build.txt` | `pyinstaller==6.20.0` |

**Сборка (Windows):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-build.txt
.\scripts\build_exe.ps1
```

**Результат:** `dist/CryptoSafeManager/` — папка с `CryptoSafeManager.exe` и всеми зависимостями.

### PKG-2 — requirements.txt с версиями (Must)

`requirements.txt` — runtime + dev/test зависимости с фиксированными версиями (`==`).

### PKG-3 — run script (Must)

`run.py` — запуск из исходников:

```bash
python run.py
```

Альтернативы: `python -m src`, `python main.py`.

### PKG-4 — инструкции (Must)

См. раздел **«Упаковка и запуск (Sprint 8)»** в `README.md`.

---

## Блок 4 — Documentation

### DOC-1 — README.md (Must)

Файл `README.md` содержит:

| Раздел | Статус |
|--------|--------|
| Обзор и назначение проекта | ✅ |
| Установка, тесты, запуск | ✅ |
| Основные функции со скриншотами | ✅ `docs/screenshots/*.png` |
| Известные ограничения | ✅ |
| Планы развития (future work) | ✅ |

### DOC-2 — user_guide.md (Must)

`docs/user_guide.md`:

- установка и запуск (исходники + exe)
- мастер-пароль и vault
- добавление / изменение / удаление записей
- защищённый буфер обмена
- import / export / share

### DOC-3 — technical.md (Must)

`docs/technical.md`:

- архитектура (слои, mermaid, bootstrap)
- криптография (Argon2id, PBKDF2, AES-GCM, Ed25519, share/export)
- схема БД и структуры данных

### DOC-4 — docstrings (Should)

- Публичные классы и функции в `src/` — docstrings (проверка):

```bash
python scripts/check_docstrings.py
```

- Массовое добавление (если нужно после правок): `python scripts/ensure_docstrings.py`

---

## Блок 5 — Final Polish & Bug Fixes

### POL-1 — критические баги (Must)

**Статус:** ✅ полный прогон `pytest -m "not perf"` — все тесты проходят; регрессии после правок GUI не выявлены.

### POL-2 — визуальная согласованность GUI (Should)

**Решение:**

- `src/gui/gui_styles.py` — `BASE_STYLESHEET` (шрифты Segoe UI / Roboto, отступы кнопок, group box, таблицы).
- `apply_base_styles(app)` вызывается в `MainWindow.run_app()` до показа окна.
- `tune_dialog_layout()` — единые margins/spacing для диалогов (при необходимости в новых диалогах).

### POL-3 — понятные сообщения об ошибках (Must)

**Решение:**

- `src/gui/ux_helpers.py`: `USER_HINTS`, `_safe_message()`, `show_user_error()`, `show_exception()`.
- Сырые traceback и пути к `.py` не попадают в `QMessageBox` — детали только в лог `cryptosafe.ui`.
- Обновлены диалоги: export, import, sharing, login, setup, change password, audit, QR viewer; обработка ошибок в `main_window.py`.

**Проверка:**

```bash
pytest tests/test_sprint8_polish.py -q
```

### POL-4 — edge cases (Must)

| Сценарий | Поведение |
|----------|-----------|
| Пустой vault | Статус-бар «Хранилище пусто…»; экспорт — `empty_vault` без crash |
| Неверный мастер-пароль | Код `wrong_password` с подсказкой (Caps Lock, раскладка) |
| Отмена login / master password | Диалог закрывается без падения приложения |
| Нет выбранной записи | `no_selection` при share/edit/delete |

**Тесты:** `tests/test_sprint8_polish.py` (UX helpers + import error report без Traceback).

