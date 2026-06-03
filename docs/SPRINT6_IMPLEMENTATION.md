# Sprint 6 — журнал реализации (CryptoSafe Manager)

Документ заполняется по ходу работы: **что делаем**, **какие решения принимаем**, **где лежит код**.  
ТЗ: `sprints/sprint6.md`.

---

## Цель спринта

Импорт/экспорт хранилища, безопасный обмен записью, обмен ключами (в т.ч. QR) — с **отдельными** ключами шифрования, не совпадающими с ключом vault.

---

## Содержание (будет пополняться)

| Блок | Статус | Файлы |
|------|--------|--------|
| 1. ARC — архитектура | готово (каркас) | `src/core/import_export/` |
| 2. EXP — экспорт | готово | `exporter.py`, `formats/` |
| 3. IMP — импорт | готово | `importer.py`, `formats/` |
| 4. SHR — sharing | готово | `sharing_service.py` |
| 5. QR / key exchange | готово | `key_exchange.py`, `qr_code_service.py` |
| 6. CRY — протоколы sharing | готово | `share_crypto.py` |
| 7. UI — интерфейсы | готово | `src/gui/widgets/*_dialog.py` |
| 8. DB — схема | готово | `models.py`, `io_storage.py` |
| 9. FMT — форматы файлов | готово | `formats/native_json_format.py`, `share_json_format.py`, `csv_format.py` |
| 10. SEC — безопасность | готово | `import_security.py` |
| 11. TEST | готово | `test_sprint6_validation.py`, `test_sec_sprint6.py`, `test_fmt_sprint6.py` |
| 12. INT | готово | `io_integration.py`, `future_integrations.py`, EventBus `VaultShared` |
| 13. PERF / ERR | готово | `import_errors.py`, `import_checkpoint.py`, `test_perf_err_sprint6.py` |

---

## Блок 1 — ARC (Architecture)

### Соответствие примерам из ТЗ (преподаватель)

| Пример | Наш код |
|--------|---------|
| `VaultExporter(entry_manager, key_manager)` | `VaultExporter` + свойства `entry_manager`, `key_manager` |
| `_get_entries_for_export`, `_prepare_export_data` | реализовано |
| `_encrypt_with_password`, `_encrypt_with_public_key` | реализовано (+ hybrid hex для совместимости) |
| `SharingService.share_entry`, `_create_share_package` | реализовано; `create_share` сохранён |
| `QRCodeService.generate_qr_code`, `decode_qr_chunks` | реализовано; `generate_qr_images` для GUI |

### ARC-1 — структура каталога

**Требование:** пакет `src/core/import_export/` с модулями:

- `exporter.py` — экспорт vault с шифрованием  
- `importer.py` — импорт с проверкой и санитизацией  
- `sharing_service.py` — обмен одной записью  
- `key_exchange.py` — пары ключей для обмена  
- `formats/` — обработчики JSON, CSV и др.

**Решение:** создаём плоскую структуру как в `clipboard/` и `audit/`, без лишних подпакетов.  
В `formats/` — отдельные файлы `json_format.py`, `csv_format.py` (не десяток классов-наследников).

### ARC-2 — разделение ключей (key separation)

**Требование:** ключи import/export **не равны** мастер-ключу шифрования vault.

**Решение (как в Sprint 5 для audit export):**

1. Ключ vault: `PBKDF2(мастер-пароль, соль master_enc)` → `KeyManager.get_vault_encryption_key()`.
2. Ключи I/O: тот же пароль пользователя, но **другой контекст HKDF**:
   - `vault-export` — экспорт файла  
   - `vault-import` — импорт файла  
   - `vault-sharing` — пакет «поделиться записью»

Файл: `io_keys.py` — функции `derive_export_key`, `derive_import_key`, `derive_sharing_key`.

Для **конкретного файла** экспорта дополнительно случайная `export_salt` в метаданных пакета (отдельный ключ файла, EXP-4 — позже).

### ARC-3 — полный и выборочный экспорт

**Требование:** экспорт всего vault или выбранных записей.

**Решение:** в `VaultExporter.export_vault(entry_ids=None, ...)`:

- `entry_ids is None` → все записи через `EntryManager.get_all_entries()`  
- `entry_ids=[1, 2, 5]` → фильтр по `id` после загрузки

---

## Связь с прошлыми спринтами

| Спринт | Что используем |
|--------|----------------|
| 2 | PBKDF2, AES-GCM, `VaultEncryptionService` |
| 3 | `EntryManager`, расшифровка записей |
| 5 | паттерн HKDF + отдельный `info` для ключа (как `export-enc` в audit) |
| 1 | `EventBus` — события `VaultExported` / `VaultImported` (позже в EXP/IMP) |

---

## Блок 2 — EXP (Export)

### EXP-1 — форматы

| Формат | Параметр `fmt` | Поведение |
|--------|----------------|-----------|
| Encrypted JSON | `encrypted_json` (по умолчанию) | основной пакет + AES-GCM |
| CSV | `csv` + `encrypt_csv=False` | plaintext для миграции |
| CSV зашифрованный | `csv_encrypted` | тело CSV внутри AES-пакета |
| Bitwarden JSON | `bitwarden_json` | структура `items[]`, затем шифрование |

Файл Bitwarden: `formats/bw_json_format.py`.

### EXP-2 — encrypted JSON

- **AES-256-GCM** (или AES-128-GCM при `key_bits=128`), новый `nonce` и `salt` на каждый экспорт.
- Метаданные: `exported_at`, `version`, `source_application`, `export_mode`, `entry_count`.
- Шифрование: **пароль** (`export_password` + PBKDF2 с солью файла) или **публичный ключ** (`recipient_public_key_hex` — гибрид: случайный AES-ключ, обёртка PBKDF2 от pubkey).
- **Целостность:** SHA-256 от plaintext (до/после gzip — от сжатых байт).
- **Подпись:** HMAC-SHA256 с ключом `derive_export_key(export_password)` (контекст `vault-export`, не vault).

### EXP-3 — опции

| Опция | Параметр |
|-------|----------|
| Весь vault / выбор | `entry_ids=None` / `[1,2]` |
| Без notes | `include_notes=False` или `exclude_fields=["notes"]` |
| 128 / 256 бит | `key_bits=128` или `256` |
| GZIP | `compress=True` |

### EXP-4 — безопасность

| Требование | Реализация |
|------------|------------|
| Подтверждение мастер-пароля | `verify_master_password(master_password)` в начале `export_vault` |
| Новый ключ на экспорт | `os.urandom(16)` соль файла + новый nonce |
| Очистка temp | `export_vault_to_file` → `tempfile.mkstemp`, `unlink` в `finally` |
| Аудит | `get_event_bus().publish("VaultExported", …)` → подписчик аудита Sprint 5 |

Проверка ARC-2: сравниваем `vault_key` и `derive_export_key` — при равенстве `ValueError`.

### Пример вызова

```python
from src.core.import_export import VaultExporter

ex = VaultExporter()
pkg = ex.export_vault(
    None,
    master_password="...",
    export_password="отдельный-пароль-файла",
    fmt="encrypted_json",
    exclude_fields=["notes"],
    key_bits=256,
    compress=True,
)
# CSV plaintext (миграция):
csv_pkg = ex.export_vault(None, master_password="...", fmt="csv", encrypt_csv=False)
# в файл:
ex.export_vault_to_file("backup.enc.json", None, master_password="...", export_password="...")
```

---

## Блок 3 — IMP (Import)

### IMP-1 — форматы

| Формат | Как определяется | Парсер |
|--------|------------------|--------|
| Encrypted JSON (native) | `encryption` + `data` | `decrypt_package` → `parse_json_dict` |
| CSV | `csv_body` или сырой текст | `parse_csv_text_multi_dialect` (`,` и `;`) |
| Bitwarden JSON | `items[]` | `parse_bitwarden_json` |
| LastPass CSV | заголовок `name,url,username,password,extra` | `parse_lastpass_csv` |

Авто: `detect_format()`. Ручной: параметр `fmt` в `import_from_file`.

### IMP-2 — валидация

- **Шифрование:** `validate_encryption_block()` до `AESGCM.decrypt`.
- **Целостность:** SHA-256 plaintext = `integrity.hash`.
- **Подпись:** HMAC-SHA256 с `derive_export_key(import_password)` (как при экспорте).
- **Типы:** `validate_entry_constraints()` — все поля строки.
- **Санитизация:** `sanitize_text` / `sanitize_entry` (управляющие символы, `<script`).
- **Дубликаты:** ключ `(title, username)`; политики `skip` / `update` / `allow`.

### IMP-3 — режимы

| Режим | Константа | Поведение |
|-------|-----------|-----------|
| Merge | `MODE_MERGE` | новые → `create_entry`, дубликат → skip/update |
| Replace | `MODE_REPLACE` | `delete_entry` всех, затем create |
| Dry-run | `MODE_DRY_RUN` | только `preview`, без записи в БД |

### IMP-4 — безопасность

| Требование | Реализация |
|------------|------------|
| Песочница | `ImportSandbox` — лимит размера и `check_time()` каждые шаги |
| 10 MB | `DEFAULT_MAX_FILE_BYTES` |
| Таймаут 30 с | `DEFAULT_IMPORT_TIMEOUT_SEC` |
| Подтверждение мастер-пароля | `verify_master_password` в `apply_import` |
| Аудит | `VaultImported` через EventBus (не в dry-run) |

### Пример

```python
from src.core.import_export import VaultImporter, MODE_MERGE, MODE_DRY_RUN, DUP_UPDATE

imp = VaultImporter()
# предпросмотр:
preview = imp.import_from_file("backup.json", master_password="...", import_password="...", mode=MODE_DRY_RUN)
# импорт с обновлением дубликатов:
imp.import_from_file("backup.json", master_password="...", import_password="...", mode=MODE_MERGE, on_duplicate=DUP_UPDATE)
```

---

## Блок 4 — SHR (Secure Entry Sharing)

### SHR-1 — способы шифрования

| Метод | Константа | Реализация |
|-------|-----------|------------|
| Пароль | `METHOD_PASSWORD` | AES-256-GCM + PBKDF2 с `file_salt` (`vault-sharing`) |
| Публичный ключ | `METHOD_PUBLIC_KEY` | гибрид: AES + обёртка ключа через `recipient_public_key_hex` |
| Ссылка | `METHOD_LINK` | тот же пакет + блок `share_link` (token, `url_hint`, срок) |

Сеть не реализуем — только token и подсказка URL для учебного проекта.

### SHR-2 — формат пакета

- Только поля одной записи в `entry` (без других записей vault).
- Ключ **не** мастер-ключ vault — `derive_file_key_from_salt` / `derive_sharing_key`.
- Метаданные: `sharer`, `recipient`, `expires_at`, `permission`, `sender_public_key` (для ответа).
- `read_only` / `editable` — в metadata; при импорте передаётся в результат.

### SHR-3 — workflow

`create_share(entry_id, recipient, method=..., expire_days=1..30, ...)` — шаги 1–4.  
`share_to_file(path, entry_id, ...)` — шаг 5 (файл для передачи).

### SHR-4 — получатель

| Метод | Назначение |
|-------|------------|
| `open_share_package` | расшифровка + проверка срока/HMAC, **без** записи в БД |
| `import_shared_entry(..., save_to_vault=False)` | только просмотр в памяти |
| `import_shared_entry(..., save_to_vault=True)` | `create_entry` в vault (merge не трогает остальные записи) |

### Пример

```python
from src.core.import_export import SharingService, METHOD_PASSWORD, PERMISSION_READ_ONLY

svc = SharingService()
pkg = svc.create_share(
    1,
    recipient="user@example.com",
    method=METHOD_PASSWORD,
    share_password="отдельный-пароль-share",
    expire_days=7,
    permission=PERMISSION_READ_ONLY,
)
body = svc.open_share_package(pkg, share_password="отдельный-пароль-share")
svc.import_shared_entry(pkg, share_password="...", save_to_vault=True, master_password="...")
```

---

## Блок 6 — CRY (Cryptographic Protocols for Sharing)

### CRY-1 — пароль

- AES-256-GCM, случайная `salt`, PBKDF2 **100 000** итераций, параметры в `encryption`.
- `encrypt_password_package` / `decrypt_password_package`.

### CRY-2 — публичный ключ

| Ключ | Гибрид | Схема |
|------|--------|--------|
| RSA-2048 | `rsa_oaep_aes_gcm` | RSA-OAEP + AES-GCM |
| ECC P-256 | `ecies_ecdh_aes_gcm` | эфемерный ECDH + HKDF + AES-GCM |

`sender_public_key_pem` в пакете для ответа получателю.

### CRY-3 — forward secrecy (Should)

- Новый `sym_key` (RSA) или новая эфемерная EC-пара на каждый share.
- `ephemeral_public_key_pem` в пакете ECIES.

### CRY-4 — целостность

1. `verify_before_decrypt` — `tamper_evidence`, signature, integrity.  
2. AES decrypt.  
3. SHA-256 + HMAC (`share_password` или дефолт `vault-sharing-hmac`).

Файл: `share_crypto.py`.

---

## Блок 7 — UI (User Interface & Workflow)

### UI-1 — `export_dialog.py`

- Выбор формата + описание.
- Панель шифрования: пароль файла, 128/256 бит, GZIP, notes.
- Дерево записей с чекбоксами (все / выборочно).
- Предпросмотр перед сохранением.

Меню: **Данные → Экспорт...**

### UI-2 — `import_dialog.py`

- Автоопределение формата при выборе файла.
- Режим merge / replace / dry-run, политика дубликатов.
- Таблица предпросмотра, сводка изменений.

Меню: **Данные → Импорт...** (после импорта обновляется таблица).

### UI-3 — `sharing_dialog.py`

- Запись, получатель (контакты или новый).
- Права read/edit, срок 1–30 дней.
- Доставка: файл / QR / ссылка.
- История в `share_history_json` (settings).

Меню: **Данные → Поделиться записью...**

### UI-4 — `qr_viewer_dialog.py`

- Крупный QR (PNG), информация о payload.
- Копировать JSON, сохранить PNG.
- Таймер обновления (30 с), проверка `expires_at`.

---

## Блок 8 — DB (Database Schema Extensions)

Версия БД: **9** (`CURRENT_DB_VERSION = 9`), миграция `_migrate_v8_to_v9`.

### DB-1 — `shared_entries`

| Поле | Назначение |
|------|------------|
| `shared_id` | уникальный id share (PRIMARY KEY) |
| `original_entry_id` | id записи vault |
| `encryption_method` | password / public_key / link |
| `recipient_info` | получатель |
| `permissions` | read_only / editable |
| `shared_at`, `expires_at` | сроки |

Запись: `SharingService.create_share()` → `io_storage.insert_shared_entry()`.

### DB-2 — `import_export_history`

| Поле | Назначение |
|------|------------|
| `operation_type` | `export` / `import` |
| `file_format` | encrypted_json, csv, … |
| `encryption_used` | algorithm из пакета |
| `entry_count`, `file_size` | метаданные |
| `checksum`, `verification_status` | целостность (`ok`) |

Запись: `VaultExporter._log_export()`, `VaultImporter._log_import()`.

### DB-3 — `contacts`

| Поле | Назначение |
|------|------------|
| `contact_id`, `contact_name` | идентификатор |
| `public_key_pem`, `public_key_hex` | ключи |
| `key_fingerprint` | отпечаток |
| `last_used_at` | последнее использование |

`ContactList` в `key_exchange.py` читает/пишет через `io_storage` (вместо JSON файла).

Файл API: `src/database/io_storage.py`.

---

## Блок 9 — FMT (File Format Specifications)

### FMT-1 — нативный encrypted JSON

Файл: `formats/native_json_format.py` → `build_native_export_package()`.

```json
{
  "version": "1.0",
  "cryptosafe_export": true,
  "timestamp": "...",
  "encryption": { "algorithm", "key_derivation", "iterations", "salt", "nonce" },
  "data": "base64...",
  "integrity": { "hash": "sha256...", "signature": "hmac_hex..." }
}
```

Импорт: `is_native_export_package()`, подпись через `integrity.signature` (старый формат `signature.value` тоже читается).

### FMT-2 — share

Файл: `formats/share_json_format.py`.

- Зашифрованный: `cryptosafe_share`, `header.encrypted=true`, структура как FMT-1.
- Plaintext (учебный): `header.encrypted=false`, `entry` + `metadata`.
- Поля записи: `title`, `username`, `password`, `url`, `notes`.

### FMT-3 — CSV

Файл: `formats/csv_format.py`.

- Колонки: `title`, `username`, `password`, `URL`, `notes`.
- Экранирование: стандартный модуль `csv` (`QUOTE_MINIMAL`).
- Заголовок метаданных: `# cryptosafe-csv version=1.0 exported_at=...`.

---

## Блок 10 — SEC (Security Requirements)

| ID | Реализация |
|----|------------|
| SEC-1 | Экспорт по умолчанию `encrypted_json`; plaintext CSV только при `fmt="csv"` и `encrypt_csv=False`. |
| SEC-2 | `sanitize_text` / `sanitize_entry` в `importer.py`. |
| SEC-3 | HKDF `vault-export` / `vault-import` / `vault-sharing` в `io_keys.py`; проверка `keys_differ` в `exporter.py`. |
| SEC-4 | `wipe_sensitive()` в `import_security.py` — обнуление ключей и plaintext после encrypt/decrypt. |
| SEC-5 | `scan_import_text()` — шаблоны script/javascript/eval/powershell; CSV/plain JSON до разбора, расшифрованное тело после decrypt. |

Тесты: `tests/test_sec_sprint6.py`.

---

## Блок 12 — INT (Integration Points)

| ID | Реализация |
|----|------------|
| INT-1 | `EntryManager.find_entries_by_query`, `VaultExporter.export_vault_by_query` / `pick_entry_ids_by_query`. |
| INT-2 | EventBus: `VaultExported`, `VaultImported`, `VaultShared` (recipient, method) → аудит Sprint 5. |
| INT-3 | `io_integration.copy_share_link_to_clipboard`, `scan_qr_from_clipboard_image`; GUI: SharingDialog, QrViewerDialog. |
| INT-4 | `future_integrations.py` — заготовки CloudSync / NetworkShare (NotImplemented). |

Тесты: `tests/test_int_sprint6.py`.

---

## Блок 13–14 — PERF / ERR

| ID | Реализация |
|----|------------|
| PERF-1..2 | `test_perf_err_sprint6.py` — 1000 записей &lt;5 с / &lt;10 с |
| PERF-3 | QR без padding &lt;100 ms |
| PERF-4 | память: 2× файл + 6 MB (Python overhead) |
| ERR-1 | `ImportErrorReport`, `import_from_file_safe()` |
| ERR-2 | `import_checkpoint.py`, resume с `.import.ckpt.json` |
| ERR-3 | `resolve_import_format()`, ручной формат в `ImportDialog` |
| ERR-4 | `EncryptionDecryptError`, wipe plaintext при сбое decrypt |

---

## Следующие шаги

1. Доработки по желанию (облако/сеть — отдельный спринт).

---

## Файлы блока ARC (созданы)

```text
src/core/import_export/
├── __init__.py
├── io_keys.py           # ARC-2: HKDF vault-export / vault-import / vault-sharing
├── exporter.py          # ARC-3: export_vault(entry_ids=None | [ids])
├── importer.py          # санитизация, каркас merge
├── sharing_service.py   # одна запись, ключ sharing
├── key_exchange.py      # Ed25519 + payload для QR
└── formats/
    ├── __init__.py
    ├── json_format.py
    └── csv_format.py
```

### Как проверить ARC-3 вручную (после входа в приложение)

```python
from src.core.import_export import VaultExporter

ex = VaultExporter()
# весь vault:
pkg = ex.export_vault(None, master_password="...", export_password="...")
# только id 1 и 2:
pkg2 = ex.export_vault([1, 2], master_password="...", export_password="...")
```

---

*Обновлено: блок 9 FMT — спецификации JSON/CSV/share.*
