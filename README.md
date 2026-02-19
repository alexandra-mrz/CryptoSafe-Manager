CryptoSafe Manager (проект по дисциплине "Методы и средства криптографической защиты информации")

Менеджер паролей с графическим интерфейсом, зашифрованной локальной базой данных и защищенной работой с буфером обмена 

Дорожная карта из 8 спринтов

1. Спринт 1 – базовая архитектура, БД, простое шифрование, GUI‑оболочка, события, тесты (то, что реализовано в этом репозитории).  
2. Спринт 2 
3. Спринт 3  
4. Спринт 4  
5. Спринт 5  
6. Спринт 6 
7. Спринт 7   
8. Спринт 8 

Инструкция по настройке создания виртуального окружения:

Создать виртуальное окружение (по желанию):
  ```bash
  python -m venv .venv
  .venv\Scripts\activate   # Windows
  ```
Установить зависимости:
  ```bash
  pip install -r requirements.txt
  ```
Запустить программу:
  ```bash
  python main.py
  ```
  При первом запуске откроется мастер создания учётной записи (логин + мастер‑пароль)
  и выбора файла базы данных. Потом откроется основное окно с таблицей записей.

Запустить тесты:
  ```bash
  python -m unittest discover tests/ -v
  ```
 

 Структура проекта

- `src/core/` – конфиг, криптография, события, состояние приложения  
- `src/gui/` – PyQt‑интерфейс (окно входа, мастер, главное окно, виджеты)  
- `src/database/` – схема SQLite и помощник для работы с БД  
- `tests/` – модульные и интеграционные тесты  
 
Результаты по итогу спринта 1

ARC (архитектура)  
  - Разделение на core/gui/database/tests: см. папки `src/*`, `tests/`.  
  - Менеджер конфигураций: `src/core/config.py` (`Config`, `get_config()`).  

DB (база данных) 
  - Таблицы `vault_entries`, `audit_log`, `settings`, `key_store`: `src/database/models.py`.  
  - Помощник БД и миграции (user_version): `src/database/db.py` (`DatabaseHelper`).  
  - Шифрование чувствительных полей при вставке: `src/database/vault_repository.py`.  

CRY (криптография)  
  - Абстрактный `EncryptionService`: `src/core/crypto/abstract.py`.  
  - Заглушка AES‑шифрования на XOR: `src/core/crypto/placeholder.py`.  
  - Заглушка `KeyManager`: `src/core/key_manager.py`.  

GUI 
  - Главное окно (меню, таблица, статус‑бар): `src/gui/main_window.py`.  
  - Окно входа (логин + пароль): `src/gui/login_dialog.py`.  
  - Мастер первого запуска (логин + пароль + повтор пароля + путь к БД): `src/gui/setup_wizard.py`.  
  - Виджеты `PasswordEntry`, `SecureTable`, `AuditLogViewer`: `src/gui/widgets/*.py`.  

Events / Audit / State 
  - Шина событий и типы событий: `src/core/events.py`.  
  - Заглушка журнала аудита: `src/core/audit_stub.py`.  
  - Менеджер состояния (сессия, буфер, таймеры): `src/core/state_manager.py`.  

Тесты и деплой
  - Тесты БД, крипто, событий, GUI‑импортов: файлы в `tests/`.  
  - Зависимости: `requirements.txt`.  
  - Dockerfile‑заглушка и CI workflow: `Dockerfile`, `.github/workflows/tests.yml`.  
