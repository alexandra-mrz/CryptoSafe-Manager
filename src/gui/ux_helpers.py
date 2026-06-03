from __future__ import annotations



# Sprint 7 / UX-2, UX-3; Sprint 8 / POL-3: сообщения без stack trace



import logging

import re

from typing import Callable, Optional, TypeVar



_log = logging.getLogger("cryptosafe.ui")



T = TypeVar("T")



# UX-3 / POL-3: код → (заголовок, подсказка) — только безопасный текст для пользователя

USER_HINTS: dict[str, tuple[str, str]] = {

    "vault_locked": ("Хранилище заблокировано.", "Меню «Вид» → разблокировать или введите мастер-пароль."),

    "load_failed": ("Не удалось загрузить записи.", "Проверьте мастер-пароль и целостность базы данных."),

    "save_failed": ("Не удалось сохранить запись.", "Проверьте подключение к базе и повторите попытку."),

    "delete_failed": ("Не удалось удалить запись.", "Повторите позже или перезапустите приложение."),

    "clipboard_failed": ("Не удалось скопировать в буфер.", "Проверьте настройки буфера и права доступа."),

    "import_failed": ("Импорт не выполнен.", "Проверьте формат файла и пароль импорта."),

    "export_failed": ("Экспорт не выполнен.", "Проверьте пароль файла и свободное место на диске."),

    "share_failed": ("Обмен записью не выполнен.", "Проверьте пароль share и выбранную запись."),

    "wrong_password": ("Неверный мастер-пароль.", "Проверьте раскладку клавиатуры и Caps Lock."),

    "empty_vault": ("Хранилище пусто.", "Создайте первую запись: Правка → Добавить (Ctrl+N)."),

    "no_selection": ("Запись не выбрана.", "Выберите строку в таблице и повторите действие."),

    "qr_failed": ("Не удалось обработать QR-код.", "Попробуйте другой QR или файл share.json."),

    "audit_export_failed": ("Не удалось экспортировать журнал.", "Проверьте мастер-пароль и права на запись файла."),

    "setup_failed": ("Не удалось завершить первый запуск.", "Проверьте пароль и путь к базе данных."),

    "change_password_failed": ("Не удалось сменить мастер-пароль.", "Проверьте текущий пароль и повторите."),

    "audit_access_denied": ("Нет доступа к журналу аудита.", "Разблокируйте хранилище или войдите с правами администратора."),

    "generic_error": ("Операция не выполнена.", "Повторите позже. Подробности — в логе приложения."),

}



_UNSAFE_DETAIL = re.compile(

    r"(Traceback|File \"|\.py\", line |Exception:|Error:|  at |\\src\\|/src/|site-packages)",

    re.IGNORECASE,

)





def _safe_message(text: str) -> str:

    """POL-3: убрать из UI следы traceback и путей к исходникам."""

    raw = str(text or "").strip()

    if not raw:

        return ""

    if _UNSAFE_DETAIL.search(raw):

        return ""

    if len(raw) > 240:

        return raw[:237] + "..."

    return raw





def exception_to_code(exc: BaseException) -> str:

    """Сопоставить исключение с кодом подсказки (POL-3 / POL-4)."""

    from src.core.import_export.import_errors import (

        EncryptionDecryptError,

        FormatDetectionError,

    )



    if isinstance(exc, PermissionError):

        return "vault_locked"

    if isinstance(exc, FormatDetectionError):

        return "import_failed"

    if isinstance(exc, EncryptionDecryptError):

        return "wrong_password"

    if isinstance(exc, FileNotFoundError):

        return "import_failed"

    if isinstance(exc, ValueError):

        msg = str(exc).lower()

        if any(k in msg for k in ("мастер", "master", "парол", "password", "неверн", "wrong")):

            return "wrong_password"

        if "пуст" in msg or "empty" in msg:

            return "empty_vault"

    return "generic_error"





def log_error(code: str, detail: Optional[str] = None) -> None:

    """UX-3: подробности в лог для отладки (может содержать exception repr)."""

    if detail:

        _log.error("[%s] %s", code, detail)

    else:

        _log.error("[%s]", code)





def show_user_error(parent, code: str, detail: Optional[str] = None) -> None:

    """UX-3 / POL-3: понятное сообщение пользователю; detail только в лог."""

    from PyQt6.QtWidgets import QMessageBox



    log_error(code, detail)

    title, hint = USER_HINTS.get(code, USER_HINTS["generic_error"])

    extra = _safe_message(detail or "")

    if extra and extra.lower() not in title.lower() and extra.lower() not in hint.lower():

        text = f"{title}\n\n{extra}\n\n{hint}"

    elif hint:

        text = f"{title}\n\n{hint}"

    else:

        text = title

    QMessageBox.warning(parent, "CryptoSafe", text)





def show_exception(parent, exc: BaseException, *, code: Optional[str] = None) -> None:

    """POL-3: показать ошибку без сырого stack trace."""

    use_code = code or exception_to_code(exc)

    log_error(use_code, repr(exc))

    show_user_error(parent, use_code, str(exc))





def show_user_info(parent, title: str, message: str) -> None:

    """Информационное сообщение (POL-4 edge cases)."""

    from PyQt6.QtWidgets import QMessageBox



    QMessageBox.information(parent, title, message)





def run_with_progress(parent, title: str, work: Callable[[], T]) -> T:

    """UX-2: индикатор для долгой операции."""

    from PyQt6.QtCore import Qt

    from PyQt6.QtWidgets import QApplication, QProgressDialog



    dlg = QProgressDialog(title, None, 0, 0, parent)

    dlg.setWindowModality(Qt.WindowModality.WindowModal)

    dlg.setMinimumDuration(400)

    dlg.show()

    app = QApplication.instance()

    if app is not None:

        app.processEvents()

    try:

        return work()

    finally:

        dlg.close()


