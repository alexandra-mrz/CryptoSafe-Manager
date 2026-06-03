from __future__ import annotations

# Sprint 6: общие помощники UI (мастер-пароль для import/export)

from typing import Optional

from PyQt6.QtWidgets import QInputDialog, QLineEdit, QMessageBox

from src.core.crypto.authentication import verify_master_password


def ask_master_password(parent) -> Optional[str]:
    # подтверждение мастер-пароля перед операцией
    """Ask master password."""
    pwd, ok = QInputDialog.getText(
        parent,
        "Мастер-пароль",
        "Введите мастер-пароль:",
        QLineEdit.EchoMode.Password,
    )
    if not ok:
        return None
    if not verify_master_password(pwd):
        QMessageBox.warning(parent, "Ошибка", "Неверный мастер-пароль.")
        return None
    return pwd
