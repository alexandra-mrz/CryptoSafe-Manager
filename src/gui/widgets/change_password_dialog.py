from __future__ import annotations

from PyQt6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QProgressDialog,
)
from PyQt6.QtWidgets import QApplication

import binascii
import os

from src.core.crypto.authentication import (
    is_password_strong,
    verify_master_password,
    get_encryption_key,
)
from src.core.crypto.key_derivation import derive_key_argon2, derive_key_pbkdf2
from src.core.crypto.key_storage import save_key_metadata, cache_key
from src.core.crypto.placeholder import AES256Placeholder
from src.database.db import get_default_database

from .password_entry import PasswordEntry


class ChangePasswordDialog(QDialog):
    # диалог смены мастер-пароля (CHANGE-1)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Смена мастер-пароля")

        self.old_password = PasswordEntry(self)
        self.new_password = PasswordEntry(self)
        self.new_confirm = PasswordEntry(self)

        form = QFormLayout()
        form.addRow("Текущий пароль", self.old_password)
        form.addRow("Новый пароль", self.new_password)
        form.addRow("Подтверждение", self.new_confirm)

        buttons = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Отмена")
        self.ok_button.clicked.connect(self._on_ok)
        self.cancel_button.clicked.connect(self.reject)
        buttons.addStretch(1)
        buttons.addWidget(self.ok_button)
        buttons.addWidget(self.cancel_button)

        main = QVBoxLayout(self)
        main.addLayout(form)
        main.addLayout(buttons)

    def _on_ok(self) -> None:
        old_pwd = self.old_password.text()
        new_pwd = self.new_password.text()
        confirm = self.new_confirm.text()

        if not old_pwd or not new_pwd or not confirm:
            QMessageBox.warning(self, "Ошибка", "Все поля должны быть заполнены.")
            return

        if new_pwd != confirm:
            QMessageBox.warning(self, "Ошибка", "Новый пароль и подтверждение не совпадают.")
            return

        if not is_password_strong(new_pwd):
            QMessageBox.warning(self, "Ошибка", "Новый пароль слишком простой.")
            return

        try:
            self._rotate_keys(old_pwd, new_pwd)
        except ValueError as e:
            QMessageBox.warning(self, "Ошибка", str(e))
            return
        except Exception:
            QMessageBox.warning(self, "Ошибка", "Не удалось обновить шифрование.")
            return

        QMessageBox.information(self, "Готово", "Мастер-пароль успешно изменён.")
        self.accept()

    def _rotate_keys(self, old_password: str, new_password: str) -> None:
        # CHANGE-2: процесс ротации
        if not verify_master_password(old_password):
            raise ValueError("Текущий пароль неверный.")

        db = get_default_database()
        conn = db.create_connection()
        cipher = AES256Placeholder()

        try:
            cur = conn.cursor()
            cur.execute("SELECT id, encrypted_password FROM vault_entries")
            rows = cur.fetchall()
            total = len(rows)

            progress = QProgressDialog("Перешифрование записей...", "Отмена", 0, total, self)
            progress.setWindowTitle("Смена мастер-пароля")
            progress.setModal(True)

            # старый ключ шифрования берём из существующей соли (PBKDF2)
            old_key = get_encryption_key(old_password)

            salt_new = os.urandom(16)
            new_key = derive_key_pbkdf2(new_password, salt_new, length=32, iterations=100_000)

            conn.execute("BEGIN")

            for index, row in enumerate(rows):
                if progress.wasCanceled():
                    raise RuntimeError("отменено пользователем")

                entry_id = row["id"]
                enc_value = row["encrypted_password"]
                if enc_value:
                    try:
                        old_bytes = bytes.fromhex(enc_value)
                        plain = cipher.decrypt(old_bytes, old_key)
                        new_bytes = cipher.encrypt(plain, new_key)
                        cur.execute(
                            "UPDATE vault_entries SET encrypted_password = ? WHERE id = ?",
                            (new_bytes.hex(), entry_id),
                        )
                    except Exception:
                        raise

                progress.setValue(index + 1)
                QApplication.processEvents()

            conn.commit()

            # обновляем соли и хеши в key_store для нового пароля
            salt_auth = os.urandom(16)
            auth_key = derive_key_argon2(new_password, salt_auth)
            auth_hash_hex = binascii.hexlify(auth_key).decode("ascii")
            auth_salt_hex = binascii.hexlify(salt_auth).decode("ascii")
            auth_params = "argon2id_t3_m64mb_p4_32"
            save_key_metadata("master_auth", auth_salt_hex, auth_hash_hex, auth_params)
            cache_key("master_auth", auth_key)

            new_salt_hex = binascii.hexlify(salt_new).decode("ascii")
            enc_params = "pbkdf2_sha256_100000_32"
            save_key_metadata("master_enc", new_salt_hex, "", enc_params)
            cache_key("master_enc", new_key)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

