from __future__ import annotations

# Sprint 6 / UI-1: диалог экспорта vault

import json
from pathlib import Path
from typing import Any, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QSpinBox,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from src.core.import_export.exporter import VaultExporter
from src.core.import_export.key_exchange import KeyExchange
from src.core.vault.entry_manager import EntryManager
from src.gui.ux_helpers import show_exception, show_user_error
from src.gui.widgets.password_entry import PasswordEntry

# описания форматов для UI-1
_FORMAT_HINTS = {
    "encrypted_json": "Основной формат CryptoSafe: JSON + AES-GCM.",
    "csv_encrypted": "CSV внутри зашифрованного пакета.",
    "csv": "CSV без шифрования (только для миграции).",
    "bitwarden_json": "Структура Bitwarden, затем шифрование.",
    "lastpass_csv": "CSV LastPass (name, url, username…) без шифрования — для импорта в LastPass.",
    "lastpass_csv_encrypted": "CSV LastPass внутри зашифрованного пакета CryptoSafe.",
}

_PLAINTEXT_FORMATS = frozenset({"csv", "lastpass_csv"})


class ExportDialog(QDialog):
    # выбор формата, записей, пароля файла и опционально публичного ключа

    """Публичный класс ExportDialog."""
    def __init__(self, parent=None, entry_manager: Optional[EntryManager] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Экспорт хранилища")
        self.resize(680, 580)
        self._entries = entry_manager or EntryManager()
        self._key_exchange = KeyExchange()
        self._all_rows: list[dict] = []

        root = QVBoxLayout(self)

        form = QFormLayout()
        self.format_combo = QComboBox(self)
        for key in _FORMAT_HINTS:
            self.format_combo.addItem(key, key)
        self.format_desc = QLabel(_FORMAT_HINTS["encrypted_json"], self)
        self.format_desc.setWordWrap(True)
        self.format_combo.currentIndexChanged.connect(self._on_format_changed)
        form.addRow("Формат:", self.format_combo)
        form.addRow("", self.format_desc)
        root.addLayout(form)

        enc_box = QGroupBox("Шифрование", self)
        enc_form = QFormLayout(enc_box)
        self.export_password = PasswordEntry(enc_box)
        self.key_bits = QSpinBox(enc_box)
        self.key_bits.setRange(128, 256)
        self.key_bits.setSingleStep(128)
        self.key_bits.setValue(256)
        self.compress_check = QCheckBox("Сжатие GZIP", enc_box)
        self.include_notes = QCheckBox("Включать заметки", enc_box)
        self.include_notes.setChecked(True)
        self.use_pubkey_check = QCheckBox("Шифровать публичным ключом получателя (EXP-2)", enc_box)
        self.contact_combo = QComboBox(enc_box)
        self.contact_combo.addItem("— ввести ключ вручную —", "")
        for contact in self._key_exchange.contacts.list_contacts():
            if contact.revoked:
                continue
            label = f"{contact.contact_id} ({contact.fingerprint})"
            self.contact_combo.addItem(label, contact.public_key_pem)
        self.contact_combo.currentIndexChanged.connect(self._on_contact_selected)
        self.recipient_pubkey = QPlainTextEdit(enc_box)
        self.recipient_pubkey.setPlaceholderText(
            "PEM (-----BEGIN PUBLIC KEY-----) или hex публичного ключа"
        )
        self.recipient_pubkey.setMaximumHeight(72)
        self.use_pubkey_check.toggled.connect(self._on_pubkey_mode_toggled)
        enc_form.addRow("Пароль файла:", self.export_password)
        enc_form.addRow("Ключ (бит):", self.key_bits)
        enc_form.addRow("", self.compress_check)
        enc_form.addRow("", self.include_notes)
        enc_form.addRow("", self.use_pubkey_check)
        enc_form.addRow("Контакт:", self.contact_combo)
        enc_form.addRow("Публичный ключ:", self.recipient_pubkey)
        root.addWidget(enc_box)
        self._on_pubkey_mode_toggled(False)

        tree_box = QGroupBox("Записи для экспорта", self)
        tree_layout = QVBoxLayout(tree_box)
        btn_row = QHBoxLayout()
        self.select_all_btn = QLabel("<a href='#'>Выбрать все</a>", self)
        self.select_none_btn = QLabel("<a href='#'>Снять все</a>", self)
        self.select_all_btn.linkActivated.connect(lambda _: self._set_all_checks(True))
        self.select_none_btn.linkActivated.connect(lambda _: self._set_all_checks(False))
        btn_row.addWidget(self.select_all_btn)
        btn_row.addWidget(self.select_none_btn)
        btn_row.addStretch(1)
        tree_layout.addLayout(btn_row)
        self.entry_tree = QTreeWidget(self)
        self.entry_tree.setHeaderLabels(["Запись"])
        tree_layout.addWidget(self.entry_tree)
        root.addWidget(tree_box)

        self.preview = QTextEdit(self)
        self.preview.setReadOnly(True)
        self.preview.setMaximumHeight(100)
        root.addWidget(QLabel("Предпросмотр:", self))
        root.addWidget(self.preview)

        preview_btn = QHBoxLayout()
        self.btn_preview = QLabel("<a href='#'>Обновить предпросмотр</a>", self)
        self.btn_preview.linkActivated.connect(lambda _: self._update_preview())
        preview_btn.addWidget(self.btn_preview)
        preview_btn.addStretch(1)
        root.addLayout(preview_btn)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        buttons.accepted.connect(self._on_export)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

        self._load_entries()
        self._update_preview()

    def _on_format_changed(self) -> None:
        key = self.format_combo.currentData()
        self.format_desc.setText(_FORMAT_HINTS.get(str(key), ""))
        fmt = str(key or "")
        plain = fmt in _PLAINTEXT_FORMATS
        self.export_password.setEnabled(not plain or self.use_pubkey_check.isChecked())
        if plain and not self.use_pubkey_check.isChecked():
            self.export_password.clear()

    def _on_pubkey_mode_toggled(self, enabled: bool) -> None:
        self.contact_combo.setEnabled(enabled)
        self.recipient_pubkey.setEnabled(enabled)
        fmt = str(self.format_combo.currentData() or "")
        self.export_password.setEnabled(enabled or fmt not in _PLAINTEXT_FORMATS)

    def _on_contact_selected(self) -> None:
        pem = str(self.contact_combo.currentData() or "")
        if pem:
            self.recipient_pubkey.setPlainText(pem)

    def _recipient_public_key(self) -> str:
        if not self.use_pubkey_check.isChecked():
            return ""
        return self.recipient_pubkey.toPlainText().strip()

    def _load_entries(self) -> None:
        self.entry_tree.clear()
        try:
            encrypted_total = len(self._entries.get_all_entries_encrypted())
            self._all_rows = self._entries.get_all_entries(skip_invalid=True)
        except Exception as exc:
            show_exception(self, exc, code="export_failed")
            self._all_rows = []
            return
        skipped = encrypted_total - len(self._all_rows)
        if skipped > 0:
            QMessageBox.warning(
                self,
                "Внимание",
                f"Пропущено записей с повреждёнными данными: {skipped} из {encrypted_total}.\n"
                "Они не попадут в экспорт.",
            )
        root_item = QTreeWidgetItem(["Все записи"])
        root_item.setFlags(root_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        root_item.setCheckState(0, Qt.CheckState.Checked)
        self.entry_tree.addTopLevelItem(root_item)
        for row in self._all_rows:
            title = str(row.get("title", "") or "")
            username = str(row.get("username", "") or "")
            entry_id = int(row.get("id", 0) or 0)
            label = f"[{entry_id}] {title} — {username}"
            item = QTreeWidgetItem([label])
            item.setData(0, Qt.ItemDataRole.UserRole, entry_id)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(0, Qt.CheckState.Checked)
            root_item.addChild(item)
        self.entry_tree.expandAll()

    def _set_all_checks(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        root = self.entry_tree.topLevelItem(0)
        if root is None:
            return
        root.setCheckState(0, state)
        for i in range(root.childCount()):
            root.child(i).setCheckState(0, state)

    def selected_entry_ids(self) -> Optional[list[int]]:
        """Selected entry ids."""
        root = self.entry_tree.topLevelItem(0)
        if root is None:
            return None
        ids: list[int] = []
        for i in range(root.childCount()):
            child = root.child(i)
            if child.checkState(0) == Qt.CheckState.Checked:
                entry_id = child.data(0, Qt.ItemDataRole.UserRole)
                if entry_id is not None:
                    ids.append(int(entry_id))
        if root.checkState(0) == Qt.CheckState.Checked and not ids:
            return None
        if len(ids) == len(self._all_rows):
            return None
        return ids

    def _update_preview(self) -> None:
        ids = self.selected_entry_ids()
        if ids is None:
            count = len(self._all_rows)
            mode = "весь vault"
        else:
            count = len(ids)
            mode = f"выбрано: {count}"
        fmt = self.format_combo.currentData()
        lines = [f"Режим: {mode}", f"Формат: {fmt}", f"Записей: {count}"]
        if self.use_pubkey_check.isChecked() and self._recipient_public_key():
            lines.append("Шифрование: публичный ключ получателя")
        if ids is not None:
            for row in self._all_rows:
                if int(row.get("id", 0)) in ids:
                    lines.append(f"  - {row.get('title', '')}")
        self.preview.setPlainText("\n".join(lines))

    def _on_export(self) -> None:
        if not self._all_rows:
            show_user_error(self, "empty_vault")
            return

        master = ask_master_password(self)
        if master is None:
            return

        fmt = str(self.format_combo.currentData())
        export_pwd = self.export_password.text()
        recipient = self._recipient_public_key()
        plain = fmt in _PLAINTEXT_FORMATS

        if self.use_pubkey_check.isChecked() and not recipient:
            QMessageBox.warning(self, "Ошибка", "Укажите публичный ключ получателя или выберите контакт.")
            return
        if not plain and not export_pwd and not recipient:
            QMessageBox.warning(self, "Ошибка", "Укажите пароль файла или публичный ключ получателя.")
            return

        if plain:
            default_name = "lastpass_export.csv" if fmt == "lastpass_csv" else "vault_export.csv"
            file_filter = "CSV (*.csv);;JSON (*.json)"
        else:
            default_name = "vault_export.json"
            file_filter = "JSON (*.json)"

        path, _ = QFileDialog.getSaveFileName(self, "Сохранить экспорт", default_name, file_filter)
        if not path:
            return

        save_path = Path(path)
        exporter = VaultExporter(self._entries)
        export_kw = dict(
            master_password=master,
            export_password=export_pwd,
            recipient_public_key_hex=recipient,
            fmt=fmt,
            include_notes=self.include_notes.isChecked(),
            key_bits=int(self.key_bits.value()),
            compress=self.compress_check.isChecked(),
            encrypt_csv=not plain,
        )
        try:
            if plain:
                pkg = exporter.export_vault(self.selected_entry_ids(), **export_kw)
                if save_path.suffix.lower() == ".csv":
                    save_path.write_text(str(pkg.get("csv_body", "") or ""), encoding="utf-8")
                else:
                    save_path.write_text(
                        json.dumps(pkg, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
            else:
                exporter.export_vault_to_file(save_path, self.selected_entry_ids(), **export_kw)
            QMessageBox.information(self, "Готово", f"Экспорт сохранён:\n{save_path}")
            self.accept()
        except Exception as exc:
            show_exception(self, exc, code="export_failed")
