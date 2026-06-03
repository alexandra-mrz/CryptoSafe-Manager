from __future__ import annotations

# Sprint 6 / UI-3: обмен записью — вкладки «Отправить» и «Получить»

import json
from typing import Any, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QScrollArea,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    QMessageBox,
    QFileDialog,
)

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.import_export.formats.share_json_format import is_share_package
from src.core.import_export.io_integration import (
    copy_share_link_to_clipboard,
    extract_share_link,
    extract_share_package_from_qr_body,
    format_qr_scan_error,
    load_share_package_from_file,
    resolve_share_package_from_link,
    scan_qr_from_camera_with_hint,
    scan_qr_from_clipboard_image,
)
from src.core.import_export.key_exchange import KeyExchange
from src.core.import_export.qr_code_service import QRCodeService
from src.core.import_export.sharing_service import (
    METHOD_LINK,
    METHOD_PASSWORD,
    METHOD_PUBLIC_KEY,
    PERMISSION_EDITABLE,
    PERMISSION_READ_ONLY,
    SharingService,
    entries_from_share_body,
)
from src.core.crypto.authentication import is_session_unlocked
from src.database import io_storage
from src.core.vault.entry_manager import EntryManager
from src.gui.ux_helpers import show_exception
from src.gui.widgets.io_ui_helpers import ask_master_password
from src.gui.widgets.password_entry import PasswordEntry
from src.gui.widgets.qr_viewer_dialog import QrViewerDialog


class SharingDialog(QDialog):
    """Публичный класс SharingDialog."""
    def __init__(
        self,
        parent=None,
        *,
        entry_id: Optional[int] = None,
        entry_ids: Optional[list[int]] = None,
        entry_manager: Optional[EntryManager] = None,
        clipboard_service: Optional[ClipboardService] = None,
        initial_tab: int = 0,
        initial_receive_package: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Обмен записью")
        self.resize(520, 500)
        self._entries = entry_manager or EntryManager()
        self._sharing = SharingService(self._entries)
        self._key_exchange = KeyExchange()
        self._clipboard = clipboard_service
        self._qr = QRCodeService()
        self._last_package: dict[str, Any] = {}
        if entry_ids:
            self._preselect_ids = [int(x) for x in entry_ids if int(x) > 0]
        elif entry_id is not None:
            self._preselect_ids = [int(entry_id)]
        else:
            self._preselect_ids = None
        self._recv_package: Optional[dict[str, Any]] = None
        self._recv_body: Optional[dict[str, Any]] = None
        self._recv_permission = PERMISSION_READ_ONLY
        self._recv_entries: list[dict[str, str]] = []
        self._all_rows: list[dict] = []

        root = QVBoxLayout(self)
        self._tabs = QTabWidget(self)
        self._tabs.addTab(self._wrap_scroll(self._build_share_tab()), "Отправить")
        self._tabs.addTab(self._wrap_scroll(self._build_receive_tab()), "Получить")
        self._tabs.setCurrentIndex(max(0, min(int(initial_tab), 1)))
        root.addWidget(self._tabs, 1)

        close_row = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        close_row.rejected.connect(self.reject)
        root.addWidget(close_row)

        if initial_receive_package is not None:
            self._tabs.setCurrentIndex(1)
            try:
                self._recv_set_package(initial_receive_package)
            except Exception as exc:
                show_exception(self, exc, code="share_failed")

    def _wrap_scroll(self, content: QWidget) -> QScrollArea:
        # прокрутка внутри вкладки — окно не растягивается на весь экран
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(content)
        return scroll

    def _build_share_tab(self) -> QWidget:
        page = QWidget(self)
        root = QVBoxLayout(page)

        entries_box = QGroupBox("Записи для share", page)
        entries_layout = QVBoxLayout(entries_box)
        pick_row = QHBoxLayout()
        pick_all = QLabel("<a href='#'>Выбрать все</a>", page)
        pick_none = QLabel("<a href='#'>Снять все</a>", page)
        pick_all.linkActivated.connect(lambda _: self._set_share_checks(True))
        pick_none.linkActivated.connect(lambda _: self._set_share_checks(False))
        pick_row.addWidget(pick_all)
        pick_row.addWidget(pick_none)
        pick_row.addStretch(1)
        entries_layout.addLayout(pick_row)
        self.share_entry_tree = QTreeWidget(page)
        self.share_entry_tree.setHeaderLabels(["Запись"])
        self.share_entry_tree.setMaximumHeight(110)
        entries_layout.addWidget(self.share_entry_tree)
        root.addWidget(entries_box)
        self._load_share_entries()

        form = QFormLayout()
        self.recipient_combo = QComboBox(page)
        self.recipient_combo.setEditable(True)
        self.recipient_combo.addItem("Новый получатель...", "")
        for contact in self._key_exchange.contacts.list_contacts():
            label = f"{contact.contact_id} ({contact.fingerprint})"
            self.recipient_combo.addItem(label, contact.contact_id)
        form.addRow("Получатель:", self.recipient_combo)

        self.method_combo = QComboBox(page)
        self.method_combo.addItem("Пароль", METHOD_PASSWORD)
        self.method_combo.addItem("Публичный ключ", METHOD_PUBLIC_KEY)
        self.method_combo.addItem("Ссылка + пароль", METHOD_LINK)
        form.addRow("Шифрование:", self.method_combo)

        self.permission_combo = QComboBox(page)
        self.permission_combo.addItem("Только чтение", PERMISSION_READ_ONLY)
        self.permission_combo.addItem("Можно редактировать", PERMISSION_EDITABLE)
        form.addRow("Права:", self.permission_combo)

        self.expire_days = QSpinBox(page)
        self.expire_days.setRange(1, 30)
        self.expire_days.setValue(7)
        form.addRow("Срок (дней):", self.expire_days)

        self.share_password = PasswordEntry(page)
        form.addRow("Пароль share:", self.share_password)
        root.addLayout(form)

        delivery = QGroupBox("Способ доставки", page)
        d_layout = QHBoxLayout(delivery)
        self.delivery_file = QRadioButton("Файл", delivery)
        self.delivery_qr = QRadioButton("QR-код", delivery)
        self.delivery_link = QRadioButton("Ссылка (token)", delivery)
        self.delivery_file.setChecked(True)
        d_layout.addWidget(self.delivery_file)
        d_layout.addWidget(self.delivery_qr)
        d_layout.addWidget(self.delivery_link)
        d_layout.addStretch(1)
        root.addWidget(delivery)

        hist_box = QGroupBox("История обмена", page)
        hist_layout = QVBoxLayout(hist_box)
        self.history_list = QListWidget(hist_box)
        self.history_list.setMaximumHeight(88)
        self._load_history()
        hist_layout.addWidget(self.history_list)
        root.addWidget(hist_box)

        share_btn = QPushButton("Создать share", page)
        share_btn.clicked.connect(self._on_share)
        root.addWidget(share_btn)
        return page

    def _build_receive_tab(self) -> QWidget:
        page = QWidget(self)
        root = QVBoxLayout(page)
        hint = QLabel(
            "Файл, QR или ссылка. При «только чтение» поля записи нельзя менять.",
            page,
        )
        hint.setWordWrap(True)
        root.addWidget(hint)

        src = QGroupBox("Откуда загрузить", page)
        sl = QVBoxLayout(src)
        self.recv_file = QRadioButton("Файл share.json", src)
        self.recv_qr = QRadioButton("QR-код", src)
        self.recv_link = QRadioButton("Ссылка", src)
        self.recv_file.setChecked(True)
        sl.addWidget(self.recv_file)
        sl.addWidget(self.recv_qr)
        sl.addWidget(self.recv_link)

        self.recv_file_row = QWidget(src)
        fr = QHBoxLayout(self.recv_file_row)
        fr.setContentsMargins(0, 0, 0, 0)
        self.recv_file_path = QLineEdit(self.recv_file_row)
        self.recv_file_path.setPlaceholderText("путь к share.json")
        browse = QPushButton("Обзор...", self.recv_file_row)
        browse.clicked.connect(self._recv_browse_file)
        fr.addWidget(self.recv_file_path)
        fr.addWidget(browse)
        sl.addWidget(self.recv_file_row)

        self.recv_qr_row = QWidget(src)
        qr_l = QHBoxLayout(self.recv_qr_row)
        qr_l.setContentsMargins(0, 0, 0, 0)
        qr_png = QPushButton("Выбрать PNG...", self.recv_qr_row)
        qr_clip = QPushButton("Из буфера (картинка)", self.recv_qr_row)
        qr_cam = QPushButton("С камеры", self.recv_qr_row)
        qr_png.clicked.connect(self._recv_qr_from_png)
        qr_clip.clicked.connect(self._recv_qr_from_clipboard)
        qr_cam.clicked.connect(self._recv_qr_from_camera)
        qr_l.addWidget(qr_png)
        qr_l.addWidget(qr_clip)
        qr_l.addWidget(qr_cam)
        sl.addWidget(self.recv_qr_row)

        self.recv_link_row = QWidget(src)
        lr = QHBoxLayout(self.recv_link_row)
        lr.setContentsMargins(0, 0, 0, 0)
        self.recv_link_edit = QLineEdit(self.recv_link_row)
        self.recv_link_edit.setPlaceholderText("cryptosafe://share/…")
        lr.addWidget(self.recv_link_edit)
        sl.addWidget(self.recv_link_row)

        for w in (self.recv_file_row, self.recv_qr_row, self.recv_link_row):
            w.setVisible(False)
        self.recv_file_row.setVisible(True)
        self.recv_file.toggled.connect(lambda c: self.recv_file_row.setVisible(c))
        self.recv_qr.toggled.connect(lambda c: self.recv_qr_row.setVisible(c))
        self.recv_link.toggled.connect(lambda c: self.recv_link_row.setVisible(c))

        load_pkg = QPushButton("Загрузить пакет", src)
        load_pkg.clicked.connect(self._recv_load_package)
        sl.addWidget(load_pkg)
        root.addWidget(src)

        creds = QGroupBox("Расшифровка", page)
        cf = QFormLayout(creds)
        self.recv_share_password = PasswordEntry(creds)
        self.recv_private_key = QLineEdit(creds)
        self.recv_private_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.recv_private_key.setPlaceholderText("только для share по публичному ключу")
        cf.addRow("Пароль share:", self.recv_share_password)
        cf.addRow("Приватный ключ:", self.recv_private_key)
        show_btn = QPushButton("Показать данные", creds)
        show_btn.clicked.connect(self._recv_show_data)
        cf.addRow("", show_btn)
        root.addWidget(creds)

        self.recv_permission_label = QLabel("Права: —", page)
        self.recv_permission_label.setWordWrap(True)
        root.addWidget(self.recv_permission_label)

        self.recv_entry_list = QListWidget(page)
        self.recv_entry_list.setMaximumHeight(56)
        self.recv_entry_list.currentRowChanged.connect(self._recv_on_pick_entry)
        self.recv_entry_list.setVisible(False)
        root.addWidget(self.recv_entry_list)

        meta_box = QGroupBox("Сведения о share", page)
        mf = QFormLayout(meta_box)
        self.recv_sharer = QLineEdit(meta_box)
        self.recv_recipient = QLineEdit(meta_box)
        self.recv_expires = QLineEdit(meta_box)
        self.recv_encryption = QLineEdit(meta_box)
        for w in (self.recv_sharer, self.recv_recipient, self.recv_expires, self.recv_encryption):
            w.setReadOnly(True)
        mf.addRow("Отправитель:", self.recv_sharer)
        mf.addRow("Получатель:", self.recv_recipient)
        mf.addRow("Действует до:", self.recv_expires)
        mf.addRow("Шифрование:", self.recv_encryption)
        root.addWidget(meta_box)

        view = QGroupBox("Запись из share", page)
        vf = QFormLayout(view)
        self.recv_title = QLineEdit(view)
        self.recv_username = QLineEdit(view)
        self.recv_password = QLineEdit(view)
        self.recv_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.recv_url = QLineEdit(view)
        self.recv_category = QLineEdit(view)
        self.recv_tags = QLineEdit(view)
        self.recv_notes = QTextEdit(view)
        self.recv_notes.setMaximumHeight(56)
        vf.addRow("Название:", self.recv_title)
        vf.addRow("Логин:", self.recv_username)
        vf.addRow("Пароль:", self.recv_password)
        vf.addRow("URL:", self.recv_url)
        vf.addRow("Категория:", self.recv_category)
        vf.addRow("Теги:", self.recv_tags)
        vf.addRow("Заметки:", self.recv_notes)
        self._recv_set_fields_enabled(False)
        root.addWidget(view)

        self.recv_meta = QLabel("", page)
        self.recv_meta.setWordWrap(True)
        root.addWidget(self.recv_meta)

        save_btn = QPushButton("Сохранить выбранные в мой vault", page)
        save_btn.clicked.connect(self._recv_save_to_vault)
        root.addWidget(save_btn)
        return page

    def _recv_set_fields_enabled(self, enabled: bool) -> None:
        for w in (
            self.recv_title,
            self.recv_username,
            self.recv_password,
            self.recv_url,
            self.recv_category,
            self.recv_tags,
            self.recv_notes,
        ):
            w.setEnabled(enabled)

    def _recv_apply_field_policy(self) -> None:
        editable = self._recv_permission == PERMISSION_EDITABLE
        for w in (
            self.recv_title,
            self.recv_username,
            self.recv_password,
            self.recv_url,
            self.recv_notes,
        ):
            w.setReadOnly(not editable)
        if self._recv_permission == PERMISSION_READ_ONLY:
            self.recv_permission_label.setText(
                "Права: только чтение — просмотр разрешён, изменять поля нельзя."
            )
        else:
            self.recv_permission_label.setText(
                "Права: можно редактировать — перед сохранением в vault можно изменить поля."
            )

    def _load_share_entries(self) -> None:
        self.share_entry_tree.clear()
        try:
            self._all_rows = self._entries.get_all_entries(skip_invalid=True)
        except Exception as exc:
            show_exception(self, exc, code="load_failed")
            self._all_rows = []
            return
        root_item = QTreeWidgetItem(["Все записи"])
        root_item.setFlags(root_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        root_item.setCheckState(0, Qt.CheckState.Checked)
        self.share_entry_tree.addTopLevelItem(root_item)
        preselect = set(self._preselect_ids or [])
        for row in self._all_rows:
            eid = int(row.get("id", 0) or 0)
            title = str(row.get("title", "") or "")
            username = str(row.get("username", "") or "")
            item = QTreeWidgetItem([f"[{eid}] {title} — {username}"])
            item.setData(0, Qt.ItemDataRole.UserRole, eid)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            if not preselect or eid in preselect:
                item.setCheckState(0, Qt.CheckState.Checked)
            else:
                item.setCheckState(0, Qt.CheckState.Unchecked)
            root_item.addChild(item)
        if not preselect:
            root_item.setCheckState(0, Qt.CheckState.Checked)
        self.share_entry_tree.expandAll()

    def _set_share_checks(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        root = self.share_entry_tree.topLevelItem(0)
        if root is None:
            return
        root.setCheckState(0, state)
        for i in range(root.childCount()):
            root.child(i).setCheckState(0, state)

    def _selected_share_entry_ids(self) -> list[int]:
        root = self.share_entry_tree.topLevelItem(0)
        if root is None:
            return []
        ids: list[int] = []
        for i in range(root.childCount()):
            child = root.child(i)
            if child.checkState(0) == Qt.CheckState.Checked:
                eid = child.data(0, Qt.ItemDataRole.UserRole)
                if eid is not None:
                    ids.append(int(eid))
        return ids

    def _load_history(self) -> None:
        self.history_list.clear()
        for row in io_storage.list_shared_entries(limit=30):
            text = (
                f"{row.get('shared_at', '')} | запись {row.get('original_entry_id')} | "
                f"{row.get('recipient_info')} | {row.get('permissions')} | до {row.get('expires_at', '')}"
            )
            self.history_list.addItem(text)

    def _on_share(self) -> None:
        if not is_session_unlocked():
            QMessageBox.warning(self, "Ошибка", "Сначала разблокируйте vault.")
            return
        entry_ids = self._selected_share_entry_ids()
        if not entry_ids:
            QMessageBox.warning(self, "Ошибка", "Выберите хотя бы одну запись.")
            return
        recipient = self.recipient_combo.currentText().strip()
        if not recipient:
            QMessageBox.warning(self, "Ошибка", "Укажите получателя.")
            return
        method = str(self.method_combo.currentData())
        share_pwd = self.share_password.text()
        if method in (METHOD_PASSWORD, METHOD_LINK) and not share_pwd:
            QMessageBox.warning(self, "Ошибка", "Укажите пароль share.")
            return

        recipient_pubkey = ""
        contact = self._key_exchange.contacts.get_contact(recipient)
        if method == METHOD_PUBLIC_KEY:
            if contact is None or contact.revoked:
                QMessageBox.warning(self, "Ошибка", "Выберите контакт с публичным ключом.")
                return
            recipient_pubkey = contact.public_key_pem

        try:
            package = self._sharing.create_share(
                entry_ids,
                recipient,
                method=method,
                share_password=share_pwd,
                recipient_public_key_pem=recipient_pubkey,
                expire_days=int(self.expire_days.value()),
                permission=str(self.permission_combo.currentData()),
                include_link=self.delivery_link.isChecked() or method == METHOD_LINK,
            )
            self._last_package = package

            if self.delivery_file.isChecked():
                path, _ = QFileDialog.getSaveFileName(
                    self, "Сохранить share", "share.json", "JSON (*.json)"
                )
                if path:
                    with open(path, "w", encoding="utf-8") as fh:
                        json.dump(package, fh, ensure_ascii=False, indent=2)
                    QMessageBox.information(self, "Готово", f"Файл: {path}")

            link = extract_share_link(package)
            if link and self._clipboard is not None and (
                self.delivery_link.isChecked() or method == METHOD_LINK
            ):
                copy_share_link_to_clipboard(
                    self._clipboard,
                    package,
                    source_entry_id=entry_id,
                )

            if self.delivery_qr.isChecked() or self.delivery_link.isChecked():
                try:
                    if package.get("share_link"):
                        wrapped = self._key_exchange.share_link_qr_payload(
                            package["share_link"],
                            package=package,
                        )
                    else:
                        wrapped = self._key_exchange.encrypted_entry_qr_payload(package)
                except ValueError as qr_exc:
                    QMessageBox.warning(
                        self,
                        "QR",
                        f"{qr_exc}\n\nShare создан — используйте «Файл» или «Ссылка».",
                    )
                    wrapped = None
                if wrapped is not None:
                    QrViewerDialog(
                        self, wrapped_payload=wrapped, clipboard_service=self._clipboard
                    ).exec()

            perm = str(self.permission_combo.currentData())
            n = len(entry_ids)
            hint = (
                f"В пакете {n} запис(ей/и).\n"
                "Получатель: вкладка «Получить» → QR / файл / ссылка → пароль share → «Показать данные»."
            )
            if perm == PERMISSION_READ_ONLY:
                hint += "\n(права: только чтение.)"
            if n > 3:
                hint += "\nМного записей — надёжнее «Файл», чем QR."
            QMessageBox.information(self, "Share создан", hint)
        except Exception as exc:
            show_exception(self, exc, code="share_failed")

    def _recv_browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Файл share", "", "JSON (*.json);;Все (*.*)"
        )
        if path:
            self.recv_file_path.setText(path)

    def _recv_resolve_package_from_qr_body(self, body: dict[str, Any]) -> Optional[dict[str, Any]]:
        if body.get("type") == "cryptosafe_pubkey":
            QMessageBox.information(
                self,
                "QR",
                "Это QR публичного ключа контакта, не share записи.",
            )
            return None
        package = extract_share_package_from_qr_body(body)
        if package is None:
            QMessageBox.warning(
                self,
                "QR",
                "В QR нет пакета share. Используйте свежий QR или файл .json.",
            )
        return package

    def _recv_qr_from_png(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "QR изображение",
            "",
            "Изображения (*.png *.jpg *.jpeg *.bmp);;Все (*.*)",
        )
        if not path:
            return
        try:
            body = self._qr.scan_from_image_file(path)
        except Exception as exc:
            QMessageBox.warning(self, "Ошибка", format_qr_scan_error(exc))
            return
        pkg = self._recv_resolve_package_from_qr_body(body)
        if pkg:
            self._recv_set_package(pkg)

    def _recv_qr_from_clipboard(self) -> None:
        image = QApplication.clipboard().image()
        if image.isNull():
            QMessageBox.warning(self, "Ошибка", "В буфере нет изображения QR.")
            return
        try:
            body = scan_qr_from_clipboard_image(self._qr, image)
        except Exception as exc:
            QMessageBox.warning(self, "Ошибка", format_qr_scan_error(exc))
            return
        pkg = self._recv_resolve_package_from_qr_body(body)
        if pkg:
            self._recv_set_package(pkg)

    def _recv_qr_from_camera(self) -> None:
        body = scan_qr_from_camera_with_hint(self._qr, self, timeout_sec=15.0)
        if body is None:
            return
        pkg = self._recv_resolve_package_from_qr_body(body)
        if pkg:
            self._recv_set_package(pkg)

    def _recv_load_package(self) -> None:
        try:
            if self.recv_file.isChecked():
                path = self.recv_file_path.text().strip()
                if not path:
                    QMessageBox.warning(self, "Ошибка", "Укажите файл share.json.")
                    return
                self._recv_set_package(load_share_package_from_file(path))
            elif self.recv_qr.isChecked():
                QMessageBox.information(
                    self,
                    "QR",
                    "Нажмите «Выбрать PNG» или «Из буфера» для загрузки QR.",
                )
            elif self.recv_link.isChecked():
                pkg = resolve_share_package_from_link(self.recv_link_edit.text())
                if pkg is None:
                    QMessageBox.warning(
                        self,
                        "Ссылка",
                        "Пакет не найден на этом ПК.\n"
                        "С другого устройства используйте QR или файл .json.",
                    )
                    return
                self._recv_set_package(pkg)
        except Exception as exc:
            show_exception(self, exc, code="share_failed")

    def _recv_set_package(self, package: dict[str, Any]) -> None:
        if not is_share_package(package):
            raise ValueError("ожидался пакет cryptosafe_share")
        self._recv_package = package
        self._recv_body = None
        ids = package.get("entry_ids")
        if isinstance(ids, list) and len(ids) > 1:
            meta = f"Пакет: {len(ids)} записей."
        else:
            meta = f"Пакет: запись {package.get('entry_id', '')}."
        self.recv_meta.setText(f"{meta} Введите пароль share и нажмите «Показать данные».")

    def _recv_sync_fields_to_list(self) -> None:
        if not self._recv_entries or self.recv_entry_list.currentRow() < 0:
            return
        idx = self.recv_entry_list.currentRow()
        self._recv_entries[idx] = self._recv_entry_from_fields()

    def _recv_fill_fields(self, entry: dict[str, str]) -> None:
        self.recv_title.setText(str(entry.get("title", "") or ""))
        self.recv_username.setText(str(entry.get("username", "") or ""))
        self.recv_password.setText(str(entry.get("password", "") or ""))
        self.recv_url.setText(str(entry.get("url", "") or ""))
        self.recv_category.setText(str(entry.get("category", "") or ""))
        self.recv_tags.setText(str(entry.get("tags", "") or ""))
        self.recv_notes.setPlainText(str(entry.get("notes", "") or ""))

    def _recv_on_pick_entry(self, row: int) -> None:
        if row < 0 or row >= len(self._recv_entries):
            return
        if self._recv_permission == PERMISSION_EDITABLE:
            self._recv_sync_fields_to_list()
        self._recv_fill_fields(self._recv_entries[row])

    def _recv_show_data(self) -> None:
        if self._recv_package is None:
            QMessageBox.warning(self, "Ошибка", "Сначала загрузите пакет.")
            return
        enc = (
            self._recv_package.get("encryption")
            if isinstance(self._recv_package.get("encryption"), dict)
            else {}
        )
        mode = str(enc.get("mode", "") or "")
        share_pwd = self.recv_share_password.text()
        priv = self.recv_private_key.text().strip()
        if mode == METHOD_PUBLIC_KEY and not priv:
            QMessageBox.warning(self, "Ошибка", "Нужен ваш приватный ключ.")
            return
        if mode != METHOD_PUBLIC_KEY and not share_pwd:
            QMessageBox.warning(self, "Ошибка", "Укажите пароль share.")
            return
        try:
            body = self._sharing.open_share_package(
                self._recv_package,
                share_password=share_pwd,
                recipient_private_key_pem=priv,
            )
        except Exception as exc:
            show_exception(self, exc, code="share_failed")
            return

        self._recv_body = body
        self._recv_permission = str(
            body.get("permission", PERMISSION_READ_ONLY) or PERMISSION_READ_ONLY
        )
        self._recv_entries = [
            {
                "title": str(e.get("title", "") or ""),
                "username": str(e.get("username", "") or ""),
                "password": str(e.get("password", "") or ""),
                "url": str(e.get("url", "") or ""),
                "notes": str(e.get("notes", "") or ""),
                "category": str(e.get("category", "") or ""),
                "tags": str(e.get("tags", "") or ""),
            }
            for e in entries_from_share_body(body)
        ]
        self.recv_entry_list.blockSignals(True)
        self.recv_entry_list.clear()
        for entry in self._recv_entries:
            self.recv_entry_list.addItem(
                f"{entry.get('title', '')} — {entry.get('username', '')}"
            )
        multi = len(self._recv_entries) > 1
        self.recv_entry_list.setVisible(multi)
        if self._recv_entries:
            self.recv_entry_list.setCurrentRow(0)
        self.recv_entry_list.blockSignals(False)
        self._recv_fill_fields(self._recv_entries[0] if self._recv_entries else {})
        self._recv_set_fields_enabled(True)
        self._recv_apply_field_policy()
        self.recv_sharer.setText(str(body.get("sharer", "") or ""))
        self.recv_recipient.setText(str(body.get("recipient", "") or ""))
        self.recv_expires.setText(str(body.get("expires_at", "") or ""))
        enc = self._recv_package.get("encryption") if isinstance(self._recv_package, dict) else {}
        enc_mode = ""
        if isinstance(enc, dict):
            enc_mode = str(enc.get("mode", "") or enc.get("algorithm", "") or "")
        self.recv_encryption.setText(enc_mode)
        n = len(self._recv_entries)
        self.recv_meta.setText(f"Загружено записей: {n}")

    def _recv_entry_from_fields(self) -> dict[str, str]:
        return {
            "title": self.recv_title.text().strip(),
            "username": self.recv_username.text().strip(),
            "password": self.recv_password.text(),
            "url": self.recv_url.text().strip(),
            "notes": self.recv_notes.toPlainText(),
            "category": self.recv_category.text().strip(),
            "tags": self.recv_tags.text().strip(),
        }

    def _recv_save_to_vault(self) -> None:
        if self._recv_package is None or self._recv_body is None:
            QMessageBox.warning(self, "Ошибка", "Сначала «Показать данные».")
            return
        master = ask_master_password(self)
        if master is None:
            return
        if self._recv_permission == PERMISSION_EDITABLE:
            self._recv_sync_fields_to_list()
        to_save = list(self._recv_entries)
        if not to_save:
            QMessageBox.warning(self, "Ошибка", "Нет записей для сохранения.")
            return
        created_ids: list[int] = []
        try:
            for entry in to_save:
                created = self._entries.create_entry(entry, master_password=master)
                created_ids.append(int(created.id))
        except Exception as exc:
            show_exception(self, exc, code="share_failed")
            return
        if len(created_ids) == 1:
            msg = f"Сохранена 1 запись (id {created_ids[0]})."
        else:
            msg = f"Сохранено записей: {len(created_ids)} (id: {', '.join(map(str, created_ids))})."
        QMessageBox.information(self, "Готово", msg)
        self.accept()
