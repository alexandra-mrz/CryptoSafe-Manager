from __future__ import annotations

# Sprint 6 / UI-4: просмотр и сканирование QR-кода

import json
from datetime import datetime, timezone
from typing import Any, Optional

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap, QImage
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QFileDialog,
    QApplication,
)

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.import_export.io_integration import (
    format_qr_import_result,
    import_pubkey_contact_from_body,
    process_scanned_qr_body,
    scan_qr_from_camera_with_hint,
    scan_qr_from_clipboard_image,
)
from src.core.import_export.key_exchange import KeyExchange
from src.core.import_export.qr_code_service import QRCodeService, DEFAULT_QR_VALID_MINUTES
from src.gui.ux_helpers import show_exception


class QrViewerDialog(QDialog):
    # показать QR без секретов в открытом виде

    """Публичный класс QrViewerDialog."""
    def __init__(
        self,
        parent=None,
        *,
        wrapped_payload: Optional[dict[str, Any]] = None,
        clipboard_service: Optional[ClipboardService] = None,
    ) -> None:
        # PNG, таймер обновления, скан из буфера
        super().__init__(parent)
        self.setWindowTitle("QR-код")
        self.resize(480, 560)
        self._qr = QRCodeService()
        self._key_exchange = KeyExchange()
        self._payload = wrapped_payload or {}
        self._payload_builder = None

        root = QVBoxLayout(self)

        self.chunk_hint = QLabel("", self)
        self.chunk_hint.setWordWrap(True)
        root.addWidget(self.chunk_hint)

        nav_row = QHBoxLayout()
        self.prev_qr_btn = QPushButton("◀", self)
        self.qr_page_label = QLabel("QR 1/1", self)
        self.next_qr_btn = QPushButton("▶", self)
        self.prev_qr_btn.clicked.connect(self._show_prev_qr)
        self.next_qr_btn.clicked.connect(self._show_next_qr)
        nav_row.addWidget(self.prev_qr_btn)
        nav_row.addWidget(self.qr_page_label, 1, Qt.AlignmentFlag.AlignCenter)
        nav_row.addWidget(self.next_qr_btn)
        root.addLayout(nav_row)

        self.qr_label = QLabel(self)
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_label.setMinimumHeight(280)
        root.addWidget(self.qr_label)

        root.addWidget(QLabel("Данные QR (без секретов):", self))
        self.info_text = QTextEdit(self)
        self.info_text.setReadOnly(True)
        self.info_text.setMaximumHeight(160)
        root.addWidget(self.info_text)

        btn_row = QHBoxLayout()
        self.copy_btn = QPushButton("Копировать JSON", self)
        self.save_btn = QPushButton("Сохранить PNG", self)
        self.save_all_btn = QPushButton("Сохранить все PNG", self)
        self.refresh_btn = QPushButton("Обновить QR", self)
        self.scan_clip_btn = QPushButton("QR из буфера", self)
        self.scan_cam_btn = QPushButton("QR с камеры", self)
        self.copy_btn.clicked.connect(self._copy_json)
        self.save_btn.clicked.connect(self._save_png)
        self.save_all_btn.clicked.connect(self._save_all_png)
        self.refresh_btn.clicked.connect(self._render_qr)
        self.scan_clip_btn.clicked.connect(self._scan_from_clipboard)
        self.scan_cam_btn.clicked.connect(self._scan_from_camera)
        btn_row.addWidget(self.copy_btn)
        btn_row.addWidget(self.save_btn)
        btn_row.addWidget(self.save_all_btn)
        btn_row.addWidget(self.refresh_btn)
        btn_row.addWidget(self.scan_clip_btn)
        btn_row.addWidget(self.scan_cam_btn)
        self._clipboard = clipboard_service
        root.addWidget(QLabel(f"Срок QR по умолчанию: {DEFAULT_QR_VALID_MINUTES} мин", self))
        root.addLayout(btn_row)

        close_btn = QPushButton("Закрыть", self)
        close_btn.clicked.connect(self.accept)
        root.addWidget(close_btn)

        self._png_images: list[bytes] = []
        self._qr_index = 0
        self._png_bytes: bytes = b""
        self._render_qr()
        self._fill_info()

        # UI-4: таймер для QR с ограниченным сроком
        self._timer = QTimer(self)
        self._timer.setInterval(30_000)
        self._timer.timeout.connect(self._on_timer)
        self._timer.start()

    def set_payload_builder(self, builder) -> None:
        # колбэк для пересборки payload (например новая ссылка)
        """Set payload builder."""
        self._payload_builder = builder

    def _fill_info(self) -> None:
        # показать только безопасные поля payload
        safe = {
            "type": self._payload.get("type"),
            "payload_type": self._payload.get("payload_type"),
            "expires_at": self._payload.get("expires_at"),
            "checksum": self._payload.get("checksum"),
            "body": self._payload.get("body"),
        }
        self.info_text.setPlainText(json.dumps(safe, ensure_ascii=False, indent=2))

    def _render_qr(self) -> None:
        # сгенерировать PNG (может быть несколько частей)
        try:
            images = self._key_exchange.generate_qr_images(self._payload)
            if not images:
                self.qr_label.setText("Не удалось создать QR")
                return
            self._png_images = images
            if self._qr_index >= len(self._png_images):
                self._qr_index = 0
            multi = len(self._png_images) > 1
            self.chunk_hint.setVisible(multi)
            if multi:
                self.chunk_hint.setText(
                    f"Запись в {len(self._png_images)} QR-кодах. "
                    "Листайте ◀ ▶ и сохраните все PNG для импорта на другом устройстве."
                )
            else:
                self.chunk_hint.setText("")
            self.prev_qr_btn.setEnabled(multi)
            self.next_qr_btn.setEnabled(multi)
            self.save_all_btn.setEnabled(multi)
            self._show_qr_at(self._qr_index)
        except Exception as exc:
            self.qr_label.setText(f"Ошибка QR: {exc}")

    def _show_qr_at(self, index: int) -> None:
        if not self._png_images:
            return
        self._qr_index = max(0, min(index, len(self._png_images) - 1))
        self._png_bytes = self._png_images[self._qr_index]
        self.qr_page_label.setText(f"QR {self._qr_index + 1}/{len(self._png_images)}")
        image = QImage.fromData(self._png_bytes)
        pix = QPixmap.fromImage(image)
        self.qr_label.setPixmap(pix.scaled(260, 260, Qt.AspectRatioMode.KeepAspectRatio))

    def _show_prev_qr(self) -> None:
        if self._png_images:
            self._show_qr_at((self._qr_index - 1) % len(self._png_images))

    def _show_next_qr(self) -> None:
        if self._png_images:
            self._show_qr_at((self._qr_index + 1) % len(self._png_images))

    def _on_timer(self) -> None:
        expires = str(self._payload.get("expires_at", "") or "")
        if not expires:
            return
        try:
            exp_dt = datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            return
        if datetime.now(timezone.utc) > exp_dt:
            self.qr_label.setText("QR истёк — обновите share")
            self._timer.stop()
            return
        if self._payload_builder is not None:
            try:
                self._payload = self._payload_builder()
                self._fill_info()
            except Exception:
                pass
        self._render_qr()

    def _copy_json(self) -> None:
        # копировать обёртку QR в системный буфер
        text = json.dumps(self._payload, ensure_ascii=False, indent=2)
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Копирование", "JSON скопирован в буфер.")

    def _show_scan_result(self, body: dict[str, Any], *, title: str) -> None:
        try:
            if str(body.get("type", "") or "") == "cryptosafe_pubkey":
                contact = import_pubkey_contact_from_body(self._key_exchange, body)
                QMessageBox.information(self, title, format_qr_import_result(body, contact=contact))
            else:
                QMessageBox.information(self, title, process_scanned_qr_body(self._key_exchange, body))
        except Exception as exc:
            show_exception(self, exc, code="qr_failed")

    def _scan_from_clipboard(self) -> None:
        clip = QApplication.clipboard()
        image = clip.image()
        if image.isNull():
            QMessageBox.warning(self, "Ошибка", "В буфере нет изображения QR.")
            return
        try:
            body = scan_qr_from_clipboard_image(self._qr, image)
        except Exception as exc:
            show_exception(self, exc, code="qr_failed")
            return
        self._show_scan_result(body, title="QR из буфера")

    def _scan_from_camera(self) -> None:
        body = scan_qr_from_camera_with_hint(self._qr, self, timeout_sec=15.0)
        if body is not None:
            self._show_scan_result(body, title="QR с камеры")

    def _save_png(self) -> None:
        if not self._png_bytes:
            QMessageBox.warning(self, "Ошибка", "Нет изображения QR.")
            return
        suffix = f"_{self._qr_index + 1}" if len(self._png_images) > 1 else ""
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить QR", f"qrcode{suffix}.png", "PNG (*.png)"
        )
        if not path:
            return
        with open(path, "wb") as fh:
            fh.write(self._png_bytes)
        QMessageBox.information(self, "Готово", f"Сохранено: {path}")

    def _save_all_png(self) -> None:
        if len(self._png_images) < 2:
            self._save_png()
            return
        folder = QFileDialog.getExistingDirectory(self, "Папка для всех QR")
        if not folder:
            return
        from pathlib import Path

        base = Path(folder)
        for idx, png in enumerate(self._png_images, start=1):
            (base / f"qrcode_part{idx}_of_{len(self._png_images)}.png").write_bytes(png)
        QMessageBox.information(
            self,
            "Готово",
            f"Сохранено {len(self._png_images)} файлов в:\n{folder}",
        )
