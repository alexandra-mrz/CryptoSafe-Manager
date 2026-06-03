from __future__ import annotations

# Sprint 6: связка share/QR с буфером обмена (INT-3)

import os
import tempfile
from pathlib import Path
from typing import Any, Optional

from datetime import datetime, timezone

from src.core.clipboard.clipboard_service import ClipboardService
from src.database import io_storage
from src.core.import_export.formats.share_json_format import is_share_package
from src.core.import_export.key_exchange import ContactRecord, KeyExchange
from src.core.import_export.qr_code_service import QRCodeService
from src.core.import_export.share_package_codec import decode_share_package_b64

SHARE_LINK_PREFIX = "cryptosafe://share/"
_PIP_HINT = "Установите в venv: pip install pyzbar Pillow qrcode[pil]"


def format_qr_scan_error(exc: BaseException) -> str:
    """Format qr scan error."""
    msg = str(exc).strip() or exc.__class__.__name__
    if isinstance(exc, ImportError):
        return f"{msg}\n\n{_PIP_HINT}"
    if isinstance(exc, RuntimeError) and any(
        k in msg.lower() for k in ("установите", "pyzbar", "qrcode", "pillow")
    ):
        return f"{msg}\n\n{_PIP_HINT}"
    if "истёк" in msg.lower() or "истек" in msg.lower():
        return (
            f"{msg}\n\n"
            "Срок QR обёртки — до 30 минут. "
            "Попросите новый QR или используйте файл share.json."
        )
    return msg


def extract_share_link(package: dict[str, Any]) -> str:
    # INT-3: URL из пакета share
    """Extract share link."""
    block = package.get("share_link") or {}
    if not isinstance(block, dict):
        return ""
    return str(block.get("url_hint", "") or block.get("url", "") or "")


def copy_share_link_to_clipboard(
    clipboard: ClipboardService,
    package: dict[str, Any],
    *,
    source_entry_id: Optional[int] = None,
) -> str:
    # INT-3: ссылка в буфер с автоочисткой (ClipboardService)
    """Copy share link to clipboard."""
    link = extract_share_link(package)
    if not link:
        raise ValueError("в пакете нет share_link")
    sid = str(source_entry_id) if source_entry_id is not None else None
    clipboard.copy_to_clipboard(
        link,
        data_type=ClipboardService.DATA_TYPE_NOTES,
        source_entry_id=sid,
    )
    return link


def scan_qr_from_png_bytes(qr: QRCodeService, png_bytes: bytes) -> dict[str, Any]:
    # INT-3: «сканирование» QR из PNG (в т.ч. изображение из буфера)
    """Scan qr from png bytes."""
    if not png_bytes:
        raise ValueError("пустое изображение QR")
    fd, path = tempfile.mkstemp(suffix=".clipboard_qr.png")
    os.close(fd)
    try:
        Path(path).write_bytes(png_bytes)
        return qr.scan_from_image_file(path)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def scan_qr_from_camera(
    qr: QRCodeService,
    *,
    timeout_sec: float = 15.0,
) -> dict[str, Any]:
    # QR-2: сканирование с камеры (opencv + pyzbar)
    """Scan qr from camera."""
    return qr.scan_from_camera(timeout_sec=timeout_sec)


def scan_qr_from_camera_with_hint(
    qr: QRCodeService,
    parent=None,
    *,
    timeout_sec: float = 15.0,
) -> dict[str, Any] | None:
    # UI: подсказка перед захватом кадра с камеры
    """Scan qr from camera with hint."""
    try:
        from PyQt6.QtWidgets import QMessageBox
    except ImportError:
        return scan_qr_from_camera(qr, timeout_sec=timeout_sec)
    if parent is not None:
        QMessageBox.information(
            parent,
            "Сканирование QR",
            f"Наведите камеру на QR-код.\nСканирование до {int(timeout_sec)} с.",
        )
    try:
        return scan_qr_from_camera(qr, timeout_sec=timeout_sec)
    except Exception as exc:
        if parent is not None:
            QMessageBox.warning(parent, "Ошибка камеры", format_qr_scan_error(exc))
        else:
            raise
    return None


def scan_qr_from_clipboard_image(qr: QRCodeService, image) -> dict[str, Any]:
    # INT-3: PyQt6 QImage → PNG bytes → pyzbar
    """Scan qr from clipboard image."""
    try:
        from PyQt6.QtCore import QBuffer, QIODevice
    except ImportError as exc:
        raise RuntimeError("нужен PyQt6 для QR из буфера") from exc
    buffer = QBuffer()
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    if not image.save(buffer, "PNG"):
        raise ValueError("не удалось сохранить изображение из буфера")
    png_bytes = bytes(buffer.data())
    return scan_qr_from_png_bytes(qr, png_bytes)


def parse_share_token(text: str) -> str:
    # token из cryptosafe://share/... или голого hex
    """Parse share token."""
    raw = str(text or "").strip()
    if raw.lower().startswith(SHARE_LINK_PREFIX):
        return raw[len(SHARE_LINK_PREFIX) :].strip()
    return raw


def extract_share_package_from_qr_body(body: dict[str, Any]) -> dict[str, Any] | None:
    # package из QR (package_b64 или локальный inbox по token)
    """Extract share package from qr body."""
    b64 = body.get("package_b64")
    if b64:
        return decode_share_package_b64(str(b64))
    kind = str(body.get("type", "") or "")
    if kind == "cryptosafe_share_link":
        token = str(body.get("token", "") or "").strip()
        if token:
            return io_storage.load_share_inbox_by_token(token)
    return None


def resolve_share_package_from_link(text: str) -> dict[str, Any] | None:
    # импорт по ссылке: на этом ПК пакет в share_inbox
    """Resolve share package from link."""
    token = parse_share_token(text)
    if not token:
        return None
    return io_storage.load_share_inbox_by_token(token)


def load_share_package_from_file(path: str | Path) -> dict[str, Any]:
    """Load share package from file."""
    import json

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("файл share должен быть JSON-объектом")
    if not is_share_package(data):
        raise ValueError("это не пакет cryptosafe_share")
    return data


def import_pubkey_contact_from_body(
    key_exchange: KeyExchange,
    body: dict[str, Any],
) -> ContactRecord:
    # QR-3: pubkey из отсканированного body → контакт в БД
    """Import pubkey contact from body."""
    if body.get("type") != "cryptosafe_pubkey":
        raise ValueError("QR не содержит публичный ключ контакта")
    contact_id = str(body.get("contact_id", "") or "").strip()
    if not contact_id:
        raise ValueError("в QR нет contact_id")
    contact = ContactRecord(
        contact_id=contact_id,
        algorithm=str(body.get("algorithm", "") or ""),
        public_key_pem=str(body.get("public_key_pem", "") or ""),
        public_key_hex=str(body.get("public_key_hex", "") or ""),
        fingerprint=str(body.get("fingerprint", "") or ""),
        added_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    if not contact.public_key_pem:
        raise ValueError("в QR нет public_key_pem")
    key_exchange.contacts.add_contact(contact)
    return contact


def format_qr_import_result(body: dict[str, Any], *, contact: ContactRecord | None = None) -> str:
    # текст результата для UI (без секретов)
    """Format qr import result."""
    kind = str(body.get("type", "") or "")
    if kind == "cryptosafe_pubkey" and contact is not None:
        return (
            f"Контакт добавлен: {contact.contact_id}\n"
            f"Алгоритм: {contact.algorithm}\n"
            f"Отпечаток: {contact.fingerprint}"
        )
    if kind in ("cryptosafe_share_link", "cryptosafe_encrypted_entry", "cryptosafe_share_package"):
        if extract_share_package_from_qr_body(body) is not None:
            return "В QR найден пакет share — нажмите «Импорт в vault»."
        return (
            "В QR нет полного пакета (только метаданные).\n"
            "Получите файл share.json, новый QR с пакетом или ссылку с этого же ПК."
        )
    raise ValueError(f"неизвестный тип QR: {kind or '?'}")


def process_scanned_qr_body(key_exchange: KeyExchange, body: dict[str, Any]) -> str:
    # импорт pubkey или пояснение для share-QR
    """Process scanned qr body."""
    kind = str(body.get("type", "") or "")
    if kind == "cryptosafe_pubkey":
        contact = import_pubkey_contact_from_body(key_exchange, body)
        return format_qr_import_result(body, contact=contact)
    if kind in ("cryptosafe_share_link", "cryptosafe_encrypted_entry", "cryptosafe_share_package"):
        return format_qr_import_result(body)
    raise ValueError(f"неизвестный тип QR: {kind or '?'}")
