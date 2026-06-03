from __future__ import annotations

# Sprint 6: QR-коды (QR-1..QR-4 — генерация, сканирование, срок действия)

import base64
import hashlib
import json
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

# QR-1: уровень коррекции для печати/сканирования
try:
    import qrcode
    from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M

    _HAS_QRCODE = True
except ImportError:
    qrcode = None
    ERROR_CORRECT_L = 0
    ERROR_CORRECT_M = 0
    _HAS_QRCODE = False

# QR-2: чтение из файла картинки
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    from PIL import Image

    _HAS_PYZBAR = True
except ImportError:
    pyzbar_decode = None
    Image = None
    _HAS_PYZBAR = False

# типы payload (QR-1)
PAYLOAD_PUBKEY = "pubkey"
PAYLOAD_SHARE_LINK = "share_link"
PAYLOAD_ENCRYPTED_ENTRY = "encrypted_entry"

DEFAULT_QR_VALID_MINUTES = 5
# лимит UTF-8 для одного QR (EC-L, version до 40); без дробления на chunks
_MAX_SINGLE_QR_UTF8_BYTES = 2900
# внутренний порог для _chunk_texts (только pubkey/legacy, не share)
_CHUNK_MAX_BYTES = 2400


def _utc_now_iso() -> str:
    # метка времени UTC для QR
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _expires_iso(minutes: int = DEFAULT_QR_VALID_MINUTES) -> str:
    # срок действия QR в ISO 8601
    dt = datetime.now(timezone.utc) + timedelta(minutes=int(minutes))
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class QRCodeService:
    # обёртка payload: checksum, nonce, срок (QR-4)

    """Публичный класс QRCodeService."""
    def __init__(self, *, valid_minutes: int = DEFAULT_QR_VALID_MINUTES) -> None:
        # valid_minutes — срок жизни обёртки payload
        self._valid_minutes = int(valid_minutes)

    def build_wrapped_payload(
        self,
        payload_type: str,
        body: dict[str, Any],
        *,
        valid_minutes: Optional[int] = None,
    ) -> dict[str, Any]:
        # QR-4: без plaintext-секретов — в body только ссылки/публичные данные
        """Build wrapped payload."""
        minutes = self._valid_minutes if valid_minutes is None else int(valid_minutes)
        inner = json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
        checksum = hashlib.sha256(inner).hexdigest()[:16]
        import secrets

        return {
            "type": "cryptosafe_qr",
            "payload_type": str(payload_type),
            "created_at": _utc_now_iso(),
            "expires_at": _expires_iso(minutes),
            "nonce": secrets.token_hex(8),
            "checksum": checksum,
            "body": body,
        }

    def validate_wrapped_payload(self, data: dict[str, Any]) -> dict[str, Any]:
        # QR-2 / QR-4: checksum, срок, nonce
        """Validate wrapped payload."""
        if data.get("type") != "cryptosafe_qr":
            raise ValueError("неизвестный тип QR")
        expires = str(data.get("expires_at", "") or "")
        if expires:
            try:
                exp_dt = datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp_dt:
                    raise ValueError("QR истёк")
            except ValueError as exc:
                if "QR истёк" in str(exc):
                    raise
        body = data.get("body")
        if not isinstance(body, dict):
            raise ValueError("нет body")
        inner = json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
        expected = str(data.get("checksum", "") or "")
        actual = hashlib.sha256(inner).hexdigest()[:16]
        if expected and actual != expected:
            raise ValueError("checksum QR не совпадает")
        return body

    def generate_qr_code(self, data: bytes, chunk_size: int = 2953) -> list[str]:
        # как в примере: сжать и разбить на chunk JSON-строки
        """Generate qr code."""
        compressed = zlib.compress(data)
        chunks: list[str] = []
        total = (len(compressed) + chunk_size - 1) // chunk_size
        if total < 1:
            total = 1
        for index in range(total):
            start = index * chunk_size
            part = compressed[start : start + chunk_size]
            piece = {
                "chunk": index + 1,
                "total": total,
                "data": base64.b64encode(part).decode("ascii"),
                "checksum": hashlib.sha256(part).hexdigest()[:8],
            }
            chunks.append(json.dumps(piece, ensure_ascii=False, sort_keys=True))
        return chunks

    def decode_qr_chunks(self, chunks: list[str]) -> Optional[bytes]:
        # собрать фрагменты → zlib → байты
        """Decode qr chunks."""
        validated: list[tuple[int, bytes]] = []
        for chunk_str in chunks:
            try:
                chunk_data = json.loads(chunk_str)
            except json.JSONDecodeError:
                return None
            raw = base64.b64decode(str(chunk_data.get("data", "") or ""))
            check = hashlib.sha256(raw).hexdigest()[:8]
            if check != str(chunk_data.get("checksum", "") or ""):
                return None
            validated.append((int(chunk_data.get("chunk", 0)), raw))
        if not validated:
            return None
        validated.sort(key=lambda item: item[0])
        merged = b"".join(item[1] for item in validated)
        try:
            return zlib.decompress(merged)
        except zlib.error:
            return None

    def _chunk_texts(self, text: str) -> list[str]:
        # обёртка cryptosafe (type) для внутреннего формата
        raw = text.encode("utf-8")
        chunks = self.generate_qr_code(raw, chunk_size=_CHUNK_MAX_BYTES)
        wrapped: list[str] = []
        for piece in chunks:
            data = json.loads(piece)
            data["type"] = "cryptosafe_qr_chunk"
            wrapped.append(json.dumps(data, ensure_ascii=False, sort_keys=True))
        return wrapped

    @staticmethod
    def payload_json_bytes(payload: dict[str, Any]) -> bytes:
        # компактный JSON — больше данных в одном QR
        """Payload json bytes."""
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    def assert_fits_single_qr(self, payload: dict[str, Any]) -> None:
        # до генерации: share не должен дробиться
        """Assert fits single qr."""
        size = len(self.payload_json_bytes(payload))
        if size > _MAX_SINGLE_QR_UTF8_BYTES:
            raise ValueError(
                f"данные слишком большие для одного QR ({size} байт). "
                "Используйте «Файл» или «Ссылка»."
            )

    def generate_qr_images(self, payload: dict[str, Any], *, allow_chunks: bool = False) -> list[bytes]:
        # один QR на экран; allow_chunks — только для больших pubkey (не share)
        """Generate qr images."""
        if not _HAS_QRCODE:
            raise RuntimeError("установите пакет qrcode: pip install qrcode[pil]")
        text = self.payload_json_bytes(payload).decode("utf-8")
        raw_len = len(text.encode("utf-8"))
        if allow_chunks and raw_len > _CHUNK_MAX_BYTES:
            texts = self._chunk_texts(text)
        else:
            if raw_len > _MAX_SINGLE_QR_UTF8_BYTES:
                raise ValueError(
                    f"данные слишком большие для одного QR ({raw_len} байт). "
                    "Используйте «Файл» или «Ссылка»."
                )
            texts = [text]
        images: list[bytes] = []
        ec = ERROR_CORRECT_M if allow_chunks and len(texts) > 1 else ERROR_CORRECT_L
        for part in texts:
            qr = qrcode.QRCode(version=None, error_correction=ec, box_size=6, border=4)
            qr.add_data(part)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            import io

            buf = io.BytesIO()
            img.save(buf, format="PNG")
            images.append(buf.getvalue())
        return images

    def decode_chunk_texts(self, chunk_texts: list[str]) -> Optional[str]:
        # собрать chunks (cryptosafe_qr_chunk или формат преподавателя)
        """Decode chunk texts."""
        plain_chunks: list[str] = []
        for text in chunk_texts:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return None
            if data.get("type") == "cryptosafe_qr_chunk":
                data.pop("type", None)
            plain_chunks.append(json.dumps(data, sort_keys=True))
        raw = self.decode_qr_chunks(plain_chunks)
        if raw is None:
            return None
        return raw.decode("utf-8")

    def parse_scanned_text(self, text: str) -> dict[str, Any]:
        # QR-2: разбор текста со сканера (целиком или по фрагментам)
        """Parse scanned text."""
        cleaned = (text or "").strip()
        if not cleaned:
            raise ValueError("пустой QR")
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise ValueError("некорректный QR JSON") from exc
        if not isinstance(data, dict):
            raise ValueError("QR должен быть объектом JSON")
        if data.get("type") == "cryptosafe_qr_chunk":
            full = self.decode_chunk_texts([cleaned])
            if not full:
                raise ValueError("не удалось собрать chunk")
            data = json.loads(full)
        if not isinstance(data, dict):
            raise ValueError("некорректный собранный QR")
        body = self.validate_wrapped_payload(data)
        return body

    def decode_from_image_file(self, file_path: str) -> list[str]:
        # QR-2: загрузка картинки с QR
        """Decode from image file."""
        if not _HAS_PYZBAR:
            raise RuntimeError("установите pyzbar и Pillow: pip install pyzbar Pillow")
        img = Image.open(file_path)
        codes = pyzbar_decode(img)
        texts: list[str] = []
        for code in codes:
            try:
                texts.append(code.data.decode("utf-8"))
            except Exception:
                continue
        return texts

    @staticmethod
    def _dedupe_chunk_texts(chunk_parts: list[str]) -> list[str]:
        by_index: dict[int, str] = {}
        for text in chunk_parts:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            idx = int(data.get("chunk", 0) or 0)
            if idx > 0:
                by_index[idx] = text
        return [by_index[k] for k in sorted(by_index)]

    @staticmethod
    def _chunk_parts_from_texts(texts: list[str]) -> list[str]:
        return [t for t in texts if "cryptosafe_qr_chunk" in t]

    def _assemble_chunk_qr(self, chunk_parts: list[str]) -> dict[str, Any]:
        deduped = self._dedupe_chunk_texts(chunk_parts)
        if not deduped:
            raise ValueError("ошибка сборки QR chunks")
        try:
            total_expected = max(int(json.loads(t).get("total", 1) or 1) for t in deduped)
        except (json.JSONDecodeError, ValueError):
            total_expected = len(deduped)
        if len(deduped) < total_expected:
            raise ValueError(
                f"найдено частей QR: {len(deduped)} из {total_expected}. "
                "Отсканируйте все PNG (кнопка «Несколько PNG») или используйте файл share.json."
            )
        full = self.decode_chunk_texts(deduped)
        if not full:
            raise ValueError(
                "ошибка сборки QR chunks — проверьте, что все части от одного QR и не повреждены"
            )
        data = json.loads(full)
        return self.validate_wrapped_payload(data)

    def scan_from_decoded_texts(self, texts: list[str]) -> dict[str, Any]:
        # QR-2: собрать все распознанные строки (в т.ч. из нескольких PNG)
        """Scan from decoded texts."""
        if not texts:
            raise ValueError("QR не найден")
        chunk_parts = self._chunk_parts_from_texts(texts)
        if chunk_parts:
            return self._assemble_chunk_qr(chunk_parts)
        return self.parse_scanned_text(texts[0])

    def scan_from_image_file(self, file_path: str) -> dict[str, Any]:
        """Scan from image file."""
        texts = self.decode_from_image_file(file_path)
        if not texts:
            raise ValueError("QR на изображении не найден")
        return self.scan_from_decoded_texts(texts)

    def scan_from_image_files(self, file_paths: list[str]) -> dict[str, Any]:
        # несколько PNG с частями одного QR
        """Scan from image files."""
        if not _HAS_PYZBAR:
            raise RuntimeError("установите pyzbar и Pillow: pip install pyzbar Pillow")
        all_texts: list[str] = []
        for path in file_paths:
            all_texts.extend(self.decode_from_image_file(path))
        if not all_texts:
            raise ValueError("QR на изображениях не найден")
        return self.scan_from_decoded_texts(all_texts)

    def scan_from_camera(self, timeout_sec: float = 5.0) -> dict[str, Any]:
        # QR-2: камера если доступна (opencv)
        """Scan from camera."""
        try:
            import cv2
        except ImportError as exc:
            raise RuntimeError("камера недоступна: установите opencv-python") from exc

        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            cap.release()
            raise RuntimeError("не удалось открыть камеру")
        import time

        deadline = time.monotonic() + float(timeout_sec)
        last_error = "QR не распознан"
        try:
            while time.monotonic() < deadline:
                ok, frame = cap.read()
                if not ok:
                    continue
                if not _HAS_PYZBAR:
                    last_error = "pyzbar не установлен"
                    break
                codes = pyzbar_decode(frame)
                texts = []
                for code in codes:
                    try:
                        texts.append(code.data.decode("utf-8"))
                    except Exception:
                        pass
                if texts:
                    chunk_parts = [t for t in texts if '"cryptosafe_qr_chunk"' in t]
                    if chunk_parts:
                        full = self.decode_chunk_texts(chunk_parts)
                        if full:
                            data = json.loads(full)
                            return self.validate_wrapped_payload(data)
                    return self.parse_scanned_text(texts[0])
        finally:
            cap.release()
        raise ValueError(last_error)
