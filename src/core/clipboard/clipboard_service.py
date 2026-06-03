from __future__ import annotations

# Sprint 4: безопасный буфер обмена (копирование, мониторинг, автоочистка)

import ctypes
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Optional
from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.crypto.authentication import is_session_unlocked
from src.core.security.integration import log_security_hardening
from src.core.security.memory_guard import secure_wipe
from src.core.clipboard.platform_adapter import (
    ClipboardAdapter,
    PyperclipClipboardAdapter,
    create_platform_adapter,
)
from src.core.events import EventBus, get_event_bus

Observer = Callable[[str, dict[str, Any]], None]

@dataclass
class SecureClipboardItem:
    # текущий секрет в памяти + метаданные копирования
    """Публичный класс SecureClipboardItem."""
    masked_data: bytearray
    data_type: str
    source_entry_id: Optional[str]
    copied_at: datetime
    mask: bytearray
    clipboard_value: str = ""
    secure_locked: bool = False

    def secure_wipe(self) -> None:
        # INT-2: secure wipe буферов буфера обмена
        """Secure wipe."""
        if self.masked_data:
            secure_wipe(self.masked_data)
        if self.mask:
            secure_wipe(self.mask)
        self.data_type = ""
        self.source_entry_id = None
        self.masked_data = bytearray()
        self.mask = bytearray()
        self.clipboard_value = ""
        self.secure_locked = False

class ClipboardService:
    # основной сервис буфера обмена
    """Публичный класс ClipboardService."""
    DATA_TYPE_PASSWORD = "password"
    DATA_TYPE_USERNAME = "username"
    DATA_TYPE_NOTES = "notes"
    # задел под следующие спринты
    DATA_TYPE_TOTP = "totp"
    DATA_TYPE_ENCRYPTED_BLOB = "encrypted_blob"

    def _entry_id_from_source(self, source_entry_id: Optional[str]) -> Optional[int]:
        # строковый id записи vault → int для аудита
        try:
            if source_entry_id is None or source_entry_id == "":
                return None
            return int(source_entry_id)
        except Exception:
            return None

    def __init__(
        self,
        platform_adapter: Optional[ClipboardAdapter] = None,
        bus: Optional[EventBus] = None,
        config: Optional[dict[str, Any]] = None,
    ) -> None:
        # platform — ОС-адаптер, config — таймаут и политики
        self.platform = platform_adapter or create_platform_adapter()
        self._fallback_platform = PyperclipClipboardAdapter()
        self._bus = bus or get_event_bus()
        self._config = config or {}
        self._observers: list[Observer] = []
        self._monitor: Optional[ClipboardMonitor] = None
        self.current_content: Optional[SecureClipboardItem] = None
        self._ephemeral_content: Optional[SecureClipboardItem] = None
        self.timer: Optional[threading.Timer] = None
        self.lock = threading.RLock()
        self.last_notification = ""
        self._copy_blocked = False
        # SEC-2: сервис сразу подписан на блокировку сессии
        self._bus.subscribe("UserLoggedOut", self._on_user_logged_out, async_handler=False)

    def start(self) -> None:
        # запуск мониторинга системного буфера
        """Start."""
        try:
            if self._monitor is None:
                self._monitor = ClipboardMonitor(self.platform, self._on_clipboard_changed)
            self._monitor.start()
            self._bus.publish(
                "ClipboardMonitorStarted",
                {"source": "clipboard_service", "timestamp": datetime.utcnow().isoformat(timespec="seconds")},
            )
        except Exception:
            # ERR-3: если мониторинг не стартовал, работаем без него
            payload = {
                "operation": "monitor_start",
                "code": "monitor_unavailable",
                "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
            }
            self._bus.publish("ClipboardError", payload)
            self._notify("clipboard_warning", {"message": "Мониторинг буфера недоступен"})

    def stop(self) -> None:
        # аккуратно останавливаем монитор и очищаем буфер
        """Stop."""
        if self._monitor is not None:
            self._monitor.stop()
            self._bus.publish(
                "ClipboardMonitorStopped",
                {"source": "clipboard_service", "timestamp": datetime.utcnow().isoformat(timespec="seconds")},
            )
        self._clear_clipboard()

    def subscribe(self, observer: Observer) -> None:
        # observer-подписка для UI
        """Subscribe."""
        if observer not in self._observers:
            self._observers.append(observer)

    def unsubscribe(self, observer: Observer) -> None:
        # отписать UI от уведомлений буфера
        """Unsubscribe."""
        if observer in self._observers:
            self._observers.remove(observer)

    def copy_to_clipboard(
        self,
        data: str,
        data_type: str = "password",
        source_entry_id: Optional[str] = None,
    ) -> None:
        # безопасно копируем данные и ставим автоочистку
        """Copy to clipboard."""
        if not is_session_unlocked():
            raise PermissionError("сессия заблокирована")
        safe_type = self._validate_data_type(data_type)
        safe_data = self._sanitize_input(data)
        with self.lock:
            # MON-2: опция блокировки будущих копирований
            if self._copy_blocked:
                self._bus.publish(
                    "ClipboardCopyBlocked",
                    {
                        "reason": "suspicious_activity",
                        "entry_id": self._entry_id_from_source(source_entry_id),
                        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
                    },
                )
                raise PermissionError("копирование временно заблокировано")
            self._clear_clipboard()
            plain = bytearray(safe_data.encode("utf-8"))
            try:
                mask = bytearray(secrets.token_bytes(max(1, len(plain))))
                masked = self._xor_bytes(bytes(plain), mask)
            finally:
                secure_wipe(plain)
            self.current_content = SecureClipboardItem(
                masked_data=bytearray(masked),
                data_type=safe_type,
                source_entry_id=source_entry_id,
                copied_at=datetime.utcnow(),
                mask=mask,
            )
            self.current_content.secure_locked = self._try_lock_buffer(self.current_content.masked_data)
            # как в примере: в буфер кладем обфусцированное значение
            obfuscated = self._obfuscate_data(safe_data)
            self.current_content.clipboard_value = obfuscated
            copied = self.platform.copy_to_clipboard(obfuscated)
            if not copied:
                # ERR-1: fallback на pyperclip
                copied = self._fallback_platform.copy_to_clipboard(obfuscated)
            if not copied:
                self._bus.publish(
                    "ClipboardError",
                    {
                        "operation": "copy",
                        "code": "copy_failed",
                        "entry_id": self._entry_id_from_source(source_entry_id),
                        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
                    },
                )
                raise RuntimeError("не удалось скопировать в буфер обмена")

            timeout = self._normalize_timeout(int(self._config.get("clipboard_timeout", 30)))
            if timeout > 0:
                self.timer = threading.Timer(timeout, self._on_timeout)
                self.timer.daemon = True
                self.timer.start()

        payload = {
            "data_type": safe_type,
            "source_entry_id": source_entry_id,
            "entry_id": self._entry_id_from_source(source_entry_id),
            "timeout": timeout,
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        }
        self._bus.publish("ClipboardCopied", payload)
        self._notify("clipboard_copied", payload)
        self._show_notification(f"Скопировано в буфер: {data_type}")

    def copy_ephemeral(self, data: str, data_type: str = "password") -> None:
        # MON-4 (optional): копирование только в память, без системного буфера
        """Copy ephemeral."""
        if not is_session_unlocked():
            raise PermissionError("сессия заблокирована")
        safe_type = self._validate_data_type(data_type)
        safe_data = self._sanitize_input(data)
        with self.lock:
            plain = bytearray(safe_data.encode("utf-8"))
            try:
                mask = bytearray(secrets.token_bytes(max(1, len(plain))))
                masked = self._xor_bytes(bytes(plain), mask)
            finally:
                secure_wipe(plain)
            self._ephemeral_content = SecureClipboardItem(
                masked_data=bytearray(masked),
                data_type=safe_type,
                source_entry_id=None,
                copied_at=datetime.utcnow(),
                mask=mask,
            )
            self._ephemeral_content.secure_locked = self._try_lock_buffer(self._ephemeral_content.masked_data)
        self._notify("clipboard_ephemeral_copied", {"data_type": safe_type})

    def clear_clipboard(self) -> None:
        # внешний метод ручной очистки
        """Clear clipboard."""
        with self.lock:
            self._clear_clipboard()

    def _on_timeout(self) -> None:
        # автоочистка по таймауту
        source_entry_id = self.current_content.source_entry_id if self.current_content is not None else None
        with self.lock:
            self._clear_clipboard()

        payload = {
            "reason": "timeout",
            "entry_id": self._entry_id_from_source(source_entry_id),
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        }
        self._bus.publish("ClipboardCleared", payload)
        self._notify("clipboard_cleared", payload)
        self._show_notification("Буфер очищен автоматически")

    def _clear_clipboard(self) -> None:
        # очистка буфера и памяти
        if self.current_content is not None:
            cleared = self.platform.clear_clipboard()
            if not cleared:
                # ERR-1: fallback на pyperclip
                cleared = self._fallback_platform.clear_clipboard()
            if not cleared:
                # ERR-2/ERR-4: предупреждаем и логируем без данных секрета
                self._bus.publish(
                    "ClipboardError",
                    {
                        "operation": "clear",
                        "code": "clear_failed",
                        "entry_id": self._entry_id_from_source(self.current_content.source_entry_id),
                        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
                    },
                )
                self._notify(
                    "clipboard_warning",
                    {"message": "Не удалось очистить буфер автоматически. Очистите буфер вручную."},
                )
            was_locked = self.current_content.secure_locked
            buf = self.current_content.masked_data
            self.current_content.secure_wipe()
            if was_locked:
                self._try_unlock_buffer(buf)
            self.current_content = None
        if self._ephemeral_content is not None:
            was_locked = self._ephemeral_content.secure_locked
            buf = self._ephemeral_content.masked_data
            self._ephemeral_content.secure_wipe()
            if was_locked:
                self._try_unlock_buffer(buf)
            self._ephemeral_content = None

        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

    def get_clipboard_status(self) -> dict[str, Any]:
        # статус для UI
        """Get clipboard status."""
        with self.lock:
            if self.current_content is None:
                return {"active": False}

            remaining = self._get_remaining_time()
            return {
                "active": True,
                "data_type": self.current_content.data_type,
                "remaining_seconds": int(remaining.total_seconds()) if remaining is not None else 0,
                "source_entry_id": self.current_content.source_entry_id,
            }

    def get_clipboard_preview(self, masked: bool = True) -> dict[str, Any]:
        # UI-4: preview в статусе (маска + тип + источник)
        """Get clipboard preview."""
        with self.lock:
            if self.current_content is None:
                return {"active": False}
            value = self._decode_item(self.current_content)
            if masked:
                preview = self._mask_preview(value, self.current_content.data_type)
            else:
                preview = value
            return {
                "active": True,
                "preview": preview,
                "data_type": self.current_content.data_type,
                "source_entry_id": self.current_content.source_entry_id,
            }

    def set_timeout_seconds(self, timeout_seconds: int) -> None:
        # обновление таймаута из настроек GUI
        """Set timeout seconds."""
        with self.lock:
            self._config["clipboard_timeout"] = self._normalize_timeout(int(timeout_seconds))

    def _get_remaining_time(self) -> Optional[timedelta]:
        # сколько секунд до автоочистки
        if self.current_content is None:
            return None
        timeout = self._normalize_timeout(int(self._config.get("clipboard_timeout", 30)))
        if timeout == 0:
            return timedelta(seconds=0)
        expires_at = self.current_content.copied_at + timedelta(seconds=timeout)
        delta = expires_at - datetime.utcnow()
        if delta.total_seconds() < 0:
            return timedelta(seconds=0)
        return delta

    def copy_secret(self, text: str, ttl_seconds: int = 30) -> None:
        # совместимость со старым именем метода
        """Copy secret."""
        old = self._config.get("clipboard_timeout")
        self._config["clipboard_timeout"] = int(ttl_seconds)
        try:
            self.copy_to_clipboard(text, data_type="password")
        finally:
            if old is None:
                self._config.pop("clipboard_timeout", None)
            else:
                self._config["clipboard_timeout"] = old

    def _on_clipboard_changed(self, current_text: str) -> None:
        # мониторинг внешних изменений буфера
        reason = "external_change"
        source_entry_id = self.current_content.source_entry_id if self.current_content is not None else None
        with self.lock:
            if self.current_content is None:
                return
            if current_text == self.current_content.clipboard_value:
                return
            if not current_text:
                # MON-1: считаем это признаком внешнего доступа/чтения+очистки
                reason = "external_read"
            if self.timer is not None:
                self.timer.cancel()
                self.timer = None
            # MON-2: ускоренная очистка при подозрении
            self._clear_clipboard()
            # MON-2: опционально блокируем будущие копирования
            if bool(self._config.get("block_future_copies_on_suspicious", False)):
                self._copy_blocked = True

        payload = {
            "reason": reason,
            "entry_id": self._entry_id_from_source(source_entry_id),
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        }
        self._bus.publish("ClipboardSnoopingDetected", payload)
        self._bus.publish("ClipboardCleared", payload)
        self._notify("clipboard_external_change", payload)
        self._notify("clipboard_snooping_detected", payload)
        self._show_notification("Обнаружена подозрительная активность буфера")

    def _obfuscate_data(self, data: str) -> str:
        # простая обфускация XOR для хранения в буфере как hex
        if self.current_content is None:
            return data
        data_bytes = data.encode("utf-8")
        mask = self.current_content.mask
        mixed = self._xor_bytes(data_bytes, mask)
        return mixed.hex()

    def _decode_item(self, item: SecureClipboardItem) -> str:
        # SEC-2: plaintext достаем только по требованию
        if not item.masked_data or not item.mask:
            return ""
        plain = self._xor_bytes(bytes(item.masked_data), item.mask)
        try:
            return plain.decode("utf-8")
        except Exception:
            return ""

    def _xor_bytes(self, data: bytes, mask: bytearray) -> bytes:
        # XOR для маскирования секрета в памяти
        if not mask:
            return data
        return bytes([b ^ mask[i % len(mask)] for i, b in enumerate(data)])

    def _try_lock_buffer(self, buf: bytearray) -> bool:
        # SEC-1: non-pageable memory (best-effort)
        if not buf:
            return False
        try:
            ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
            addr = ctypes.addressof(ptr)
            size = ctypes.c_size_t(len(buf))
            if os.name == "nt":
                return bool(ctypes.windll.kernel32.VirtualLock(ctypes.c_void_p(addr), size))  # type: ignore[attr-defined]
            libc = ctypes.CDLL(None)
            if hasattr(libc, "mlock"):
                return int(libc.mlock(ctypes.c_void_p(addr), size)) == 0
        except Exception:
            return False
        return False

    def _try_unlock_buffer(self, buf: bytearray) -> bool:
        # снять блокировку страницы памяти (VirtualUnlock / munlock)
        if not buf:
            return False
        try:
            ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
            addr = ctypes.addressof(ptr)
            size = ctypes.c_size_t(len(buf))
            if os.name == "nt":
                return bool(ctypes.windll.kernel32.VirtualUnlock(ctypes.c_void_p(addr), size))  # type: ignore[attr-defined]
            libc = ctypes.CDLL(None)
            if hasattr(libc, "munlock"):
                return int(libc.munlock(ctypes.c_void_p(addr), size)) == 0
        except Exception:
            return False
        return False

    def _show_notification(self, text: str) -> None:
        # простая заглушка под UI-уведомления
        self.last_notification = str(text)

    def _on_user_logged_out(self, event_name: str, payload: Any) -> None:
        # SEC-3: при блокировке сессии чистим буфер сразу
        _ = event_name
        _ = payload
        self.force_clear(reason="vault_locked")

    def _notify(self, event_name: str, payload: dict[str, Any]) -> None:
        # уведомляем всех подписчиков observer
        for observer in list(self._observers):
            try:
                observer(event_name, payload)
            except Exception:
                continue

    def _cancel_timer(self) -> None:
        # оставлено для совместимости
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

    def clear_if_owned(self) -> bool:
        # совместимость с ранней версией сервиса
        """Clear if owned."""
        with self.lock:
            content = self.platform.get_clipboard_content() or ""
            if self.current_content is None:
                return False
            if content != self.current_content.clipboard_value:
                return False
            self._clear_clipboard()
            return True

    def force_clear(self, reason: str = "manual") -> None:
        # совместимость с ранней версией сервиса
        """Force clear."""
        source_entry_id = self.current_content.source_entry_id if self.current_content is not None else None
        with self.lock:
            self._clear_clipboard()
        payload = {
            "reason": reason,
            "entry_id": self._entry_id_from_source(source_entry_id),
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        }
        self._bus.publish("ClipboardCleared", payload)
        if reason == "panic":
            log_security_hardening("clipboard", "panic_clear", payload)
        self._notify("clipboard_cleared", payload)
        self._show_notification("Буфер очищен")

    def set_block_future_copies_on_suspicious(self, enabled: bool) -> None:
        # MON-2: настройка политики блокировки
        """Set block future copies on suspicious."""
        with self.lock:
            self._config["block_future_copies_on_suspicious"] = bool(enabled)

    def allow_future_copies(self) -> None:
        # ручной сброс блокировки копирования
        """Allow future copies."""
        with self.lock:
            self._copy_blocked = False

    def _arm_timer(self) -> None:
        # оставлено для совместимости
        timeout = self._normalize_timeout(int(self._config.get("clipboard_timeout", 30)))
        if timeout <= 0:
            return
        self.timer = threading.Timer(timeout, self._on_timeout)
        self.timer.daemon = True
        self.timer.start()

    def _normalize_timeout(self, value: int) -> int:
        # CLIP-2: 0 = never auto-clear, иначе диапазон 5..300
        v = int(value)
        if v <= 0:
            return 0
        if v < 5:
            return 5
        if v > 300:
            return 300
        return v

    def _validate_data_type(self, value: str) -> str:
        # SEC-4: простая валидация типа данных буфера
        data_type = str(value or "").strip().lower()
        allowed = {
            self.DATA_TYPE_PASSWORD,
            self.DATA_TYPE_USERNAME,
            self.DATA_TYPE_NOTES,
            self.DATA_TYPE_TOTP,
            self.DATA_TYPE_ENCRYPTED_BLOB,
        }
        if data_type in allowed:
            return data_type
        return self.DATA_TYPE_NOTES

    def _sanitize_input(self, value: Any) -> str:
        # SEC-4: базовая санитизация входа
        text = str(value)
        text = text.replace("\x00", "")
        # ограничиваем размер, чтобы не перегружать буфер и память
        if len(text) > 4096:
            text = text[:4096]
        return text

    def _mask_preview(self, value: str, data_type: str) -> str:
        # UI-4: маска содержимого для preview
        if not value:
            return ""
        if data_type == self.DATA_TYPE_PASSWORD:
            return "pas" + "•" * max(3, min(8, len(value)))
        if len(value) <= 4:
            return "•" * len(value)
        return value[:2] + "•" * (len(value) - 4) + value[-2:]

