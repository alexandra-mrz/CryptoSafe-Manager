from __future__ import annotations

# Sprint 3 + Sprint 7 / INT-1, MEM-2: шифрование записей с wipe plaintext

import os
from datetime import datetime
import json
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.security.memory_guard import wipe_local


class VaultEncryptionService:
    # AES-256-GCM для записей vault.

    """Публичный класс VaultEncryptionService."""
    def encrypt_entry(
        self,
        entry: Dict[str, Any],
        key: bytes,
        *,
        created_at: Optional[str] = None,
        version: int = 1,
    ) -> bytes:
        """Зашифровать запись и вернуть nonce+ciphertext+tag."""
        if len(key) != 32:
            raise ValueError("ключ должен быть 32 байта (AES-256)")

        nonce = os.urandom(12)
        payload = {
            "v": int(version),
            "created_at": created_at or datetime.utcnow().isoformat(),
            "data": entry,
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        plain_buf = bytearray(data)
        try:
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, bytes(plain_buf), None)
            return nonce + ciphertext
        finally:
            wipe_local(plain_buf)  # INT-1 / MEM-2: не оставлять JSON в RAM

    def decrypt_entry(self, token: bytes, key: bytes) -> Dict[str, Any]:
        """Расшифровать запись и вернуть payload."""
        if len(key) != 32:
            raise ValueError("ключ должен быть 32 байта (AES-256)")

        if len(token) < 13:
            raise ValueError("слишком короткие данные")

        nonce = token[:12]
        ciphertext = token[12:]
        aesgcm = AESGCM(key)
        plain = aesgcm.decrypt(nonce, ciphertext, None)
        plain_buf = bytearray(plain)
        try:
            payload = json.loads(plain_buf.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("некорректный payload")
            return payload
        finally:
            wipe_local(plain_buf)  # INT-1 / MEM-2

