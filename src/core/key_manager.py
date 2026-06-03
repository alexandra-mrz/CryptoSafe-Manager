
from __future__ import annotations

# KeyManager для Sprint 2/3: ключ шифрования хранится в кэше в памяти.
# На диск ключ не пишем. Если ключа нет в кэше, можно пересчитать через мастер-пароль.

from typing import Optional

from src.core.crypto.authentication import get_encryption_key, is_session_unlocked
from src.core.crypto.key_storage import get_cached_key

class KeyManager:
    """Публичный класс KeyManager."""
    def get_vault_encryption_key(self, master_password: str = "") -> bytes:
        # ARC-3: операции хранилища должны использовать ключ шифрования из кэша KeyManager.
        """Get vault encryption key."""
        if not is_session_unlocked():
            raise PermissionError("сессия заблокирована")

        key = get_cached_key("master_enc")
        if key is not None:
            return key

        if not master_password:
            raise PermissionError("ключ не в кэше (нужен мастер-пароль)")

        return get_encryption_key(master_password)
