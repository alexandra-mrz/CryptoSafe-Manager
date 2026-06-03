from __future__ import annotations

# Sprint 6: ключи import/export (ARC-2 — отдельный HKDF от vault)

import binascii

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.core.crypto.key_derivation import derive_key_pbkdf2
from src.core.crypto.key_storage import load_key_metadata

_ENC_KEY_TYPE = "master_enc"

# контексты HKDF — не совпадают с vault и audit
_HKDF_EXPORT = b"vault-export"
_HKDF_IMPORT = b"vault-import"
_HKDF_SHARING = b"vault-sharing"


def _get_master_salt() -> bytes:
    # соль master_enc из БД (та же база PBKDF2, другой info в HKDF)
    info = load_key_metadata(_ENC_KEY_TYPE)
    if info is None:
        return b""
    try:
        return binascii.unhexlify(info["salt"].encode("ascii"))
    except (binascii.Error, KeyError, TypeError):
        return b""


def _derive_io_key(password: str, info: bytes) -> bytes:
    # ARC-2: базовый ключ от пароля, затем HKDF с отдельным info
    salt = _get_master_salt()
    base = derive_key_pbkdf2(password, salt, length=32, iterations=100_000)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(base)


def derive_export_key(password: str) -> bytes:
    # ключ шифрования пакета экспорта (не ключ vault)
    """Derive export key."""
    return _derive_io_key(password, _HKDF_EXPORT)


def derive_import_key(password: str) -> bytes:
    # ключ расшифровки импорта
    """Derive import key."""
    return _derive_io_key(password, _HKDF_IMPORT)


def derive_sharing_key(password: str) -> bytes:
    # ключ пакета sharing (SHR, позже)
    """Derive sharing key."""
    return _derive_io_key(password, _HKDF_SHARING)


def derive_file_key_from_salt(password: str, file_salt: bytes) -> bytes:
    # соль файла уникальна на каждый экспорт (дополнительно к ARC-2)
    """Derive file key from salt."""
    if not file_salt:
        raise ValueError("соль файла пустая")
    return derive_key_pbkdf2(password, file_salt, length=32, iterations=100_000)
