from __future__ import annotations

# аутентификация по мастер-паролю, мастер-пароль не хранится (только хэш)

import binascii
import os
import secrets
import time
from typing import Optional

from .key_derivation import derive_key_argon2, derive_key_pbkdf2
from .key_storage import save_key_metadata, load_key_metadata, cache_key
from src.core.security.memory_guard import stack_canary_ok, wipe_local
from src.core.security.side_channel_protection import constant_time_compare

_STACK_CANARY = 0xC0FFEE42

_SESSION_UNLOCKED = False
_AUTH_KEY_TYPE = "master_auth"
_ENC_KEY_TYPE = "master_enc"
_failed_attempt_count = 0


def has_master_password() -> bool:
    """Has master password."""
    return load_key_metadata(_AUTH_KEY_TYPE) is not None


def is_mfa_available() -> bool:
    """Is mfa available."""
    return False


def is_password_strong(password: str) -> bool:
    """Is password strong."""
    if len(password) < 12:
        return False

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    if not (has_lower and has_upper and has_digit and has_symbol):
        return False

    bad_patterns = ["password", "password123", "qwerty", "123456", "admin"]
    lower = password.lower()
    for pat in bad_patterns:
        if pat in lower:
            return False

    return True


def set_master_password(password: str) -> None:
    """Set master password."""
    if not is_password_strong(password):
        raise ValueError("слишком простой мастер-пароль")
    salt_auth = os.urandom(16)
    auth_key = derive_key_argon2(password, salt_auth)
    auth_hash_hex = binascii.hexlify(auth_key).decode("ascii")
    auth_salt_hex = binascii.hexlify(salt_auth).decode("ascii")

    auth_params = "argon2id_t3_m64mb_p4_32"
    save_key_metadata(_AUTH_KEY_TYPE, auth_salt_hex, auth_hash_hex, auth_params)
    cache_key(_AUTH_KEY_TYPE, auth_key)
    salt_enc = os.urandom(16)
    enc_key = derive_key_pbkdf2(password, salt_enc, length=32, iterations=100_000)
    enc_salt_hex = binascii.hexlify(salt_enc).decode("ascii")
    enc_params = "pbkdf2_sha256_100000_32"
    save_key_metadata(_ENC_KEY_TYPE, enc_salt_hex, "", enc_params)
    cache_key(_ENC_KEY_TYPE, enc_key)


def verify_master_password(password: str) -> bool:
    """Verify master password."""
    canary = _STACK_CANARY
    info = load_key_metadata(_AUTH_KEY_TYPE)
    if info is None:
        return False

    try:
        salt = binascii.unhexlify(info["salt"].encode("ascii"))
        expected_hash = info["hash"]
    except (binascii.Error, KeyError, TypeError):
        return False

    key = derive_key_argon2(password, salt)
    hash_hex = binascii.hexlify(key).decode("ascii")
    key_buf = bytearray(key)
    try:
        # SC-1 / MEM-4: constant-time compare + stack canary + wipe derived key
        ok = constant_time_compare(hash_hex, expected_hash)
        if ok:
            cache_key(_AUTH_KEY_TYPE, key)
        return ok and stack_canary_ok(_STACK_CANARY, canary)
    finally:
        wipe_local(key_buf)


def unlock_session(password: str) -> bool:
    """Unlock session."""
    global _SESSION_UNLOCKED, _failed_attempt_count
    if verify_master_password(password):
        _SESSION_UNLOCKED = True
        get_encryption_key(password)
        from src.core.audit.log_signer import cache_audit_signing_key
        cache_audit_signing_key(password)
        _failed_attempt_count = 0
        return True
    _failed_attempt_count += 1
    if _failed_attempt_count <= 2:
        delay = 1
    elif _failed_attempt_count <= 4:
        delay = 5
    else:
        delay = 30
    time.sleep(delay)
    return False


def get_failed_attempt_count() -> int:
    """Get failed attempt count."""
    return _failed_attempt_count


def lock_session() -> None:
    """Lock session."""
    global _SESSION_UNLOCKED
    _SESSION_UNLOCKED = False


def is_session_unlocked() -> bool:
    """Is session unlocked."""
    return _SESSION_UNLOCKED


def get_encryption_key(password: str) -> bytes:
    """Get encryption key."""
    info = load_key_metadata(_ENC_KEY_TYPE)
    if info is None:
        salt = os.urandom(16)
    else:
        try:
            salt = binascii.unhexlify(info["salt"].encode("ascii"))
        except (binascii.Error, KeyError, TypeError):
            salt = os.urandom(16)

    key = derive_key_pbkdf2(password, salt, length=32, iterations=100_000)
    cache_key(_ENC_KEY_TYPE, key)
    return key

