from __future__ import annotations

# аутентификация по мастер-паролю, мастер-пароль не хранится (только хэш)

import binascii
import os
import secrets
import time
from typing import Optional

from .key_derivation import derive_key_argon2, derive_key_pbkdf2
from .key_storage import save_key_metadata, load_key_metadata, cache_key

_SESSION_UNLOCKED = False
_AUTH_KEY_TYPE = "master_auth"
_ENC_KEY_TYPE = "master_enc"
_failed_attempt_count = 0


def has_master_password() -> bool:
    return load_key_metadata(_AUTH_KEY_TYPE) is not None


def is_mfa_available() -> bool:
    return False


def is_password_strong(password: str) -> bool:
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

    if secrets.compare_digest(hash_hex, expected_hash):
        cache_key(_AUTH_KEY_TYPE, key)
        return True
    return False


def unlock_session(password: str) -> bool:
    global _SESSION_UNLOCKED, _failed_attempt_count
    if verify_master_password(password):
        _SESSION_UNLOCKED = True
        get_encryption_key(password)
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
    return _failed_attempt_count


def lock_session() -> None:
    global _SESSION_UNLOCKED
    _SESSION_UNLOCKED = False


def is_session_unlocked() -> bool:
    return _SESSION_UNLOCKED


def get_encryption_key(password: str) -> bytes:
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

