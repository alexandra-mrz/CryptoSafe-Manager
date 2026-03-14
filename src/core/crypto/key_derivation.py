from __future__ import annotations

# kdf: pbkdf2 и argon2id (одобренные библиотеки)

import hashlib
from argon2.low_level import Type, hash_secret_raw

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024
ARGON2_PARALLELISM = 4
ARGON2_HASH_LENGTH = 32
# ограничения параметров argon2 против DoS
ARGON2_TIME_COST_MAX = 10
ARGON2_MEMORY_COST_MAX = 128 * 1024
ARGON2_PARALLELISM_MAX = 8


def derive_key_pbkdf2(password: str, salt: bytes, length: int = 32, iterations: int = 100_000) -> bytes:
    password_bytes = password.encode("utf-8")
    key = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, iterations, dklen=length)
    return key


def _limit_argon2_params(time_cost: int, memory_cost: int, parallelism: int) -> tuple:
    # ограничение параметров против DoS
    if time_cost > ARGON2_TIME_COST_MAX:
        time_cost = ARGON2_TIME_COST_MAX
    if time_cost < 1:
        time_cost = 1
    if memory_cost > ARGON2_MEMORY_COST_MAX:
        memory_cost = ARGON2_MEMORY_COST_MAX
    if memory_cost < 8192:
        memory_cost = 8192
    if parallelism > ARGON2_PARALLELISM_MAX:
        parallelism = ARGON2_PARALLELISM_MAX
    if parallelism < 1:
        parallelism = 1
    return time_cost, memory_cost, parallelism


def derive_key_argon2(
    password: str,
    salt: bytes,
    length: int = ARGON2_HASH_LENGTH,
    time_cost: int = ARGON2_TIME_COST,
    memory_cost: int = ARGON2_MEMORY_COST,
    parallelism: int = ARGON2_PARALLELISM,
) -> bytes:
    time_cost, memory_cost, parallelism = _limit_argon2_params(time_cost, memory_cost, parallelism)
    password_bytes = password.encode("utf-8")
    key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=length,
        type=Type.ID,
    )
    return key


# типы ключей для будущих спринтов (аудит, экспорт, totp)
KEY_TYPE_AUDIT_SIGN = "audit_sign"
KEY_TYPE_EXPORT_ENC = "export_enc"
KEY_TYPE_TOTP = "totp"


def derive_key_for_type(key_type: str, password: str, salt: bytes, length: int = 32) -> bytes:
    salt_with_type = salt + key_type.encode("utf-8")
    return derive_key_pbkdf2(password, salt_with_type, length=length)


def get_approved_crypto_versions() -> dict:
    # версии одобренных библиотек для аудита
    result = {"hashlib": "stdlib"}
    try:
        import argon2
        result["argon2"] = getattr(argon2, "__version__", "unknown")
    except Exception:
        result["argon2"] = "not_available"
    return result
