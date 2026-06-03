from __future__ import annotations

# CRY-1/CRY-2: подпись Ed25519, запасной вариант HMAC-SHA256, ключ через HKDF

import binascii
import hmac
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from datetime import datetime, timezone

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.core.crypto.key_derivation import derive_key_pbkdf2
from src.core.crypto.key_storage import cache_key, get_cached_key, load_key_metadata
from src.core.security.side_channel_protection import constant_time_compare
from src.database.db import get_default_database

AUDIT_KEY_ID = "audit_sign"
_ENC_KEY_TYPE = "master_enc"
_AUDIT_HKDF_INFO = b"audit-signing"


def _get_master_salt() -> bytes:
    # соль мастер-ключа из БД (для HKDF audit-signing)
    info = load_key_metadata(_ENC_KEY_TYPE)
    if info is None:
        return b""
    try:
        return binascii.unhexlify(info["salt"].encode("ascii"))
    except (binascii.Error, KeyError, TypeError):
        return b""


def derive_audit_signing_key(password: str) -> bytes:
    # CRY-2: HKDF от мастер-пароля, контекст audit-signing (не ключ шифрования)
    """Derive audit signing key."""
    salt = _get_master_salt()
    base = derive_key_pbkdf2(password, salt, length=32, iterations=100_000)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_AUDIT_HKDF_INFO,
    )
    return hkdf.derive(base)


def _save_public_key_once() -> None:
    # DB-1: публичный ключ Ed25519 один раз в отдельной таблице
    private_key = _ed25519_private_key()
    if private_key is None:
        return
    try:
        public_key = private_key.public_key()
        pub_hex = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    except Exception:
        return

    db = get_default_database()
    conn = db.create_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM audit_public_keys")
        count = int(cur.fetchone()[0])
        if count > 0:
            return
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        cur.execute(
            """
            INSERT INTO audit_public_keys (algorithm, public_key, created_at)
            VALUES (?, ?, ?)
            """,
            ("ed25519", pub_hex, now),
        )
        conn.commit()
    finally:
        conn.close()


def cache_audit_signing_key(password: str) -> None:
    # положить ключ подписи в память после входа
    """Cache audit signing key."""
    key = derive_audit_signing_key(password)
    cache_key(AUDIT_KEY_ID, key)
    _save_public_key_once()


def get_audit_signing_key() -> bytes | None:
    # ключ подписи из кэша (не с диска)
    """Get audit signing key."""
    return get_cached_key(AUDIT_KEY_ID)


def _ed25519_private_key() -> Ed25519PrivateKey | None:
    # 32 байта seed → ключ Ed25519, если возможно
    key = get_audit_signing_key()
    if not key or len(key) < 32:
        return None
    try:
        return Ed25519PrivateKey.from_private_bytes(key[:32])
    except ValueError:
        return None


def _sign_ed25519(data: bytes) -> str | None:
    private_key = _ed25519_private_key()
    if private_key is None:
        return None
    try:
        sig = private_key.sign(data)
        return "ed25519:" + sig.hex()
    except Exception:
        return None


def _sign_hmac(data: bytes) -> str:
    # CRY-1: запасной вариант HMAC-SHA256
    key = get_audit_signing_key()
    if not key:
        return ""
    digest = hmac.new(key, data, hashlib.sha256).digest()
    return "hmac:" + digest.hex()


def sign_bytes(data: bytes) -> str:
    # CRY-1: сначала Ed25519, иначе HMAC-SHA256
    """Sign bytes."""
    ed_sig = _sign_ed25519(data)
    if ed_sig:
        return ed_sig
    return _sign_hmac(data)


def _verify_ed25519(data: bytes, signature_hex: str) -> bool:
    # проверка подписи Ed25519
    private_key = _ed25519_private_key()
    if private_key is None:
        return False
    try:
        raw = bytes.fromhex(signature_hex)
        public_key = private_key.public_key()
        public_key.verify(raw, data)
        return True
    except Exception:
        return False


def _verify_hmac(data: bytes, signature_hex: str) -> bool:
    # проверка HMAC-SHA256
    key = get_audit_signing_key()
    if not key:
        return False
    expected = hmac.new(key, data, hashlib.sha256).digest().hex()
    return constant_time_compare(expected, signature_hex.lower())


def verify_bytes(data: bytes, signature: str) -> bool:
    # проверка по префиксу ed25519: или hmac:
    """Verify bytes."""
    if not signature:
        return False
    if signature.startswith("ed25519:"):
        return _verify_ed25519(data, signature[8:])
    if signature.startswith("hmac:"):
        return _verify_hmac(data, signature[5:])
    # старые записи без префикса
    return _verify_hmac(data, signature)


def get_signing_algorithm_name() -> str:
    # какой алгоритм сейчас используется
    """Get signing algorithm name."""
    key = get_audit_signing_key()
    if not key:
        return "none"
    if _ed25519_private_key() is not None:
        return "ed25519"
    return "hmac-sha256"
