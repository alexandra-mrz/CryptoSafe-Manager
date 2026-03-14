from __future__ import annotations

# кэш ключей в памяти, метаданные в key_store (ключ шифрования на диск не пишем)

from pathlib import Path
from typing import Dict, Optional

from src.core.crypto.memory import zero_bytearray
from src.database.db import get_default_database

_key_cache: Dict[str, bytearray] = {}
_app_active: bool = True
_KEY_CACHE_TIMEOUT_SECONDS = 3600


def cache_key(key_id: str, key: bytes) -> None:
    from src.core.crypto.authentication import is_session_unlocked
    if not is_session_unlocked():
        return
    if not _app_active:
        return
    _key_cache[key_id] = bytearray(key)


def get_cached_key(key_id: str) -> Optional[bytes]:
    data = _key_cache.get(key_id)
    if data is None:
        return None
    return bytes(data)


def clear_all_keys() -> None:
    for key_id, data in _key_cache.items():
        zero_bytearray(data)
    _key_cache.clear()


def set_app_active(active: bool) -> None:
    global _app_active
    _app_active = active
    if not active:
        clear_all_keys()


def update_cache_activity(inactivity_seconds: int) -> None:
    if inactivity_seconds >= _KEY_CACHE_TIMEOUT_SECONDS:
        clear_all_keys()


# key_store: auth_hash, enc_salt, params (key_data BLOB, version)
import json
from datetime import datetime


def save_key_metadata(key_type: str, salt: str, hash_value: str, params: str) -> None:
    db = get_default_database()
    conn = db.create_connection()
    try:
        cur = conn.cursor()
        now = datetime.utcnow().isoformat()
        if key_type == "master_auth":
            cur.execute("DELETE FROM key_store WHERE key_type = 'auth_hash'")
            cur.execute(
                "INSERT INTO key_store (key_type, key_data, version, created_at) VALUES ('auth_hash', ?, 1, ?)",
                (bytes.fromhex(hash_value) if hash_value else b"", now),
            )
            _update_params_row(cur, now, auth_salt_hex=salt, auth_params=params)
        elif key_type == "master_enc":
            cur.execute("DELETE FROM key_store WHERE key_type = 'enc_salt'")
            cur.execute(
                "INSERT INTO key_store (key_type, key_data, version, created_at) VALUES ('enc_salt', ?, 1, ?)",
                (bytes.fromhex(salt) if salt else b"", now),
            )
            _update_params_row(cur, now, enc_params=params)
        conn.commit()
    finally:
        conn.close()


def _update_params_row(cur, now: str, auth_salt_hex: str = "", auth_params: str = "", enc_params: str = "") -> None:
    cur.execute("SELECT key_data FROM key_store WHERE key_type = 'params' LIMIT 1")
    row = cur.fetchone()
    data = {}
    if row and row[0]:
        try:
            data = json.loads(row[0].decode("utf-8"))
        except Exception:
            pass
    if auth_salt_hex:
        data["auth_salt_hex"] = auth_salt_hex
    if auth_params:
        data["auth_params"] = auth_params
    if enc_params:
        data["enc_params"] = enc_params
    blob = json.dumps(data).encode("utf-8")
    cur.execute("SELECT id FROM key_store WHERE key_type = 'params' LIMIT 1")
    if cur.fetchone():
        cur.execute("UPDATE key_store SET key_data = ?, created_at = ? WHERE key_type = 'params'", (blob, now))
    else:
        cur.execute(
            "INSERT INTO key_store (key_type, key_data, version, created_at) VALUES ('params', ?, 1, ?)",
            (blob, now),
        )


def load_key_metadata(key_type: str) -> Optional[dict]:
    db = get_default_database()
    conn = db.create_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT key_data FROM key_store WHERE key_type = 'params' LIMIT 1")
        params_row = cur.fetchone()
        data = {}
        if params_row and params_row[0]:
            try:
                data = json.loads(params_row[0].decode("utf-8"))
            except Exception:
                pass
        if key_type == "master_auth":
            cur.execute("SELECT key_data FROM key_store WHERE key_type = 'auth_hash' LIMIT 1")
            row = cur.fetchone()
            if row is None or row[0] is None:
                return None
            return {
                "salt": data.get("auth_salt_hex", ""),
                "hash": row[0].hex(),
                "params": data.get("auth_params", ""),
            }
        if key_type == "master_enc":
            cur.execute("SELECT key_data FROM key_store WHERE key_type = 'enc_salt' LIMIT 1")
            row = cur.fetchone()
            if row is None:
                return None
            return {
                "salt": row[0].hex() if row[0] else "",
                "hash": "",
                "params": data.get("enc_params", ""),
            }
        return None
    finally:
        conn.close()


# keyring для ОС, при недоступности — файл (кроме ключа шифрования)
_KEYCHAIN_SERVICE = "CryptoSafeManager"
_FALLBACK_DIR = Path("data/keychain_fallback")

try:
    import keyring
    _keyring_ok = True
except Exception:
    _keyring_ok = False


def _fallback_path(key_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in key_id)
    return _FALLBACK_DIR / f"{safe}.secret"


def store_in_os_keychain(service_name: str, key_id: str, secret: str) -> None:
    if _keyring_ok:
        try:
            keyring.set_password(service_name, key_id, secret)
            return
        except Exception:
            pass
    if key_id == "master_enc":
        return
    path = _fallback_path(key_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(secret, encoding="utf-8")


def load_from_os_keychain(service_name: str, key_id: str) -> Optional[str]:
    if _keyring_ok:
        try:
            value = keyring.get_password(service_name, key_id)
            if value is not None:
                return value
        except Exception:
            pass
    path = _fallback_path(key_id)
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return None

