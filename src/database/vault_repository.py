import datetime
from src.database.db import get_db
from src.core.crypto.placeholder import AES256Placeholder
from src.core.key_manager import KeyManager
def _get_encryption():
    return AES256Placeholder()
def _get_key():
    try:
        db = get_db()
        with db.get_connection() as conn:
            row = conn.execute("SELECT salt FROM key_store WHERE key_type = ? LIMIT 1", ("master",)).fetchone()
            if row and row[0]:
                km = KeyManager()
                return km.derive_key("stub_master", bytes(row[0]))
        return b"\x00" * 32
    except Exception:
        return b"\x00" * 32
def add_entry(title: str, username: str, password: str, url: str = "", notes: str = "", tags: str = ""):
    enc = _get_encryption()
    key = _get_key()
    enc_password = enc.encrypt(password.encode("utf-8"), key)
    enc_notes = enc.encrypt(notes.encode("utf-8"), key) if notes else b""
    now = datetime.datetime.now(datetime.UTC).isoformat()
    db = get_db()
    with db.get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO vault_entries
               (title, username, encrypted_password, url, notes, created_at, updated_at, tags)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (title, username, enc_password, url, enc_notes, now, now, tags)
        )
        return cur.lastrowid
