"""One-off: inspect key_store in data/cryptosafe.db (local diagnostic)."""
import json
import sqlite3
from pathlib import Path

p = Path(__file__).resolve().parents[1] / "data" / "cryptosafe.db"
conn = sqlite3.connect(p)
cur = conn.cursor()
cur.execute("PRAGMA user_version")
print("user_version:", cur.fetchone()[0])
cur.execute("SELECT key_type, length(key_data) FROM key_store ORDER BY key_type")
print("key_store:", cur.fetchall())
cur.execute("SELECT key_data FROM key_store WHERE key_type = 'params'")
row = cur.fetchone()
if row and row[0]:
    d = json.loads(row[0].decode("utf-8"))
    print("params:", {k: (v[:40] + "..." if len(str(v)) > 40 else v) for k, v in d.items()})
cur.execute("SELECT length(key_data), hex(key_data) FROM key_store WHERE key_type = 'auth_hash'")
ah = cur.fetchone()
print("auth_hash bytes:", ah[0] if ah else None, "hex prefix:", (ah[1][:32] if ah and ah[1] else None))
cur.execute("SELECT COUNT(*) FROM vault_entries")
print("vault_entries:", cur.fetchone()[0])
# legacy rows?
cur.execute("PRAGMA table_info(key_store)")
cols = [r[1] for r in cur.fetchall()]
print("key_store columns:", cols)
conn.close()
