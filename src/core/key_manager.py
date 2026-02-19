class KeyManager:
    def derive_key(self, password: str, salt: bytes) -> bytes:
        raw = (password.encode("utf-8") + salt)[:32]
        if len(raw) < 32:
            raw = raw + b"\x00" * (32 - len(raw))
        return raw[:32]
    def store_key(self, key: bytes, path: str) -> None:
        pass
    def load_key(self, path: str) -> bytes:
        return b"\x00" * 32
