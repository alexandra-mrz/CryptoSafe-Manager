# CRY-1: Абстрактный класс EncryptionService

from abc import ABC, abstractmethod


class EncryptionService(ABC):
    """Абстракция сервиса шифрования для замены на AES-GCM в Спринте 3."""

    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Шифрует data ключом key. Возвращает ciphertext."""
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Расшифровывает ciphertext ключом key. Возвращает data."""
        pass
