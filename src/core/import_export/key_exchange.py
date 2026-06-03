from __future__ import annotations

# Sprint 6: обмен ключами и QR (QR-3..QR-4, DB-3 — контакты)

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.database import io_storage
from src.core.import_export.qr_code_service import (
    PAYLOAD_ENCRYPTED_ENTRY,
    PAYLOAD_PUBKEY,
    PAYLOAD_SHARE_LINK,
    QRCodeService,
)

ALGO_RSA2048 = "rsa2048"
ALGO_ECC_P256 = "ecc_p256"


@dataclass
class KeyPairRecord:
    # пара ключей для контакта (QR-3)
    """Публичный класс KeyPairRecord."""
    contact_id: str
    algorithm: str
    public_key_pem: str
    private_key_pem: str
    public_key_hex: str
    fingerprint: str
    created_at: str
    revoked: bool = False


@dataclass
class ContactRecord:
    # публичный ключ в списке контактов
    """Публичный класс ContactRecord."""
    contact_id: str
    algorithm: str
    public_key_pem: str
    public_key_hex: str
    fingerprint: str
    added_at: str
    revoked: bool = False
    fingerprint_verified: bool = False


class ContactList:
    # DB-3: контакты в таблице contacts

    """Публичный класс ContactList."""
    def add_contact(self, record: ContactRecord) -> None:
        # DB-3: сохранить публичный ключ контакта
        """Add contact."""
        io_storage.upsert_contact(
            contact_id=record.contact_id,
            contact_name=record.contact_id,
            public_key_pem=record.public_key_pem,
            public_key_hex=record.public_key_hex,
            key_fingerprint=record.fingerprint,
            algorithm=record.algorithm,
            fingerprint_verified=record.fingerprint_verified,
        )

    def get_contact(self, contact_id: str) -> Optional[ContactRecord]:
        # прочитать контакт из БД
        """Get contact."""
        row = io_storage.get_contact_row(contact_id)
        if row is None:
            return None
        return ContactRecord(
            contact_id=str(row["contact_id"]),
            algorithm=str(row["algorithm"]),
            public_key_pem=str(row["public_key_pem"]),
            public_key_hex=str(row["public_key_hex"]),
            fingerprint=str(row["key_fingerprint"]),
            added_at=str(row.get("last_used_at", "") or ""),
            revoked=bool(row["revoked"]),
            fingerprint_verified=bool(row["fingerprint_verified"]),
        )

    def list_contacts(self, *, include_revoked: bool = False) -> list[ContactRecord]:
        # список контактов (можно включить отозванные)
        """List contacts."""
        result = []
        for row in io_storage.list_contact_rows(include_revoked=include_revoked):
            result.append(
                ContactRecord(
                    contact_id=str(row["contact_id"]),
                    algorithm=str(row["algorithm"]),
                    public_key_pem=str(row["public_key_pem"]),
                    public_key_hex=str(row["public_key_hex"]),
                    fingerprint=str(row["key_fingerprint"]),
                    added_at=str(row.get("last_used_at", "") or ""),
                    revoked=bool(row["revoked"]),
                    fingerprint_verified=bool(row["fingerprint_verified"]),
                )
            )
        return result

    def revoke_contact(self, contact_id: str) -> None:
        # пометить ключ контакта как отозванный
        """Revoke contact."""
        io_storage.revoke_contact_row(contact_id)

    def verify_fingerprint(self, contact_id: str, fingerprint: str) -> bool:
        # сверить отпечаток ключа с ожидаемым
        """Verify fingerprint."""
        ok = io_storage.set_contact_fingerprint_verified(contact_id, fingerprint)
        if ok:
            io_storage.touch_contact_last_used(contact_id)
        return ok


class KeyExchange:
    # генерация RSA-2048 или ECC P-256 (QR-3)

    """Публичный класс KeyExchange."""
    def __init__(self, contacts: Optional[ContactList] = None) -> None:
        # contacts — список в БД, _qr — генерация/сканирование
        self._contacts = contacts or ContactList()
        self._qr = QRCodeService()

    @staticmethod
    def _utc_now_iso() -> str:
        # время UTC для метаданных ключей
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _fingerprint(public_bytes: bytes) -> str:
        # короткий отпечаток публичного ключа
        return hashlib.sha256(public_bytes).hexdigest()[:16]

    def generate_key_pair(self, contact_id: str, algorithm: str = ALGO_ECC_P256) -> KeyPairRecord:
        # QR-3: новая пара (RSA-2048 или ECC P-256)
        """Generate key pair."""
        algo = str(algorithm or ALGO_ECC_P256).lower()
        if algo == ALGO_RSA2048:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub = private_key.public_key()
            pub_bytes = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            priv_pem = private_key.private_bytes(
                Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii")
            pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        elif algo == ALGO_ECC_P256:
            private_key = ec.generate_private_key(ec.SECP256R1())
            pub = private_key.public_key()
            pub_bytes = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            priv_pem = private_key.private_bytes(
                Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii")
            pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        else:
            raise ValueError("algorithm: rsa2048 или ecc_p256")

        return KeyPairRecord(
            contact_id=str(contact_id),
            algorithm=algo,
            public_key_pem=pub_pem,
            private_key_pem=priv_pem,
            public_key_hex=pub_bytes.hex(),
            fingerprint=self._fingerprint(pub_bytes),
            created_at=self._utc_now_iso(),
        )

    def save_contact_public_key(self, record: KeyPairRecord) -> ContactRecord:
        # QR-3 / DB-3: только публичная часть в БД
        """Save contact public key."""
        contact = ContactRecord(
            contact_id=record.contact_id,
            algorithm=record.algorithm,
            public_key_pem=record.public_key_pem,
            public_key_hex=record.public_key_hex,
            fingerprint=record.fingerprint,
            added_at=record.created_at,
            revoked=False,
            fingerprint_verified=False,
        )
        self._contacts.add_contact(contact)
        io_storage.touch_contact_last_used(record.contact_id)
        return contact

    def rotate_contact_keys(self, contact_id: str, algorithm: str = ALGO_ECC_P256) -> KeyPairRecord:
        # QR-3: ротация — отозвать старый, создать новый
        """Rotate contact keys."""
        self._contacts.revoke_contact(contact_id)
        new_pair = self.generate_key_pair(contact_id, algorithm=algorithm)
        self.save_contact_public_key(new_pair)
        return new_pair

    def public_key_qr_payload(self, record: KeyPairRecord) -> dict[str, Any]:
        # QR-4: только публичная часть, без приватного ключа
        """Public key qr payload."""
        inner = {
            "type": "cryptosafe_pubkey",
            "contact_id": record.contact_id,
            "algorithm": record.algorithm,
            "public_key_pem": record.public_key_pem,
            "public_key_hex": record.public_key_hex,
            "fingerprint": record.fingerprint,
        }
        return self._qr.build_wrapped_payload(PAYLOAD_PUBKEY, inner)

    def _share_package_qr_inner(self, package: dict[str, Any]) -> dict[str, Any]:
        # компактный body: только сжатый пакет (один QR)
        from src.core.import_export.share_package_codec import encode_share_package_b64

        return {
            "type": "cryptosafe_share_package",
            "package_b64": encode_share_package_b64(package),
        }

    def share_link_qr_payload(
        self,
        share_link: dict[str, Any],
        *,
        package: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Share link qr payload."""
        if package:
            inner = self._share_package_qr_inner(package)
            inner["token"] = str(share_link.get("token", "") or "")
            wrapped = self._qr.build_wrapped_payload(PAYLOAD_SHARE_LINK, inner, valid_minutes=30)
            self._qr.assert_fits_single_qr(wrapped)
            return wrapped
        inner = {
            "type": "cryptosafe_share_link",
            "token": str(share_link.get("token", "") or ""),
            "url_hint": str(share_link.get("url_hint", "") or ""),
            "expires_at": str(share_link.get("expires_at", "") or ""),
        }
        return self._qr.build_wrapped_payload(PAYLOAD_SHARE_LINK, inner, valid_minutes=30)

    def encrypted_entry_qr_payload(self, package: dict[str, Any]) -> dict[str, Any]:
        """Encrypted entry qr payload."""
        inner = self._share_package_qr_inner(package)
        wrapped = self._qr.build_wrapped_payload(PAYLOAD_ENCRYPTED_ENTRY, inner, valid_minutes=30)
        self._qr.assert_fits_single_qr(wrapped)
        return wrapped

    def generate_qr_code(self, data: bytes, chunk_size: int = 2953) -> list[str]:
        # как в примере преподавателя (делегат в QRCodeService)
        """Generate qr code."""
        return self._qr.generate_qr_code(data, chunk_size=chunk_size)

    def decode_qr_chunks(self, chunks: list[str]) -> Optional[bytes]:
        # собрать фрагменты QR в байты
        """Decode qr chunks."""
        return self._qr.decode_qr_chunks(chunks)

    def generate_qr_images(self, wrapped: dict[str, Any]) -> list[bytes]:
        # PNG для UI; chunks только у очень больших pubkey-QR
        """Generate qr images."""
        body = wrapped.get("body") if isinstance(wrapped.get("body"), dict) else {}
        allow_chunks = body.get("type") == "cryptosafe_pubkey"
        return self._qr.generate_qr_images(wrapped, allow_chunks=allow_chunks)

    def parse_public_key_qr_payload(self, text: str) -> dict[str, Any]:
        # разбор QR pubkey (строка JSON)
        """Parse public key qr payload."""
        body = self._qr.parse_scanned_text(text)
        if body.get("type") != "cryptosafe_pubkey":
            raise ValueError("не pubkey QR")
        return body

    def import_pubkey_from_qr(self, text: str) -> ContactRecord:
        # сканирование → контакт
        """Import pubkey from qr."""
        body = self.parse_public_key_qr_payload(text)
        contact = ContactRecord(
            contact_id=str(body.get("contact_id", "") or ""),
            algorithm=str(body.get("algorithm", "") or ""),
            public_key_pem=str(body.get("public_key_pem", "") or ""),
            public_key_hex=str(body.get("public_key_hex", "") or ""),
            fingerprint=str(body.get("fingerprint", "") or ""),
            added_at=self._utc_now_iso(),
        )
        if not contact.contact_id:
            raise ValueError("нет contact_id")
        self._contacts.add_contact(contact)
        return contact

    def scan_qr_from_image(self, file_path: str) -> dict[str, Any]:
        # QR-2: файл изображения → payload
        """Scan qr from image."""
        return self._qr.scan_from_image_file(file_path)

    def scan_qr_from_camera(self, timeout_sec: float = 5.0) -> dict[str, Any]:
        # QR-2: камера → payload
        """Scan qr from camera."""
        return self._qr.scan_from_camera(timeout_sec=timeout_sec)

    @property
    def contacts(self) -> ContactList:
        # список контактов для UI
        """Contacts."""
        return self._contacts
