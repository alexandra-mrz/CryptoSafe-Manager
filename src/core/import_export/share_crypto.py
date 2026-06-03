from __future__ import annotations

# Sprint 6: криптография share (CRY-1..CRY-4 — пароль, RSA/OAEP, ECIES)

import base64
import hashlib
import hmac
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.core.import_export.import_security import scan_import_text, wipe_sensitive
from src.core.import_export.io_keys import derive_file_key_from_salt, derive_sharing_key
from src.core.security.side_channel_protection import constant_time_compare

PBKDF2_ITERATIONS = 100_000
METHOD_PASSWORD = "password"
METHOD_PUBLIC_KEY = "public_key"
HYBRID_RSA = "rsa_oaep_aes_gcm"
HYBRID_ECIES = "ecies_ecdh_aes_gcm"
_DEFAULT_HMAC_SECRET = "vault-sharing-hmac"


def _load_public_key(pem_or_hex: str):
    # PEM или hex DER → объект публичного ключа
    text = (pem_or_hex or "").strip()
    if not text:
        raise ValueError("пустой ключ")
    if "BEGIN" in text:
        return serialization.load_pem_public_key(text.encode("utf-8"))
    raw = bytes.fromhex(text)
    return serialization.load_der_public_key(raw)


def _load_private_key(pem: str):
    # PEM приватного ключа получателя
    text = (pem or "").strip()
    if not text:
        raise ValueError("пустой приватный ключ")
    return serialization.load_pem_private_key(text.encode("utf-8"), password=None)


def _key_kind(public_key) -> str:
    # RSA или ECC — для выбора гибридного протокола
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ecc"
    raise ValueError("неподдерживаемый тип ключа")


def _body_plain(body: dict[str, Any]) -> bytes:
    # тело share в каноничном JSON
    return json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")


def _hmac_secret(share_password: str) -> str:
    # CRY-4: один и тот же секрет для HMAC при encrypt/decrypt
    text = (share_password or "").strip()
    if text:
        return text
    return _DEFAULT_HMAC_SECRET


def _sign_plain(plain: bytes, share_password: str) -> str:
    # CRY-4: HMAC-SHA256
    sign_key = derive_sharing_key(_hmac_secret(share_password))
    return hmac.new(sign_key, plain, hashlib.sha256).hexdigest()


def _tamper_evidence(encryption_block: dict[str, Any]) -> str:
    # CRY-4: отпечаток метаданных шифрования
    raw = json.dumps(encryption_block, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _package_signature_value(package: dict[str, Any]) -> str:
    # FMT-1 / FMT-2: подпись в integrity.signature
    integrity = package.get("integrity") or {}
    if integrity.get("signature"):
        return str(integrity.get("signature"))
    sig = package.get("signature") or {}
    return str(sig.get("value", "") or "")


def verify_before_decrypt(package: dict[str, Any]) -> None:
    # CRY-4: проверки до расшифровки AES
    """Verify before decrypt."""
    enc = package.get("encryption")
    if not isinstance(enc, dict):
        raise ValueError("нет encryption — возможна подмена")
    if not package.get("data"):
        raise ValueError("нет data")
    if not _package_signature_value(package):
        raise ValueError("нет подписи — tamper evidence")
    integrity = package.get("integrity") or {}
    if not integrity.get("hash"):
        raise ValueError("нет integrity hash")
    expected_tamper = str(package.get("tamper_evidence", "") or "")
    if expected_tamper:
        actual = _tamper_evidence(enc)
        if not constant_time_compare(actual, expected_tamper):
            raise ValueError("метаданные шифрования изменены")


def _verify_plain(plain: bytes, package: dict[str, Any], share_password: str) -> None:
    integrity = package.get("integrity") or {}
    expected_hash = str(integrity.get("hash", "") or "")
    if expected_hash and not constant_time_compare(hashlib.sha256(plain).hexdigest(), expected_hash):
        raise ValueError("нарушена целостность данных")
    expected_sig = _package_signature_value(package)
    actual_sig = _sign_plain(plain, share_password)
    if not constant_time_compare(actual_sig, expected_sig):
        raise ValueError("подпись не совпадает")


def encrypt_password_package(body: dict[str, Any], share_password: str) -> dict[str, Any]:
    # CRY-1: AES-256-GCM + PBKDF2 100000 + параметры в пакете
    """Encrypt password package."""
    file_salt = os.urandom(16)
    nonce = os.urandom(12)
    plain = _body_plain(body)
    plain_buf = bytearray(plain)
    file_key = derive_file_key_from_salt(share_password, file_salt)
    try:
        cipher = AESGCM(file_key).encrypt(nonce, bytes(plain_buf), None)
        sign_hex = _sign_plain(plain, share_password)
        plain_hash = hashlib.sha256(plain).hexdigest()
    finally:
        wipe_sensitive(file_key)
        wipe_sensitive(plain_buf)
    enc_block = {
        "algorithm": "AES-256-GCM",
        "mode": METHOD_PASSWORD,
        "key_derivation": "PBKDF2-HMAC-SHA256",
        "context_key": "vault-sharing",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(file_salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    return {
        "encryption": enc_block,
        "data": base64.b64encode(cipher).decode("ascii"),
        "integrity": {
            "hash": plain_hash,
            "hash_algorithm": "SHA256",
            "signature": sign_hex,
        },
        "tamper_evidence": _tamper_evidence(enc_block),
    }


def decrypt_password_package(package: dict[str, Any], share_password: str) -> bytes:
    """Decrypt password package."""
    verify_before_decrypt(package)
    enc = package["encryption"]
    file_salt = base64.b64decode(str(enc["salt"]))
    nonce = base64.b64decode(str(enc["nonce"]))
    file_key = derive_file_key_from_salt(share_password, file_salt)
    try:
        cipher = base64.b64decode(str(package["data"]))
        plain = AESGCM(file_key).decrypt(nonce, cipher, None)
        _verify_plain(plain, package, share_password)
        scan_import_text(plain.decode("utf-8"))
        return plain
    finally:
        wipe_sensitive(file_key)


def _ecdh_derive_key(private_key, public_key) -> bytes:
    # CRY-3: ECDH → HKDF → ключ AES
    shared = private_key.exchange(ec.ECDH(), public_key)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"cryptosafe-share-ecdh")
    return hkdf.derive(shared)


def encrypt_ecies_package(
    body: dict[str, Any],
    recipient_public_key_pem: str,
    *,
    sender_public_key_pem: str = "",
    sign_material: str = "",
) -> dict[str, Any]:
    # CRY-2 ECIES + CRY-3 эфемерный ECDH на каждый share
    """Encrypt ecies package."""
    recipient_pub = _load_public_key(recipient_public_key_pem)
    if _key_kind(recipient_pub) != "ecc":
        raise ValueError("ECIES требует ECC P-256 ключ получателя")

    ephemeral = ec.generate_private_key(ec.SECP256R1())
    eph_pub = ephemeral.public_key()
    wrap_key = _ecdh_derive_key(ephemeral, recipient_pub)
    plain = _body_plain(body)
    plain_buf = bytearray(plain)
    nonce = os.urandom(12)
    try:
        cipher = AESGCM(wrap_key).encrypt(nonce, bytes(plain_buf), None)
        sign_hex = _sign_plain(plain, sign_material)
        plain_hash = hashlib.sha256(plain).hexdigest()
    finally:
        wipe_sensitive(wrap_key)
        wipe_sensitive(plain_buf)

    eph_pem = eph_pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    enc_block = {
        "algorithm": "ECIES-ECDH/AES-256-GCM",
        "mode": METHOD_PUBLIC_KEY,
        "hybrid": HYBRID_ECIES,
        "ephemeral_public_key_pem": eph_pem,
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    if sender_public_key_pem:
        enc_block["sender_public_key_pem"] = sender_public_key_pem

    return {
        "encryption": enc_block,
        "data": base64.b64encode(cipher).decode("ascii"),
        "integrity": {
            "hash": plain_hash,
            "hash_algorithm": "SHA256",
            "signature": sign_hex,
        },
        "tamper_evidence": _tamper_evidence(enc_block),
    }


def decrypt_ecies_package(package: dict[str, Any], recipient_private_key_pem: str, sign_material: str = "") -> bytes:
    """Decrypt ecies package."""
    verify_before_decrypt(package)
    enc = package["encryption"]
    if enc.get("hybrid") != HYBRID_ECIES:
        raise ValueError("не ECIES пакет")
    recipient_priv = _load_private_key(recipient_private_key_pem)
    eph_pem = str(enc.get("ephemeral_public_key_pem", "") or "")
    eph_pub = _load_public_key(eph_pem)
    wrap_key = _ecdh_derive_key(recipient_priv, eph_pub)
    try:
        nonce = base64.b64decode(str(enc["nonce"]))
        cipher = base64.b64decode(str(package["data"]))
        plain = AESGCM(wrap_key).decrypt(nonce, cipher, None)
        _verify_plain(plain, package, sign_material)
        scan_import_text(plain.decode("utf-8"))
        return plain
    finally:
        wipe_sensitive(wrap_key)


def encrypt_rsa_package(
    body: dict[str, Any],
    recipient_public_key_pem: str,
    *,
    sender_public_key_pem: str = "",
    sign_material: str = "",
) -> dict[str, Any]:
    # CRY-2: RSA-OAEP + AES-256-GCM, новый sym_key на каждый share (CRY-3)
    """Encrypt rsa package."""
    recipient_pub = _load_public_key(recipient_public_key_pem)
    if _key_kind(recipient_pub) != "rsa":
        raise ValueError("RSA/OAEP требует RSA-2048 ключ получателя")

    sym_key = os.urandom(32)
    plain = _body_plain(body)
    plain_buf = bytearray(plain)
    nonce = os.urandom(12)
    try:
        cipher = AESGCM(sym_key).encrypt(nonce, bytes(plain_buf), None)
        encrypted_sym = recipient_pub.encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        sign_hex = _sign_plain(plain, sign_material)
        plain_hash = hashlib.sha256(plain).hexdigest()
    finally:
        wipe_sensitive(sym_key)
        wipe_sensitive(plain_buf)

    enc_block = {
        "algorithm": "RSA-OAEP/AES-256-GCM",
        "mode": METHOD_PUBLIC_KEY,
        "hybrid": HYBRID_RSA,
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    if sender_public_key_pem:
        enc_block["sender_public_key_pem"] = sender_public_key_pem

    return {
        "encryption": enc_block,
        "encrypted_key": base64.b64encode(encrypted_sym).decode("ascii"),
        "data": base64.b64encode(cipher).decode("ascii"),
        "integrity": {
            "hash": plain_hash,
            "hash_algorithm": "SHA256",
            "signature": sign_hex,
        },
        "tamper_evidence": _tamper_evidence(enc_block),
    }


def decrypt_rsa_package(package: dict[str, Any], recipient_private_key_pem: str, sign_material: str = "") -> bytes:
    """Decrypt rsa package."""
    verify_before_decrypt(package)
    enc = package["encryption"]
    if enc.get("hybrid") != HYBRID_RSA:
        raise ValueError("не RSA пакет")
    recipient_priv = _load_private_key(recipient_private_key_pem)
    if not isinstance(recipient_priv, rsa.RSAPrivateKey):
        raise ValueError("нужен RSA приватный ключ")
    encrypted_sym = base64.b64decode(str(package["encrypted_key"]))
    sym_key = recipient_priv.decrypt(
        encrypted_sym,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    try:
        nonce = base64.b64decode(str(enc["nonce"]))
        cipher = base64.b64decode(str(package["data"]))
        plain = AESGCM(sym_key).decrypt(nonce, cipher, None)
        _verify_plain(plain, package, sign_material)
        scan_import_text(plain.decode("utf-8"))
        return plain
    finally:
        wipe_sensitive(sym_key)


def encrypt_public_key_package(
    body: dict[str, Any],
    recipient_public_key_pem: str,
    *,
    sender_public_key_pem: str = "",
    share_password: str = "",
) -> dict[str, Any]:
    # CRY-2: выбор RSA или ECIES по типу ключа
    """Encrypt public key package."""
    pub = _load_public_key(recipient_public_key_pem)
    sign_material = share_password
    if _key_kind(pub) == "rsa":
        return encrypt_rsa_package(
            body,
            recipient_public_key_pem,
            sender_public_key_pem=sender_public_key_pem,
            sign_material=sign_material,
        )
    return encrypt_ecies_package(
        body,
        recipient_public_key_pem,
        sender_public_key_pem=sender_public_key_pem,
        sign_material=sign_material,
    )


def decrypt_public_key_package(
    package: dict[str, Any],
    recipient_private_key_pem: str,
    *,
    share_password: str = "",
) -> bytes:
    # CRY-2: RSA или ECIES по полю hybrid
    """Decrypt public key package."""
    enc = package.get("encryption") or {}
    hybrid = str(enc.get("hybrid", "") or "")
    sign_material = share_password
    if hybrid == HYBRID_RSA:
        return decrypt_rsa_package(package, recipient_private_key_pem, sign_material)
    if hybrid == HYBRID_ECIES:
        return decrypt_ecies_package(package, recipient_private_key_pem, sign_material)
    raise ValueError("неизвестный hybrid, старый формат не поддерживается")
