import base64
import hashlib
import os
import secrets
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.utils.security import SECRET_KEY


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_legacy_fernet_key() -> bytes:
    configured_key = os.getenv("FILE_ENCRYPTION_KEY")
    if configured_key:
        return configured_key.encode("utf-8")
    digest = hashlib.sha256(SECRET_KEY.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _load_master_wrap_key() -> bytes:
    # Prefer explicit wrap key; fallback to legacy key for backward-compatible local runs.
    configured = os.getenv("FILE_MASTER_KEY")
    if configured:
        raw = configured.encode("utf-8")
        if len(raw) == 32:
            return raw
        try:
            decoded = base64.urlsafe_b64decode(raw)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        raise ValueError("FILE_MASTER_KEY must be 32 raw bytes or base64url-encoded 32 bytes")
    return hashlib.sha256(_load_legacy_fernet_key()).digest()


_legacy_fernet = Fernet(_load_legacy_fernet_key())
_master_wrap_key = _load_master_wrap_key()


def encrypt_bytes(raw_bytes: bytes) -> bytes:
    # Legacy encryptor used by old records.
    return _legacy_fernet.encrypt(raw_bytes)


def decrypt_bytes(cipher_bytes: bytes) -> bytes:
    # Legacy decryptor used by old records.
    return _legacy_fernet.decrypt(cipher_bytes)


def encrypt_file_payload(raw_bytes: bytes) -> dict[str, Any]:
    dek = secrets.token_bytes(32)
    data_nonce = secrets.token_bytes(12)
    cipher_bytes = AESGCM(dek).encrypt(data_nonce, raw_bytes, None)

    wrap_nonce = secrets.token_bytes(12)
    encrypted_dek = AESGCM(_master_wrap_key).encrypt(wrap_nonce, dek, None)

    return {
        "cipher_bytes": cipher_bytes,
        "encrypted_dek": base64.urlsafe_b64encode(encrypted_dek).decode("utf-8"),
        "data_nonce": base64.urlsafe_b64encode(data_nonce).decode("utf-8"),
        "wrap_nonce": base64.urlsafe_b64encode(wrap_nonce).decode("utf-8"),
        "encryption_version": "env_aesgcm_envelope_v1",
        "file_sha256": _sha256_hex(raw_bytes),
        "cipher_sha256": _sha256_hex(cipher_bytes),
    }


def decrypt_file_payload(
    *,
    cipher_bytes: bytes,
    encrypted_dek_b64: str,
    data_nonce_b64: str,
    wrap_nonce_b64: str,
) -> bytes:
    encrypted_dek = base64.urlsafe_b64decode(encrypted_dek_b64.encode("utf-8"))
    data_nonce = base64.urlsafe_b64decode(data_nonce_b64.encode("utf-8"))
    wrap_nonce = base64.urlsafe_b64decode(wrap_nonce_b64.encode("utf-8"))

    dek = AESGCM(_master_wrap_key).decrypt(wrap_nonce, encrypted_dek, None)
    return AESGCM(dek).decrypt(data_nonce, cipher_bytes, None)


def pack_envelope_ciphertext(cipher_bytes: bytes, data_nonce_b64: str, wrap_nonce_b64: str) -> bytes:
    # Stored bytes format: ENC2:<data_nonce_b64>:<wrap_nonce_b64>:<cipher_b64>
    payload = base64.urlsafe_b64encode(cipher_bytes).decode("utf-8")
    wire = f"ENC2:{data_nonce_b64}:{wrap_nonce_b64}:{payload}"
    return wire.encode("utf-8")


def unpack_envelope_ciphertext(stored_bytes: bytes) -> tuple[str, str, bytes] | None:
    if not stored_bytes.startswith(b"ENC2:"):
        return None
    try:
        _, data_nonce_b64, wrap_nonce_b64, cipher_b64 = stored_bytes.decode("utf-8").split(":", 3)
        cipher_bytes = base64.urlsafe_b64decode(cipher_b64.encode("utf-8"))
        return data_nonce_b64, wrap_nonce_b64, cipher_bytes
    except Exception:
        return None


def sha256_hex(data: bytes) -> str:
    return _sha256_hex(data)
