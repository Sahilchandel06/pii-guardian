import base64
import hashlib
import os

from cryptography.fernet import Fernet

from app.utils.security import SECRET_KEY


def _load_key() -> bytes:
    configured_key = os.getenv("FILE_ENCRYPTION_KEY")
    if configured_key:
        return configured_key.encode("utf-8")

    # Fallback key derived from JWT secret so files remain decryptable across restarts.
    digest = hashlib.sha256(SECRET_KEY.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


_fernet = Fernet(_load_key())


def encrypt_bytes(raw_bytes: bytes) -> bytes:
    return _fernet.encrypt(raw_bytes)


def decrypt_bytes(cipher_bytes: bytes) -> bytes:
    return _fernet.decrypt(cipher_bytes)
