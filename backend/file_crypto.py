"""
Encryption at rest for certificate artifacts using AES-256-GCM.

Key derived via PBKDF2HMAC(SHA-256, 480,000 iterations) from PKI_ENCRYPTION_KEY
and PKI_ENCRYPTION_SALT environment variables. Derived key is cached at startup.

File format: [ 12-byte nonce ][ AES-256-GCM ciphertext + 16-byte tag ]
"""

import os
import base64
from pathlib import Path

from dotenv import load_dotenv
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()

_ITERATIONS   = 480_000
_NONCE_LENGTH = 12      # bytes (GCM standard)
_key: bytes | None = None


def _get_key() -> bytes:
    """Derive and cache the AES-256 key using PBKDF2HMAC from env vars."""
    global _key
    if _key is None:
        password = os.environ.get("PKI_ENCRYPTION_KEY", "").strip()
        if not password:
            raise RuntimeError(
                "PKI_ENCRYPTION_KEY not set in environment."
            )
        salt_b64 = os.environ.get("PKI_ENCRYPTION_SALT", "").strip()
        if not salt_b64:
            raise RuntimeError(
                "PKI_ENCRYPTION_SALT not set. Generate with: openssl rand -base64 32"
            )
        salt = base64.b64decode(salt_b64)  # must be exactly 32 bytes
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_ITERATIONS)
        _key = kdf.derive(password.encode())
    return _key


def write_encrypted(path: Path, data: bytes) -> None:
    """Encrypt data with AES-256-GCM and write to file.
    File format: 12-byte nonce || AES-256-GCM ciphertext+tag
    """
    nonce = os.urandom(_NONCE_LENGTH)
    ciphertext = AESGCM(_get_key()).encrypt(nonce, data, None)
    path.write_bytes(nonce + ciphertext)


def read_encrypted(path: Path) -> bytes:
    """Read and decrypt file encrypted with AES-256-GCM.
    Raises InvalidTag if authentication fails (tampered data or wrong key).
    """
    raw = path.read_bytes()
    if len(raw) < _NONCE_LENGTH + 16:
        raise ValueError(f"Encrypted file too short: {path}")
    nonce = raw[:_NONCE_LENGTH]
    ciphertext = raw[_NONCE_LENGTH:]
    return AESGCM(_get_key()).decrypt(nonce, ciphertext, None)
