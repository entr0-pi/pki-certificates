"""
Encryption at rest for certificate artifacts using Fernet (AES-128-CBC + HMAC-SHA256).

All files in /data are encrypted using a key derived from ENCRYPTION_KEY environment variable.
"""

import os
import base64
from pathlib import Path

from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Load .env file if it exists
load_dotenv()

_ITERATIONS = 480_000
_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    """Get or initialize the Fernet cipher using PKI_ENCRYPTION_KEY and PKI_ENCRYPTION_SALT from environment."""
    global _fernet
    if _fernet is None:
        key = os.environ.get("PKI_ENCRYPTION_KEY", "").strip()
        if not key:
            raise RuntimeError(
                "PKI_ENCRYPTION_KEY not set in environment. "
                "Please set PKI_ENCRYPTION_KEY in .env or as an environment variable."
            )

        # Load salt from environment (generated once at installation time)
        salt_b64 = os.environ.get("PKI_ENCRYPTION_SALT", "").strip()
        if not salt_b64:
            raise RuntimeError(
                "PKI_ENCRYPTION_SALT not set in environment. "
                "Generate a random salt with: openssl rand -base64 32 "
                "and set PKI_ENCRYPTION_SALT in .env."
            )

        try:
            salt = base64.b64decode(salt_b64)
            if len(salt) != 32:
                raise ValueError(f"Salt must be 32 bytes (got {len(salt)})")
        except Exception as exc:
            raise RuntimeError(
                f"Invalid PKI_ENCRYPTION_SALT. Must be valid base64-encoded 32-byte value. Error: {exc}"
            ) from exc

        # Derive a consistent 32-byte key from the password and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_ITERATIONS,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        _fernet = Fernet(derived_key)
    return _fernet


def write_encrypted(path: Path, data: bytes) -> None:
    """Encrypt and write bytes to file."""
    encrypted = _get_fernet().encrypt(data)
    path.write_bytes(encrypted)


def read_encrypted(path: Path) -> bytes:
    """Read and decrypt bytes from file."""
    return _get_fernet().decrypt(path.read_bytes())
