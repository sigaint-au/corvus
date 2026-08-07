"""Fernet encryption for secret values and sensitive settings."""
from base64 import urlsafe_b64encode
from functools import lru_cache
from hashlib import sha256

from cryptography.fernet import Fernet

from config import MASTER_KEY


def sha256_hex(val: str) -> str:
    """Hex SHA-256 of a UTF-8 string (tokens, PAT hashes, etc.)."""
    return sha256((val or "").encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    key = urlsafe_b64encode(sha256(MASTER_KEY.encode()).digest())
    return Fernet(key)


def encrypt(val: str) -> str:
    return _fernet().encrypt(val.encode()).decode()


def decrypt(val: str) -> str:
    return _fernet().decrypt(val.encode()).decode()
