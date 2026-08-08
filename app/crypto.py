"""Fernet encryption for secret values and sensitive settings."""
from base64 import urlsafe_b64encode
from functools import lru_cache
from hashlib import sha256

from cryptography.fernet import Fernet

from config import MASTER_KEY


def sha256_hex(val: str) -> str:
    """Return the hex-encoded SHA-256 digest of a UTF-8 string.

    Used for tokens, PAT hashes, invite tokens, and other one-way digests.

    Args:
        val: Input string to hash. ``None`` or empty is treated as ``""``.

    Returns:
        Lowercase hex SHA-256 digest (64 characters).

    Example:
        >>> sha256_hex("pat_abc123")
        'e3b0c442...'  # 64-char hex string
        >>> len(sha256_hex("secret"))
        64
    """
    return sha256((val or "").encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    """Build and cache the Fernet instance derived from ``MASTER_KEY``.

    The key is SHA-256 of ``MASTER_KEY``, then url-safe base64-encoded to
    satisfy Fernet's 32-byte key requirement. Cached for process lifetime.

    Args:
        None.

    Returns:
        A ``cryptography.fernet.Fernet`` instance ready to encrypt/decrypt.

    Example:
        >>> f = _fernet()
        >>> isinstance(f, Fernet)
        True
    """
    key = urlsafe_b64encode(sha256(MASTER_KEY.encode()).digest())
    return Fernet(key)


def encrypt(val: str) -> str:
    """Encrypt a plaintext string with the app master key (Fernet).

    Args:
        val: Plaintext UTF-8 string to encrypt (e.g. secret value, SMTP password).

    Returns:
        Fernet token as a UTF-8 string (safe to store in the database).

    Example:
        >>> token = encrypt("db-password")
        >>> token.startswith("gAAAA")
        True
        >>> decrypt(token)
        'db-password'
    """
    return _fernet().encrypt(val.encode()).decode()


def decrypt(val: str) -> str:
    """Decrypt a Fernet token produced by :func:`encrypt`.

    Args:
        val: Fernet ciphertext string previously returned by :func:`encrypt`.

    Returns:
        Original plaintext UTF-8 string.

    Raises:
        cryptography.fernet.InvalidToken: If the token is corrupt or was
            encrypted with a different master key.

    Example:
        >>> decrypt(encrypt("hello"))
        'hello'
    """
    return _fernet().decrypt(val.encode()).decode()
