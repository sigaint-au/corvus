"""Bearer-token HTTP helpers (request header parsing)."""

from __future__ import annotations

from flask import request
from crypto import sha256_hex


def bearer_raw() -> str | None:
    """Return the raw Bearer token string, or None if missing/invalid header.

    Args:
        None (reads ``Authorization`` from the current request).

    Returns:
        Token string after ``Bearer ``, or None.

    Example:
        >>> # Authorization: Bearer ss_abc
        >>> bearer_raw()
        'ss_abc'
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    raw = auth[7:].strip()
    return raw or None


def bearer_hash():
    """Return the SHA-256 hex of the Bearer token, or None if absent."""
    raw = bearer_raw()
    return sha256_hex(raw) if raw else None
