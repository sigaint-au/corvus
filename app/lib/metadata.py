"""Metadata validation helpers."""

from __future__ import annotations

import re

# Metadata key: must start with letter/digit, then up to 63 chars of [A-Za-z0-9._-]
META_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
META_VALUE_MAX = 2000


def validate_meta_key(key: str) -> bool:
    """Return True if the key is valid for metadata storage."""
    return bool(META_KEY_RE.match(key or ""))


def clean_meta_value(value: str) -> str:
    """Strip and truncate a metadata value to the platform limit."""
    val = (value or "").strip()
    return val[:META_VALUE_MAX]
