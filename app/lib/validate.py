"""Shared value-validation helpers (UUID canonical-form checks)."""

from __future__ import annotations

import re

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def is_uuid(value) -> bool:
    """Return True when ``value`` is a canonical dash-delimited UUID string.

    Empty/None and non-string inputs return False.
    """
    if not value:
        return False
    return bool(UUID_RE.match(str(value)))
