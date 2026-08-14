"""Bearer-token classification: machine vs personal access token."""

from __future__ import annotations

import pats
from crypto import sha256_hex


def classify_token(raw: str | None) -> tuple[str | None, str | None]:
    """Classify a raw Bearer token into ``(kind, identity)``.

    - ``("pat", user_id)`` for a valid ``pat_…`` token (resolves & bumps usage).
    - ``("machine", sha256_hex)`` for any other non-empty token (machine token).
    - ``(None, None)`` when the token is empty, or a PAT that fails to resolve
      (invalid/expired/disabled user).

    Example:
        >>> classify_token("pat_abc…")       # ("pat", "<user-uuid>")
        >>> classify_token("ss_xyz")         # ("machine", "<sha256>")
        >>> classify_token(None)             # (None, None)
    """
    if not raw:
        return None, None
    if raw.startswith(pats.PREFIX):
        uid = pats.resolve(raw)
        return ("pat", uid) if uid else (None, None)
    return "machine", sha256_hex(raw)
