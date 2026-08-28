"""Bearer-token classification: machine vs personal access vs CLI session token."""

from __future__ import annotations

from auth import cli_sessions, pats
from crypto import sha256_hex


def classify_token(raw: str | None) -> tuple[str | None, str | None]:
    """Classify a raw Bearer token into ``(kind, identity)``.

    - ``("pat", user_id)`` for a valid ``pat_…`` token (resolves & bumps usage).
    - ``("sso", user_id)`` for a valid ``sso_…`` CLI session token (short-lived).
    - ``("machine", sha256_hex)`` for any other non-empty token (machine token).
    - ``(None, None)`` when the token is empty, or a PAT/sso token that fails to
      resolve (invalid/expired/disabled user).

    Example:
        >>> classify_token("pat_abc…")       # ("pat", "<user-uuid>")
        >>> classify_token("sso_xyz…")       # ("sso", "<user-uuid>")
        >>> classify_token("ss_xyz")         # ("machine", "<sha256>")
        >>> classify_token(None)             # (None, None)
    """
    if not raw:
        return None, None
    if raw.startswith(pats.PREFIX):
        uid = pats.resolve(raw)
        return ("pat", uid) if uid else (None, None)
    if raw.startswith(cli_sessions.PREFIX):
        uid = cli_sessions.resolve(raw)
        return ("sso", uid) if uid else (None, None)
    return "machine", sha256_hex(raw)
