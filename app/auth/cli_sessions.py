"""Short-lived CLI session tokens (user-scoped, single-purpose login handoff).

Minted by the "Copy login command" flow so a user can paste a ready-made
``corvus login`` command without exposing a long-lived PAT. Opaque ``sso_…``
tokens, SHA-256 hashed at rest, multi-use within a fixed TTL.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from core import db, settings_svc
from crypto import sha256_hex

PREFIX = "sso_"
DEFAULT_TTL_SECONDS = 3600


def ttl_seconds() -> int:
    """Return the CLI session token lifetime in seconds (clamped to >= 60).

    Reads ``cli_session_ttl_seconds`` from server settings (default 3600).
    """
    return max(60, settings_svc.int_setting("cli_session_ttl_seconds", DEFAULT_TTL_SECONDS))


def mint_raw() -> tuple[str, str, str]:
    """Generate a new CLI session token and its stored metadata.

    Returns:
        Tuple ``(raw_token, token_hash, token_prefix)`` mirroring ``pats``.
    """
    raw = PREFIX + secrets.token_urlsafe(32)
    return raw, sha256_hex(raw), raw[:12]


def create(user_id: str) -> str:
    """Mint a CLI session token for a user and return the raw token (shown once).

    Args:
        user_id: UUID of the owner.

    Returns:
        Plaintext raw token (``sso_…``). Only the SHA-256 hash is stored.
    """
    raw, thash, prefix = mint_raw()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds())
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO private.cli_session_tokens
              (user_id, token_hash, token_prefix, expires_at)
            VALUES (%s::uuid, %s, %s, %s)
            """,
            (str(user_id), thash, prefix, expires_at),
        )
    return raw


def resolve(raw: str) -> str | None:
    """Validate a raw CLI session token and return the owning user_id.

    Updates ``last_used_at`` on success (multi-use). Rejects disabled users and
    expired tokens.

    Args:
        raw: Full plaintext token from an Authorization header.

    Returns:
        User UUID string on success, or None if invalid/expired/disabled.
    """
    raw = (raw or "").strip()
    if not raw.startswith(PREFIX) or len(raw) < 20:
        return None
    thash = sha256_hex(raw)
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT t.id, t.user_id::text AS user_id
            FROM private.cli_session_tokens t
            JOIN private.users u ON u.id = t.user_id
            WHERE t.token_hash = %s
              AND u.disabled_at IS NULL
              AND t.expires_at > now()
            """,
            (thash,),
        )
        row = cur.fetchone()
        if not row:
            return None
        cur.execute(
            """
            UPDATE private.cli_session_tokens
            SET last_used_at = now()
            WHERE id = %s::uuid
            """,
            (str(row["id"]),),
        )
        return row["user_id"]


if __name__ == "__main__":
    raw, thash, prefix = mint_raw()
    assert raw.startswith("sso_")
    assert len(thash) == 64
    assert prefix == raw[:12]
    assert sha256_hex(raw) == thash
    print("ok")
