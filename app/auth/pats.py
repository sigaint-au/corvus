"""Personal access tokens (user-scoped, long-lived). Exchange for PostgREST JWT via /api/token."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from core import db, settings_svc
from crypto import sha256_hex

PREFIX = "pat_"
MAX_NAME_LEN = 80
MAX_TOKENS_PER_USER = 50


def mint_raw() -> tuple[str, str, str]:
    """Generate a new personal access token and its stored metadata.

    Args:
        None.

    Returns:
        Tuple ``(raw_token, token_hash, token_prefix)`` where:
        - ``raw_token`` is shown once to the user (``pat_`` + urlsafe secret)
        - ``token_hash`` is the SHA-256 hex to store
        - ``token_prefix`` is the first 12 characters for UI identification

    Example:
        >>> raw, thash, prefix = mint_raw()
        >>> raw.startswith("pat_")
        True
        >>> len(thash)
        64
    """
    raw = PREFIX + secrets.token_urlsafe(32)
    thash = sha256_hex(raw)
    return raw, thash, raw[:12]


def list_for_user(user_id: str) -> list[dict]:
    """List PAT metadata for a user (never returns the raw token).

    Args:
        user_id: UUID of the token owner.

    Returns:
        List of dicts with ``id``, ``name``, ``token_prefix``, ``expires_at``,
        ``last_used_at``, ``created_at``, newest first.

    Example:
        >>> tokens = list_for_user(session["user_id"])
        >>> for t in tokens:
        ...     print(t["name"], t["token_prefix"])
    """
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, name, token_prefix, expires_at, last_used_at, created_at
            FROM private.personal_access_tokens
            WHERE user_id = %s::uuid
            ORDER BY created_at DESC
            """,
            (str(user_id),),
        )
        return cur.fetchall() or []


def count_for_user(user_id: str) -> int:
    """Count how many PATs the user currently has.

    Args:
        user_id: UUID of the user.

    Returns:
        Integer count (0 if none).

    Example:
        >>> if count_for_user(uid) >= MAX_TOKENS_PER_USER:
        ...     raise ValueError("limit reached")
    """
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT count(*)::int AS n
            FROM private.personal_access_tokens
            WHERE user_id = %s::uuid
            """,
            (str(user_id),),
        )
        row = cur.fetchone() or {}
        return int(row.get("n") or 0)


def create(user_id: str, name: str, expires_days: int | None = None) -> str:
    """Create a PAT for the user and return the raw token (shown once).

    Args:
        user_id: UUID of the owner.
        name: Human label (required, truncated to ``MAX_NAME_LEN``).
        expires_days: Optional lifetime in days (1–3650). ``None`` means no expiry.

    Returns:
        Plaintext raw token string (``pat_...``). Store only the hash server-side.

    Raises:
        ValueError: Missing name, over token limit, or invalid ``expires_days``.

    Example:
        >>> raw = create(uid, "CI bot", expires_days=90)
        >>> # Show raw once; cannot retrieve later
    """
    name = (name or "").strip()[:MAX_NAME_LEN]
    if not name:
        raise ValueError("Name is required")
    if count_for_user(user_id) >= MAX_TOKENS_PER_USER:
        raise ValueError(f"Limit of {MAX_TOKENS_PER_USER} tokens reached; revoke one first")
    require_expiry, max_days = settings_svc.token_expiry_policy("pat")
    if expires_days is None:
        if require_expiry:
            raise ValueError("Expires days is required")
        expires_at = None
    else:
        try:
            days = int(expires_days)
        except (TypeError, ValueError):
            raise ValueError("Expires days must be a positive integer")
        if days < 1 or days > max_days:
            raise ValueError(f"Expires days must be between 1 and {max_days}")
        expires_at = datetime.now(timezone.utc) + timedelta(days=days)
    raw, thash, prefix = mint_raw()
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO private.personal_access_tokens
              (user_id, name, token_hash, token_prefix, expires_at)
            VALUES (%s::uuid, %s, %s, %s, %s)
            """,
            (str(user_id), name, thash, prefix, expires_at),
        )
    return raw


def revoke(user_id: str, token_id: str) -> bool:
    """Delete a PAT owned by the user.

    Args:
        user_id: UUID of the owner (must match the row).
        token_id: UUID of the PAT row to delete.

    Returns:
        True if a row was deleted; False if not found or not owned.

    Example:
        >>> if revoke(session["user_id"], token_id):
        ...     flash("Token revoked")
    """
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM private.personal_access_tokens
            WHERE id = %s::uuid AND user_id = %s::uuid
            """,
            (str(token_id), str(user_id)),
        )
        return cur.rowcount > 0


def resolve(raw: str) -> str | None:
    """Validate a raw PAT and return the owning user_id.

    Updates ``last_used_at`` on success. Rejects disabled users and expired tokens.

    Args:
        raw: Full plaintext token from Authorization or form field.

    Returns:
        User UUID string on success, or None if invalid/expired/disabled.

    Example:
        >>> uid = resolve(request.headers.get("Authorization", "").removeprefix("Bearer "))
        >>> if uid:
        ...     jwt = make_jwt(uid)
    """
    raw = (raw or "").strip()
    if not raw.startswith(PREFIX) or len(raw) < 20:
        return None
    thash = sha256_hex(raw)
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT t.id, t.user_id::text AS user_id
            FROM private.personal_access_tokens t
            JOIN private.users u ON u.id = t.user_id
            WHERE t.token_hash = %s
              AND u.disabled_at IS NULL
              AND (t.expires_at IS NULL OR t.expires_at > now())
            """,
            (thash,),
        )
        row = cur.fetchone()
        if not row:
            return None
        cur.execute(
            """
            UPDATE private.personal_access_tokens
            SET last_used_at = now()
            WHERE id = %s::uuid
            """,
            (str(row["id"]),),
        )
        return row["user_id"]


if __name__ == "__main__":
    raw, thash, prefix = mint_raw()
    assert raw.startswith("pat_")
    assert len(thash) == 64
    assert prefix == raw[:12]
    assert sha256_hex(raw) == thash
    print("ok")
