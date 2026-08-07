"""Personal access tokens (user-scoped, long-lived). Exchange for PostgREST JWT via /api/token."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import db

PREFIX = "pat_"
MAX_NAME_LEN = 80
MAX_TOKENS_PER_USER = 50


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def mint_raw() -> tuple[str, str, str]:
    """Return (raw_token, token_hash, token_prefix)."""
    raw = PREFIX + secrets.token_urlsafe(32)
    thash = _hash(raw)
    return raw, thash, raw[:12]


def list_for_user(user_id: str) -> list[dict]:
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
    """Create PAT; returns raw token (shown once). Raises ValueError on bad input."""
    name = (name or "").strip()[:MAX_NAME_LEN]
    if not name:
        raise ValueError("Name is required")
    if count_for_user(user_id) >= MAX_TOKENS_PER_USER:
        raise ValueError(f"Limit of {MAX_TOKENS_PER_USER} tokens reached; revoke one first")
    expires_at = None
    if expires_days is not None:
        if expires_days < 1 or expires_days > 3650:
            raise ValueError("Expires days must be between 1 and 3650")
        expires_at = datetime.now(timezone.utc) + timedelta(days=int(expires_days))
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
    """Validate raw PAT; return user_id or None. Updates last_used_at on success."""
    raw = (raw or "").strip()
    if not raw.startswith(PREFIX) or len(raw) < 20:
        return None
    thash = _hash(raw)
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
    assert _hash(raw) == thash
    print("ok")
