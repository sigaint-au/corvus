"""Shared user-identity lookups (resolve user id/email under RLS)."""

from __future__ import annotations

from lib.validate import is_uuid


def lookup_user_id(cur, email_or_id: str) -> str | None:
    """Resolve a user UUID from an email address or UUID string.

    Returns None when no matching user exists.
    """
    ref = (email_or_id or "").strip()
    if not ref:
        return None
    if is_uuid(ref):
        return ref.lower()
    cur.execute("SELECT private.lookup_user(%s) AS id", (ref.lower(),))
    r = cur.fetchone() or {}
    return str(r["id"]) if r.get("id") else None


def user_email(cur, user_id: str) -> str:
    """Best-effort email lookup for a user id (empty string when missing)."""
    if not user_id:
        return ""
    try:
        cur.execute(
            "SELECT email FROM private.users WHERE id = %s::uuid",
            (user_id,),
        )
        r = cur.fetchone() or {}
        return (r.get("email") or "").strip()
    except Exception:
        return ""
