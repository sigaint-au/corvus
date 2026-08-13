"""Server-side session registry for multi-device sign-out."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from flask import request

import db

log = logging.getLogger(__name__)

# Sliding activity window; absolute max idle before re-login
SESSION_IDLE_DAYS = 14


def client_meta() -> tuple[str, str]:
    """Return (user_agent, ip) for the current request.

    Args:
        None.

    Returns:
        Tuple of (user_agent truncated to 400 chars, ip truncated to 100 chars).
        IP prefers the first X-Forwarded-For hop when present.

    Example:
        >>> # ua, ip = client_meta()
        >>> # isinstance(ua, str) and isinstance(ip, str)
    """
    ua = (request.headers.get("User-Agent") or "")[:400]
    # Prefer first X-Forwarded-For hop when behind a proxy
    xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    ip = xff or (request.remote_addr or "")
    return ua, ip[:100]




def create_session(user_id) -> str | None:
    """Insert a session row; return session id or None on failure.

    Args:
        user_id: UUID of the user owning the new session.

    Returns:
        New session UUID string, or None when TESTING is set or insert fails.

    Example:
        >>> # sid = create_session(user_id)
        >>> # sid is None or isinstance(sid, str)
    """
    from flask import current_app, has_app_context

    if has_app_context() and current_app.config.get("TESTING"):
        return None
    ua, ip = client_meta()
    expires = datetime.now(timezone.utc) + timedelta(days=SESSION_IDLE_DAYS)
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO private.user_sessions
                  (user_id, user_agent, ip, expires_at)
                VALUES (%s::uuid, %s, %s, %s)
                RETURNING id
                """,
                (str(user_id), ua, ip, expires),
            )
            row = cur.fetchone()
            return str(row["id"]) if row else None
    except Exception:
        log.exception("create_session failed")
        return None


def touch_session(session_id: str, user_id: str) -> bool:
    """Validate session is active and bump last_seen / sliding expiry.

    Args:
        session_id: UUID of the server-side session row.
        user_id: UUID of the session owner (must match the row).

    Returns:
        True if the session was found, not revoked, and not expired;
        False if missing args, not found, or on DB error.

    Example:
        >>> touch_session("", "user")
        False
    """
    if not session_id or not user_id:
        return False
    expires = datetime.now(timezone.utc) + timedelta(days=SESSION_IDLE_DAYS)
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE private.user_sessions
                SET last_seen_at = now(), expires_at = %s
                WHERE id = %s::uuid
                  AND user_id = %s::uuid
                  AND revoked_at IS NULL
                  AND expires_at > now()
                RETURNING id
                """,
                (expires, session_id, user_id),
            )
            return cur.fetchone() is not None
    except Exception:
        log.exception("touch_session failed")
        return False


def revoke_session(session_id: str, user_id: str) -> bool:
    """Revoke a single active session for a user.

    Args:
        session_id: UUID of the session to revoke.
        user_id: UUID of the session owner (scoped for safety).

    Returns:
        True if a row was revoked (or when TESTING short-circuits);
        False if no matching active session or on DB error.

    Example:
        >>> revoke_session("00000000-0000-0000-0000-000000000000",
        ...                "00000000-0000-0000-0000-000000000001")
        False
    """
    from flask import current_app, has_app_context

    if has_app_context() and current_app.config.get("TESTING"):
        return True
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE private.user_sessions
                SET revoked_at = now()
                WHERE id = %s::uuid AND user_id = %s::uuid AND revoked_at IS NULL
                RETURNING id
                """,
                (session_id, user_id),
            )
            return cur.fetchone() is not None
    except Exception:
        log.exception("revoke_session failed")
        return False


def revoke_other_sessions(user_id: str, keep_session_id: str) -> int:
    """Revoke all of a user's sessions except the current one.

    Args:
        user_id: UUID of the user whose other devices to sign out.
        keep_session_id: Session UUID to leave active.

    Returns:
        Number of sessions revoked, or 0 on error.

    Example:
        >>> n = revoke_other_sessions(
        ...     "00000000-0000-0000-0000-000000000001",
        ...     "00000000-0000-0000-0000-000000000002",
        ... )
        >>> n >= 0
        True
    """
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE private.user_sessions
                SET revoked_at = now()
                WHERE user_id = %s::uuid
                  AND revoked_at IS NULL
                  AND id <> %s::uuid
                """,
                (user_id, keep_session_id),
            )
            return cur.rowcount or 0
    except Exception:
        log.exception("revoke_other_sessions failed")
        return 0


def revoke_all_sessions(user_id: str) -> int:
    """Revoke every active session for a user.

    Args:
        user_id: UUID of the user to sign out everywhere.

    Returns:
        Number of sessions revoked, or 0 on error.

    Example:
        >>> n = revoke_all_sessions("00000000-0000-0000-0000-000000000001")
        >>> n >= 0
        True
    """
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE private.user_sessions
                SET revoked_at = now()
                WHERE user_id = %s::uuid AND revoked_at IS NULL
                """,
                (user_id,),
            )
            return cur.rowcount or 0
    except Exception:
        log.exception("revoke_all_sessions failed")
        return 0


def list_sessions(user_id: str) -> list:
    """List active (non-revoked, non-expired) sessions for a user.

    Args:
        user_id: UUID of the user whose sessions to list.

    Returns:
        List of session row dicts (id, timestamps, user_agent, ip), newest
        last_seen first, up to 50 rows; empty list on error.

    Example:
        >>> sessions = list_sessions("00000000-0000-0000-0000-000000000001")
        >>> isinstance(sessions, list)
        True
    """
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, created_at, last_seen_at, expires_at,
                       user_agent, ip
                FROM private.user_sessions
                WHERE user_id = %s::uuid
                  AND revoked_at IS NULL
                  AND expires_at > now()
                ORDER BY last_seen_at DESC
                LIMIT 50
                """,
                (user_id,),
            )
            return cur.fetchall() or []
    except Exception:
        log.exception("list_sessions failed")
        return []
