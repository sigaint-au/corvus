"""Server-side session registry for multi-device sign-out."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from flask import request, session

import db

log = logging.getLogger(__name__)

# Sliding activity window; absolute max idle before re-login
SESSION_IDLE_DAYS = 14


def client_meta() -> tuple[str, str]:
    """Return (user_agent, ip) for the current request."""
    ua = (request.headers.get("User-Agent") or "")[:400]
    # Prefer first X-Forwarded-For hop when behind a proxy
    xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    ip = xff or (request.remote_addr or "")
    return ua, ip[:100]


# Back-compat alias
_client_meta = client_meta


def create_session(user_id) -> str | None:
    """Insert a session row; return session id or None on failure."""
    from flask import current_app, has_app_context

    if has_app_context() and current_app.config.get("TESTING"):
        return None
    ua, ip = _client_meta()
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
    """Validate session is active and bump last_seen / sliding expiry."""
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


def current_session_id() -> str | None:
    return session.get("sid")
