"""JSON API helpers (PostgREST JWT)."""

import logging

from flask import jsonify, redirect, request, session, url_for

from auth import authz, pats
from core import config, db

log = logging.getLogger(__name__)


def register(app):
    """Register browser-session and personal-token API routes."""
    app.get("/api/token")(api_token)
    app.get("/api/users/suggest")(users_suggest)


def api_token():
    """Return a short-lived JWT for PostgREST API access.

    Auth: browser session, or ``Authorization: Bearer pat_…`` personal
    access token. Unauthenticated JSON/XHR clients get 401; browsers are
    redirected to login (or 2FA if pending).

    Args:
        None (reads ``Authorization`` header and Flask session).

    Returns:
        JSON with ``access_token``, ``token_type``, ``expires_in``, and
        ``postgrest`` URL; or 401 JSON; or redirect to login/2FA.

    Example:
        GET /api/token
        GET /api/token with Authorization: Bearer pat_…
    """
    uid = None
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        raw = auth[7:].strip()
        if raw.startswith(pats.PREFIX):
            uid = pats.resolve(raw)
            if not uid:
                return jsonify({"error": "unauthorized"}), 401
    if uid is None:
        if session.get("pending_2fa_uid"):
            return redirect(url_for("login_2fa"))
        if not session.get("user_id"):
            # JSON clients get 401; browsers without session go to login
            wants_json = (
                "application/json" in (request.headers.get("Accept") or "")
                or request.headers.get("X-Requested-With") == "XMLHttpRequest"
            )
            if wants_json or auth:
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        uid = session["user_id"]
    return jsonify(
        {
            "access_token": db.make_jwt(uid),
            "token_type": "bearer",
            "expires_in": 1 * 3600,
            "postgrest": config.POSTGREST_URL,
        }
    )


@authz.login_required
def users_suggest():
    """Autocomplete user emails for member/admin fields.

    Global admins see all active users; others only users who share a team.
    Empty query returns an empty list.

    Args:
        None (reads query ``q``; uses session ``user_id``).

    Returns:
        JSON list of objects with ``email``, ``name``, and ``label``.

    Example:
        GET /api/users/suggest?q=ada
    """
    q = (request.args.get("q") or "").strip().lower()[:80]
    if len(q) < 1:
        return jsonify([])
    uid = session["user_id"]
    like = f"%{q}%"
    rows = []
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            if authz.is_global_admin(uid):
                cur.execute(
                    """
                    SELECT email, name
                    FROM private.users
                    WHERE disabled_at IS NULL
                      AND (email ILIKE %s OR name ILIKE %s)
                    ORDER BY email
                    LIMIT 15
                    """,
                    (like, like),
                )
            else:
                cur.execute(
                    """
                    SELECT DISTINCT u.email, u.name
                    FROM private.users u
                    WHERE u.disabled_at IS NULL
                      AND (u.email ILIKE %s OR u.name ILIKE %s)
                      AND EXISTS (
                        SELECT 1
                        FROM rbac.bindings candidate
                        JOIN rbac.roles candidate_role
                          ON candidate_role.id = candidate.role_id
                        WHERE candidate.subject_kind = 'User'
                          AND candidate.subject_id = u.id
                          AND candidate.scope_kind = 'team'
                          AND candidate_role.name IN (
                            'team-owner', 'team-admin', 'team-member', 'team-viewer'
                          )
                          AND EXISTS (
                            SELECT 1
                            FROM rbac.bindings caller
                            JOIN api.rbac_subjects(%s::uuid) caller_subject
                              ON caller_subject.subject_kind = caller.subject_kind
                             AND caller_subject.subject_id = caller.subject_id
                            WHERE caller.scope_kind = 'team'
                              AND caller.scope_id = candidate.scope_id
                          )
                      )
                    ORDER BY u.email
                    LIMIT 15
                    """,
                    (like, like, uid),
                )
            rows = cur.fetchall() or []
    except Exception:
        log.exception("users_suggest failed")
        return jsonify([])
    return jsonify(
        [
            {
                "email": r["email"],
                "name": r.get("name") or "",
                "label": (
                    f"{r['name']} <{r['email']}>" if (r.get("name") or "").strip() else r["email"]
                ),
            }
            for r in rows
        ]
    )
