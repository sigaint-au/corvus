"""JSON API helpers (PostgREST JWT)."""

import logging

from flask import jsonify, redirect, request, session, url_for

import authz
import config
import db
import pats

log = logging.getLogger(__name__)


def register(app):
    @app.get("/api/token")
    def api_token():
        """Return short-lived JWT for PostgREST.

        Auth: browser session, or ``Authorization: Bearer pat_…`` personal access token.
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
                "expires_in": 24 * 3600,
                "postgrest": config.POSTGREST_URL,
            }
        )

    @app.get("/api/users/suggest")
    @authz.login_required
    def users_suggest():
        """
        Autocomplete for member/admin email fields.
        Global admins see all active users; others see users who share a team.
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
                        JOIN api.team_members tm ON tm.user_id = u.id
                        WHERE u.disabled_at IS NULL
                          AND (u.email ILIKE %s OR u.name ILIKE %s)
                          AND tm.team_id IN (
                            SELECT team_id FROM api.team_members
                            WHERE user_id = %s::uuid
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
                        f"{r['name']} <{r['email']}>"
                        if (r.get("name") or "").strip()
                        else r["email"]
                    ),
                }
                for r in rows
            ]
        )
