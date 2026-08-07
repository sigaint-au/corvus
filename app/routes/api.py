"""JSON API helpers (PostgREST JWT)."""

import logging

from flask import jsonify, request, session

import authz
import config
import db

log = logging.getLogger(__name__)


def register(app):
    @app.get("/api/token")
    @authz.login_required
    def api_token():
        """Return JWT for PostgREST (Authorization: Bearer ...)."""
        return jsonify(
            {
                "access_token": db.make_jwt(session["user_id"]),
                "token_type": "bearer",
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
