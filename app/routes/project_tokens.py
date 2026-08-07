"""Project machine tokens and team machine list."""

import logging
import secrets
from datetime import datetime, timedelta, timezone

from flask import flash, redirect, render_template, request, session, url_for

import authz
import config
import db
from crypto import sha256_hex
from secret_kinds import annotate_token_expiry

log = logging.getLogger(__name__)


def register(app):

    @app.get("/machines")
    @authz.login_required
    def machines_list():
        tid = session.get("team_id")
        team, tokens = None, []
        if tid:
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
                team = cur.fetchone()
                if team:
                    cur.execute(
                        """
                        SELECT mt.id, mt.name, mt.token_prefix, mt.role,
                               mt.created_at, mt.expires_at,
                               p.id AS project_id, p.name AS project_name
                        FROM api.machine_tokens mt
                        JOIN api.projects p ON p.id = mt.project_id
                        WHERE p.team_id = %s
                        ORDER BY p.name, mt.name
                        """,
                        (tid,),
                    )
                    tokens = annotate_token_expiry(cur.fetchall())
        return render_template("machines.html", team=team, tokens=tokens)


    @app.post("/projects/<uuid:project_id>/tokens")
    @authz.login_required
    def create_token(project_id):
        name = request.form.get("name", "machine").strip() or "machine"
        role = (request.form.get("role") or "read-only").strip()
        if role not in config.MACHINE_TOKEN_ROLES:
            role = "read-only"
        return_tab = (request.form.get("return_tab") or "tokens").strip().lower()
        if return_tab not in (
            "secrets",
            "audit",
            "tokens",
            "import",
            "integrations",
            "settings",
        ):
            return_tab = "tokens"

        def _token_redirect():
            return redirect(
                url_for("project_detail", project_id=project_id, tab=return_tab)
            )

        expires_at = None
        days_raw = (request.form.get("expires_days") or "").strip()
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            # Explicit write gate (read-only can list tokens, not create them)
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return _token_redirect()
            if not days_raw:
                cur.execute(
                    """
                    SELECT t.default_token_days
                    FROM api.projects p JOIN api.teams t ON t.id = p.team_id
                    WHERE p.id = %s
                    """,
                    (str(project_id),),
                )
                row = cur.fetchone() or {}
                if row.get("default_token_days"):
                    days_raw = str(row["default_token_days"])
            if days_raw:
                try:
                    days = int(days_raw)
                except ValueError:
                    flash("Expires days must be a positive integer", "error")
                    return _token_redirect()
                if days < 1 or days > config.MAX_EXPIRY_DAYS:
                    flash(
                        f"Expires days must be between 1 and {config.MAX_EXPIRY_DAYS}",
                        "error",
                    )
                    return _token_redirect()
                expires_at = datetime.now(timezone.utc) + timedelta(days=days)
            raw = "ss_" + secrets.token_urlsafe(32)
            thash = sha256_hex(raw)
            prefix = raw[:11]
            try:
                cur.execute(
                    """
                    INSERT INTO api.machine_tokens
                      (project_id, name, token_hash, token_prefix, role, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (str(project_id), name, thash, prefix, role, expires_at),
                )
                if cur.rowcount == 0:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                    return _token_redirect()
                conn.commit()
            except Exception as e:
                flash(str(e), "error")
                return _token_redirect()
        session["new_token"] = raw  # shown once
        flash("Machine account created — copy the token now; it is shown once", "ok")
        return _token_redirect()


    @app.post("/projects/<uuid:project_id>/tokens/<uuid:token_id>/delete")
    @authz.login_required
    def delete_token(project_id, token_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))
            cur.execute(
                "DELETE FROM api.machine_tokens WHERE id = %s AND project_id = %s",
                (str(token_id), str(project_id)),
            )
            if cur.rowcount == 0:
                flash("You don't have permission to do that", "error")
            conn.commit()
        return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))
