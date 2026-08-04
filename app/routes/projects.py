"""Projects, secrets, machine tokens, trash."""

import hashlib
import secrets

from flask import flash, redirect, render_template, request, session, url_for

import authz
import crypto
import db


log = __import__("logging").getLogger(__name__)


def register(app):
    # ── Projects / Secrets ─────────────────────────────────────────────


    @app.get("/projects")
    @authz.login_required
    def projects_list():
        tid = session.get("team_id")
        team, projects = None, []
        if tid:
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
                team = cur.fetchone()
                if team:
                    cur.execute(
                        "SELECT * FROM api.projects WHERE team_id = %s ORDER BY name",
                        (tid,),
                    )
                    projects = cur.fetchall()
        return render_template("projects.html", team=team, projects=projects)


    @app.get("/secrets")
    @authz.login_required
    def secrets_list():
        tid = session.get("team_id")
        team, secrets = None, []
        if tid:
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
                team = cur.fetchone()
                if team:
                    cur.execute(
                        """
                        SELECT s.id, s.key, s.note, s.updated_at,
                               p.id AS project_id, p.name AS project_name
                        FROM api.secrets s
                        JOIN api.projects p ON p.id = s.project_id
                        WHERE p.team_id = %s AND s.deleted_at IS NULL
                        ORDER BY p.name, s.key
                        """,
                        (tid,),
                    )
                    secrets = cur.fetchall()
        return render_template("secrets.html", team=team, secrets=secrets)


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
                        SELECT mt.id, mt.name, mt.token_prefix, mt.created_at,
                               p.id AS project_id, p.name AS project_name
                        FROM api.machine_tokens mt
                        JOIN api.projects p ON p.id = mt.project_id
                        WHERE p.team_id = %s
                        ORDER BY p.name, mt.name
                        """,
                        (tid,),
                    )
                    tokens = cur.fetchall()
        return render_template("machines.html", team=team, tokens=tokens)


    @app.get("/trash")
    @authz.login_required
    def trash():
        tid = session.get("team_id")
        team, items = None, []
        if tid:
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
                team = cur.fetchone()
                if team:
                    cur.execute(
                        """
                        SELECT s.id, s.key, s.note, s.deleted_at, s.project_id,
                               p.name AS project_name,
                               api.can_write_project(s.project_id) AS can_write
                        FROM api.secrets s
                        JOIN api.projects p ON p.id = s.project_id
                        WHERE p.team_id = %s AND s.deleted_at IS NOT NULL
                        ORDER BY s.deleted_at DESC
                        """,
                        (tid,),
                    )
                    items = cur.fetchall()
        return render_template("trash.html", team=team, items=items)


    @app.post("/trash/secrets/<uuid:secret_id>/restore")
    @authz.login_required
    def restore_secret(secret_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    UPDATE api.secrets
                    SET deleted_at = NULL, updated_at = now()
                    WHERE id = %s AND deleted_at IS NOT NULL
                      AND api.can_write_project(project_id)
                    """,
                    (str(secret_id),),
                )
                if cur.rowcount == 0:
                    flash("Could not restore — missing permission or key already exists", "error")
                else:
                    flash("Secret restored", "ok")
                conn.commit()
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("trash"))


    @app.post("/trash/secrets/<uuid:secret_id>/purge")
    @authz.login_required
    def purge_secret(secret_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM api.secrets
                WHERE id = %s AND deleted_at IS NOT NULL
                  AND api.can_write_project(project_id)
                """,
                (str(secret_id),),
            )
            conn.commit()
        return redirect(url_for("trash"))


    @app.get("/projects/<uuid:project_id>")
    @authz.login_required
    def project_detail(project_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT p.*, t.name AS team_name, t.id AS team_id
                FROM api.projects p JOIN api.teams t ON t.id = p.team_id
                WHERE p.id = %s
                """,
                (str(project_id),),
            )
            project = cur.fetchone()
            if not project:
                return "Not found", 404
            session["team_id"] = str(project["team_id"])
            cur.execute(
                """
                SELECT id, key, note, created_at, updated_at FROM api.secrets
                WHERE project_id = %s AND deleted_at IS NULL
                ORDER BY key
                """,
                (str(project_id),),
            )
            secret_rows = cur.fetchall()
            cur.execute(
                "SELECT id, name, token_prefix, created_at FROM api.machine_tokens WHERE project_id = %s ORDER BY created_at DESC",
                (str(project_id),),
            )
            tokens = cur.fetchall()
            can_write = False
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = cur.fetchone()["w"]
        return render_template(
            "project.html",
            project=project,
            project_id=project_id,
            secrets=secret_rows,
            tokens=tokens,
            can_write=can_write,
            new_token=session.pop("new_token", None),
        )


    @app.post("/projects/<uuid:project_id>/secrets")
    @authz.login_required
    def create_secret(project_id):
        key = request.form["key"].strip()
        value = request.form["value"]
        note = request.form.get("note", "").strip()
        if not key or value is None:
            flash("Key and value required", "error")
            return redirect(url_for("project_detail", project_id=project_id))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO api.secrets (project_id, key, value_enc, note)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
                      SET value_enc = EXCLUDED.value_enc, note = EXCLUDED.note, updated_at = now()
                    """,
                    (str(project_id), key, crypto.encrypt(value), note),
                )
                conn.commit()
            except Exception as e:
                flash(str(e), "error")
        if authz.htmx():
            return _secrets_partial(project_id)
        return redirect(url_for("project_detail", project_id=project_id))


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/delete")
    @authz.login_required
    def delete_secret(project_id, secret_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE api.secrets SET deleted_at = now()
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            conn.commit()
        if authz.htmx():
            return _secrets_partial(project_id)
        return redirect(url_for("project_detail", project_id=project_id))


    @app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/reveal")
    @authz.login_required
    def reveal_secret(project_id, secret_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT value_enc FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                return "Not found", 404
        return render_template(
            "partials/reveal.html",
            value=crypto.decrypt(row["value_enc"]),
            secret_id=secret_id,
            project_id=project_id,
        )


    def _secrets_partial(project_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, key, note, created_at, updated_at FROM api.secrets
                WHERE project_id = %s AND deleted_at IS NULL
                ORDER BY key
                """,
                (str(project_id),),
            )
            rows = cur.fetchall()
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = cur.fetchone()["w"]
        return render_template(
            "partials/secrets.html",
            secrets=rows,
            project_id=project_id,
            can_write=can_write,
        )


    @app.post("/projects/<uuid:project_id>/tokens")
    @authz.login_required
    def create_token(project_id):
        name = request.form.get("name", "machine").strip() or "machine"
        raw = "ss_" + secrets.token_urlsafe(32)
        thash = hashlib.sha256(raw.encode()).hexdigest()
        prefix = raw[:11]
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO api.machine_tokens (project_id, name, token_hash, token_prefix)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (str(project_id), name, thash, prefix),
                )
                conn.commit()
            except Exception as e:
                flash(str(e), "error")
                return redirect(url_for("project_detail", project_id=project_id))
        session["new_token"] = raw  # shown once
        return redirect(url_for("project_detail", project_id=project_id))


    @app.post("/projects/<uuid:project_id>/tokens/<uuid:token_id>/delete")
    @authz.login_required
    def delete_token(project_id, token_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM api.machine_tokens WHERE id = %s AND project_id = %s",
                (str(token_id), str(project_id)),
            )
            conn.commit()
        return redirect(url_for("project_detail", project_id=project_id))


