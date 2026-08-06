"""Projects, secrets, machine tokens, trash."""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone

from flask import flash, redirect, render_template, request, session, url_for

import audit
import authz
import config
import crypto
import db
import paging

log = logging.getLogger(__name__)


def _load_secrets_page(cur, project_id, page, q):
    """Count + page live secrets for a project. Returns (rows, pager)."""
    where = "project_id = %s AND deleted_at IS NULL"
    params = [str(project_id)]
    if q:
        where += " AND (key ILIKE %s OR note ILIKE %s)"
        like = f"%{q}%"
        params.extend([like, like])
    cur.execute(f"SELECT count(*) AS n FROM api.secrets WHERE {where}", params)
    total = int((cur.fetchone() or {}).get("n") or 0)
    pager = paging.page_window(total, page)
    pager.update(
        endpoint="project_detail",
        project_id=project_id,
        tab="secrets",
        q=q,
    )
    cur.execute(
        f"""
        SELECT id, key, note, created_at, updated_at FROM api.secrets
        WHERE {where}
        ORDER BY key
        LIMIT %s OFFSET %s
        """,
        (*params, pager["limit"], pager["offset"]),
    )
    return cur.fetchall(), pager


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
        q = (request.args.get("q") or "").strip()
        team, secrets = None, []
        if tid:
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
                team = cur.fetchone()
                if team:
                    sql = """
                        SELECT s.id, s.key, s.note, s.updated_at,
                               p.id AS project_id, p.name AS project_name
                        FROM api.secrets s
                        JOIN api.projects p ON p.id = s.project_id
                        WHERE p.team_id = %s AND s.deleted_at IS NULL
                    """
                    params = [tid]
                    if q:
                        like = f"%{q}%"
                        sql += " AND (s.key ILIKE %s OR s.note ILIKE %s OR p.name ILIKE %s)"
                        params.extend([like, like, like])
                    cur.execute(sql + " ORDER BY p.name, s.key", params)
                    secrets = cur.fetchall()
        return render_template("secrets.html", team=team, secrets=secrets, search_q=q)


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
                    SELECT id, project_id, key FROM api.secrets
                    WHERE id = %s AND deleted_at IS NOT NULL
                      AND api.can_write_project(project_id)
                    """,
                    (str(secret_id),),
                )
                row = cur.fetchone()
                if not row:
                    flash("Could not restore — missing permission or key already exists", "error")
                    conn.commit()
                    return redirect(url_for("trash"))
                cur.execute(
                    """
                    UPDATE api.secrets
                    SET deleted_at = NULL
                    WHERE id = %s AND deleted_at IS NOT NULL
                    """,
                    (str(secret_id),),
                )
                if cur.rowcount == 0:
                    flash("Could not restore — missing permission or key already exists", "error")
                else:
                    audit.log_secret(
                        cur,
                        project_id=row["project_id"],
                        secret_id=row["id"],
                        secret_key=row["key"],
                        action="restored",
                    )
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
                SELECT id, project_id, key FROM api.secrets
                WHERE id = %s AND deleted_at IS NOT NULL
                  AND api.can_write_project(project_id)
                """,
                (str(secret_id),),
            )
            row = cur.fetchone()
            if row:
                audit.log_secret(
                    cur,
                    project_id=row["project_id"],
                    secret_id=row["id"],
                    secret_key=row["key"],
                    action="purged",
                )
                cur.execute(
                    """
                    DELETE FROM api.secrets
                    WHERE id = %s AND deleted_at IS NOT NULL
                    """,
                    (str(secret_id),),
                )
            conn.commit()
        return redirect(url_for("trash"))


    @app.get("/projects/<uuid:project_id>")
    @authz.login_required
    def project_detail(project_id):
        tab = (request.args.get("tab") or "secrets").strip().lower()
        if tab not in ("secrets", "audit", "tokens", "settings"):
            tab = "secrets"
        page = paging.page_arg("page")
        q = (request.args.get("q") or "").strip()
        secrets_pager = None
        audit_pager = None
        secret_rows = []
        audit_rows = []
        tokens = []
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
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = cur.fetchone()["w"]
            cur.execute("SELECT api.team_role(%s) AS r", (str(project["team_id"]),))
            team_role = (cur.fetchone() or {}).get("r")
            # Project delete: team owner/admin (matches projects_delete RLS)
            can_delete = team_role in ("owner", "admin")

            if tab == "settings" and not can_delete:
                tab = "secrets"
            if tab == "secrets":
                secret_rows, secrets_pager = _load_secrets_page(cur, project_id, page, q)
            elif tab == "audit":
                total = audit.count_for_project(cur, project_id, q=q)
                audit_pager = paging.page_window(total, page)
                audit_pager["endpoint"] = "project_detail"
                audit_pager["project_id"] = project_id
                audit_pager["tab"] = "audit"
                audit_pager["q"] = q
                audit_rows = audit.list_for_project(
                    cur,
                    project_id,
                    limit=audit_pager["limit"],
                    offset=audit_pager["offset"],
                    q=q,
                )
            elif tab == "tokens":
                cur.execute(
                    """
                    SELECT id, name, token_prefix, role, created_at, expires_at
                    FROM api.machine_tokens
                    WHERE project_id = %s
                    ORDER BY created_at DESC
                    """,
                    (str(project_id),),
                )
                tokens = cur.fetchall()
            # settings: no extra queries
        return render_template(
            "project.html",
            project=project,
            project_id=project_id,
            secrets=secret_rows,
            tokens=tokens,
            audit_log=audit_rows,
            secrets_pager=secrets_pager,
            audit_pager=audit_pager,
            can_write=can_write,
            can_delete=can_delete,
            active_tab=tab,
            search_q=q,
            new_token=session.pop("new_token", None),
        )


    @app.post("/projects/<uuid:project_id>/delete")
    @authz.login_required
    def delete_project(project_id):
        """Delete project (and secrets/tokens via CASCADE). Team owner/admin only."""
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT p.team_id, api.team_role(p.team_id) AS r
                FROM api.projects p WHERE p.id = %s
                """,
                (str(project_id),),
            )
            row = cur.fetchone()
            if not row:
                flash("Project not found", "error")
                return redirect(url_for("projects_list"))
            team_id = row["team_id"]
            if row["r"] not in ("owner", "admin"):
                flash("Only team owners or admins can delete projects", "error")
                return redirect(url_for("project_detail", project_id=project_id))
            cur.execute("DELETE FROM api.projects WHERE id = %s", (str(project_id),))
            if cur.rowcount == 0:
                flash("You don't have permission to do that", "error")
                conn.rollback()
                return redirect(url_for("project_detail", project_id=project_id))
            conn.commit()
        flash("Project deleted", "ok")
        return redirect(url_for("team_detail", team_id=team_id))


    @app.post("/projects/<uuid:project_id>/secrets")
    @authz.login_required
    def create_secret(project_id):
        key = request.form["key"].strip()
        value = request.form["value"]
        note = request.form.get("note", "").strip()
        if not key or value is None:
            flash("Key and value required", "error")
            return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    SELECT id FROM api.secrets
                    WHERE project_id = %s AND key = %s AND deleted_at IS NULL
                    """,
                    (str(project_id), key),
                )
                existing = cur.fetchone()
                cur.execute(
                    """
                    INSERT INTO api.secrets (project_id, key, value_enc, note)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
                      SET value_enc = EXCLUDED.value_enc, note = EXCLUDED.note
                    RETURNING id
                    """,
                    (str(project_id), key, crypto.encrypt(value), note),
                )
                row = cur.fetchone()
                if not row:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    audit.log_secret(
                        cur,
                        project_id=project_id,
                        secret_id=row["id"],
                        secret_key=key,
                        action="updated" if existing else "created",
                    )
                    conn.commit()
            except Exception as e:
                flash(str(e), "error")
        if authz.htmx():
            return _secrets_partial(project_id)
        return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/delete")
    @authz.login_required
    def delete_secret(project_id, secret_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, key FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                flash("Secret not found", "error")
            else:
                cur.execute(
                    """
                    UPDATE api.secrets SET deleted_at = now()
                    WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                    """,
                    (str(secret_id), str(project_id)),
                )
                if cur.rowcount == 0:
                    # SELECT allowed (read), UPDATE blocked (write) — e.g. read-only role
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    audit.log_secret(
                        cur,
                        project_id=project_id,
                        secret_id=row["id"],
                        secret_key=row["key"],
                        action="deleted",
                    )
                    conn.commit()
        if authz.htmx():
            return _secrets_partial(project_id)
        return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))


    @app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/reveal")
    @authz.login_required
    def reveal_secret(project_id, secret_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, key, value_enc FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=row["id"],
                secret_key=row["key"],
                action="revealed",
            )
            conn.commit()
        return render_template(
            "partials/reveal.html",
            value=crypto.decrypt(row["value_enc"]),
            secret_id=secret_id,
            project_id=project_id,
        )


    def _secrets_partial(project_id):
        page = paging.page_arg("page")
        q = (request.args.get("q") or request.form.get("q") or "").strip()
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            rows, secrets_pager = _load_secrets_page(cur, project_id, page, q)
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = cur.fetchone()["w"]
        return render_template(
            "partials/secrets.html",
            secrets=rows,
            project_id=project_id,
            can_write=can_write,
            secrets_pager=secrets_pager,
            search_q=q,
        )


    @app.post("/projects/<uuid:project_id>/tokens")
    @authz.login_required
    def create_token(project_id):
        name = request.form.get("name", "machine").strip() or "machine"
        role = (request.form.get("role") or "read-only").strip()
        if role not in config.MACHINE_TOKEN_ROLES:
            role = "read-only"
        expires_at = None
        days_raw = (request.form.get("expires_days") or "").strip()
        if days_raw:
            try:
                days = int(days_raw)
                if days > 0:
                    expires_at = datetime.now(timezone.utc) + timedelta(days=days)
            except ValueError:
                flash("Expires days must be a positive integer", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            # Explicit write gate (read-only can list tokens, not create them)
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))
            raw = "ss_" + secrets.token_urlsafe(32)
            thash = hashlib.sha256(raw.encode()).hexdigest()
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
                    return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))
                conn.commit()
            except Exception as e:
                flash(str(e), "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))
        session["new_token"] = raw  # shown once
        return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))


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


