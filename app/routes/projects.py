"""Projects, secrets, machine tokens, trash."""

import csv
import hashlib
import io
import json
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import (
    Response,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import audit
import authz
import config
import crypto
import db
import paging

log = logging.getLogger(__name__)

_SOON_DAYS = 14
_ENV_LINE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$"
)


def _as_utc(dt):
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def expires_status(expires_at, soon_days=_SOON_DAYS):
    """Return 'overdue', 'soon', or None for a single expiry timestamp."""
    due = _as_utc(expires_at)
    if due is None:
        return None
    now = datetime.now(timezone.utc)
    if due <= now:
        return "overdue"
    if due <= now + timedelta(days=soon_days):
        return "soon"
    return None


def secret_due_status(row, soon_days=_SOON_DAYS):
    """Return 'overdue', 'soon', or None from expires_at."""
    return expires_status(row.get("expires_at"), soon_days=soon_days)


def _annotate_token_expiry(rows):
    for r in rows:
        r["due"] = expires_status(r.get("expires_at"))
    return rows


def parse_secret_pairs(text: str) -> list[tuple[str, str]]:
    """Parse .env, JSON object/list, or CSV (key,value) into (key, value) pairs."""
    text = (text or "").strip()
    if not text:
        return []
    # JSON
    if text[0] in "{[":
        data = json.loads(text)
        if isinstance(data, dict):
            out = []
            for k, v in data.items():
                if isinstance(v, dict) and "value" in v:
                    out.append((str(k), str(v["value"])))
                elif isinstance(v, dict) and "value_enc" in v:
                    out.append((str(k), {"_enc": v["value_enc"], "note": v.get("note", "")}))
                else:
                    out.append((str(k), "" if v is None else str(v)))
            return out
        if isinstance(data, list):
            out = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                k = item.get("key") or item.get("name")
                if not k:
                    continue
                if "value_enc" in item and "value" not in item:
                    out.append((str(k), {"_enc": item["value_enc"], "note": item.get("note", "")}))
                else:
                    out.append((str(k), "" if item.get("value") is None else str(item.get("value"))))
            return out
        raise ValueError("JSON must be object or array of {key,value}")
    # CSV with header key,value
    first = text.splitlines()[0].lower()
    if "key" in first and "value" in first and ("," in first or "\t" in first):
        delim = "\t" if "\t" in first and first.count("\t") >= first.count(",") else ","
        reader = csv.DictReader(io.StringIO(text), delimiter=delim)
        out = []
        for row in reader:
            k = (row.get("key") or row.get("KEY") or "").strip()
            if k:
                out.append((k, row.get("value") or row.get("VALUE") or ""))
        return out
    # .env
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _ENV_LINE.match(line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out.append((k, v))
    return out


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
        SELECT id, key, note, created_at, updated_at, expires_at
        FROM api.secrets
        WHERE {where}
        ORDER BY key
        LIMIT %s OFFSET %s
        """,
        (*params, pager["limit"], pager["offset"]),
    )
    rows = cur.fetchall()
    for r in rows:
        r["due"] = secret_due_status(r)
    return rows, pager


def _parse_expires_at(form):
    """Return expires_at datetime or None from form (max 10 years ahead)."""
    raw = (form.get("expires_at") or "").strip()
    if not raw:
        return None
    try:
        expires_at = datetime.fromisoformat(raw)
    except ValueError:
        raise ValueError("expires_at must be YYYY-MM-DD or ISO datetime")
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    cap = datetime.now(timezone.utc) + timedelta(days=3650)
    if expires_at > cap:
        raise ValueError("expires_at must be within 10 years")
    return expires_at


def _upsert_secret(
    cur,
    project_id,
    key,
    value_or_enc,
    note="",
    expires_at=None,
    *,
    already_enc=False,
    touch_meta=True,
):
    """Insert/update one secret; returns (id, was_new)."""
    enc = value_or_enc if already_enc else crypto.encrypt(str(value_or_enc))
    cur.execute(
        """
        SELECT id FROM api.secrets
        WHERE project_id = %s AND key = %s AND deleted_at IS NULL
        """,
        (str(project_id), key),
    )
    existing = cur.fetchone()
    if touch_meta:
        cur.execute(
            """
            INSERT INTO api.secrets
              (project_id, key, value_enc, note, expires_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
              SET value_enc = EXCLUDED.value_enc,
                  note = EXCLUDED.note,
                  expires_at = EXCLUDED.expires_at
            RETURNING id
            """,
            (str(project_id), key, enc, note or "", expires_at),
        )
    else:
        cur.execute(
            """
            INSERT INTO api.secrets (project_id, key, value_enc, note)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
              SET value_enc = EXCLUDED.value_enc,
                  note = CASE WHEN EXCLUDED.note = '' THEN api.secrets.note
                              ELSE EXCLUDED.note END
            RETURNING id
            """,
            (str(project_id), key, enc, note or ""),
        )
    row = cur.fetchone()
    return (row["id"] if row else None), (existing is None)


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
                    tokens = _annotate_token_expiry(cur.fetchall())
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
        if tab not in ("secrets", "audit", "tokens", "import", "settings"):
            tab = "secrets"
        page = paging.page_arg("page")
        q = (request.args.get("q") or "").strip()
        secrets_pager = None
        audit_pager = None
        secret_rows = []
        audit_rows = []
        tokens = []
        project_members = []
        default_token_days = None
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT p.*, t.name AS team_name, t.id AS team_id,
                       t.default_token_days
                FROM api.projects p JOIN api.teams t ON t.id = p.team_id
                WHERE p.id = %s
                """,
                (str(project_id),),
            )
            project = cur.fetchone()
            if not project:
                return "Not found", 404
            session["team_id"] = str(project["team_id"])
            default_token_days = project.get("default_token_days")
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = cur.fetchone()["w"]
            cur.execute("SELECT api.team_role(%s) AS r", (str(project["team_id"]),))
            team_role = (cur.fetchone() or {}).get("r")
            # Project delete: team owner/admin (matches projects_delete RLS)
            can_delete = team_role in ("owner", "admin")
            can_settings = bool(can_write or can_delete)

            if tab == "settings" and not can_settings:
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
                tokens = _annotate_token_expiry(cur.fetchall())
            elif tab == "settings":
                cur.execute(
                    "SELECT * FROM private.project_member_rows(%s::uuid)",
                    (str(project_id),),
                )
                project_members = cur.fetchall()
            # import: no extra queries
        return render_template(
            "project.html",
            project=project,
            project_id=project_id,
            secrets=secret_rows,
            tokens=tokens,
            audit_log=audit_rows,
            secrets_pager=secrets_pager,
            audit_pager=audit_pager,
            project_members=project_members,
            project_roles=config.PROJECT_ROLES,
            default_token_days=default_token_days,
            can_write=can_write,
            can_delete=can_delete,
            can_settings=can_settings,
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
        try:
            expires_at = _parse_expires_at(request.form)
        except (ValueError, TypeError) as e:
            flash(str(e), "error")
            return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                sid, was_new = _upsert_secret(
                    cur,
                    project_id,
                    key,
                    value,
                    note=note,
                    expires_at=expires_at,
                )
                if not sid:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    audit.log_secret(
                        cur,
                        project_id=project_id,
                        secret_id=sid,
                        secret_key=key,
                        action="created" if was_new else "updated",
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
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = bool(cur.fetchone()["w"])
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
            editable=True,
            can_write=can_write,
        )


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/value")
    @authz.login_required
    def update_secret_value(project_id, secret_id):
        """In-place update after reveal (archives prior value via trigger)."""
        value = request.form.get("value")
        if value is None:
            return "Value required", 400
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                return "Forbidden", 403
            cur.execute(
                """
                SELECT id, key FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            cur.execute(
                """
                UPDATE api.secrets SET value_enc = %s
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (crypto.encrypt(value), str(secret_id), str(project_id)),
            )
            if cur.rowcount == 0:
                conn.rollback()
                return "Forbidden", 403
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=row["id"],
                secret_key=row["key"],
                action="updated",
            )
            conn.commit()
        if authz.htmx():
            # Hide value again; show brief confirmation in the cell
            return render_template("partials/reveal_saved.html")
        flash("Secret updated", "ok")
        return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))


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


    @app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/history")
    @authz.login_required
    def secret_history(project_id, secret_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, key, note, updated_at, expires_at
                FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            secret = cur.fetchone()
            if not secret:
                return "Not found", 404
            cur.execute(
                """
                SELECT id, note, created_at
                FROM api.secret_versions
                WHERE secret_id = %s
                ORDER BY created_at DESC
                LIMIT 50
                """,
                (str(secret_id),),
            )
            versions = cur.fetchall()
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = cur.fetchone()["w"]
            cur.execute(
                """
                SELECT p.name, p.id, t.name AS team_name, t.id AS team_id
                FROM api.projects p JOIN api.teams t ON t.id = p.team_id
                WHERE p.id = %s
                """,
                (str(project_id),),
            )
            project = cur.fetchone()
        return render_template(
            "secret_history.html",
            project=project,
            secret=secret,
            versions=versions,
            can_write=can_write,
            project_id=project_id,
        )


    @app.get(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/versions/<uuid:version_id>/reveal"
    )
    @authz.login_required
    def reveal_secret_version(project_id, secret_id, version_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT v.value_enc, s.key, s.id AS secret_id
                FROM api.secret_versions v
                JOIN api.secrets s ON s.id = v.secret_id
                WHERE v.id = %s AND s.id = %s AND s.project_id = %s
                  AND s.deleted_at IS NULL
                """,
                (str(version_id), str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=row["secret_id"],
                secret_key=row["key"],
                action="revealed",
            )
            conn.commit()
        return render_template(
            "partials/reveal.html",
            value=crypto.decrypt(row["value_enc"]),
            secret_id=secret_id,
            project_id=project_id,
            editable=False,
            can_write=False,
        )


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/rollback/<uuid:version_id>")
    @authz.login_required
    def rollback_secret(project_id, secret_id, version_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT s.id, s.key, v.value_enc, v.note
                FROM api.secret_versions v
                JOIN api.secrets s ON s.id = v.secret_id
                WHERE v.id = %s AND s.id = %s AND s.project_id = %s
                  AND s.deleted_at IS NULL
                """,
                (str(version_id), str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                flash("Version not found", "error")
                return redirect(
                    url_for("secret_history", project_id=project_id, secret_id=secret_id)
                )
            cur.execute(
                """
                UPDATE api.secrets
                SET value_enc = %s, note = %s
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (row["value_enc"], row["note"] or "", str(secret_id), str(project_id)),
            )
            if cur.rowcount == 0:
                flash("You don't have permission to do that", "error")
                conn.rollback()
            else:
                audit.log_secret(
                    cur,
                    project_id=project_id,
                    secret_id=secret_id,
                    secret_key=row["key"],
                    action="updated",
                )
                conn.commit()
                flash("Rolled back to selected version", "ok")
        return redirect(url_for("secret_history", project_id=project_id, secret_id=secret_id))


    @app.get("/projects/<uuid:project_id>/export")
    @authz.login_required
    def export_secrets(project_id):
        fmt = (request.args.get("format") or "env").strip().lower()
        mode = (request.args.get("mode") or "plain").strip().lower()
        if fmt not in ("env", "json", "csv"):
            fmt = "env"
        if mode not in ("plain", "enc"):
            mode = "plain"
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_read_project(%s) AS r", (str(project_id),))
            if not (cur.fetchone() or {}).get("r"):
                return "Not found", 404
            cur.execute(
                """
                SELECT key, value_enc, note FROM api.secrets
                WHERE project_id = %s AND deleted_at IS NULL
                ORDER BY key
                """,
                (str(project_id),),
            )
            rows = cur.fetchall()
            # Bulk exfil must leave an audit trail (especially plaintext)
            audit.log_secret(
                cur,
                project_id=project_id,
                action="exported",
                secret_key=f"{mode}/{fmt} n={len(rows)}",
            )
            conn.commit()
        if mode == "enc":
            payload = {
                r["key"]: {"value_enc": r["value_enc"], "note": r["note"]} for r in rows
            }
            body = json.dumps(payload, indent=2)
            return Response(
                body,
                mimetype="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="secrets-{project_id}-enc.json"'
                },
            )
        pairs = [(r["key"], crypto.decrypt(r["value_enc"])) for r in rows]
        if fmt == "json":
            body = json.dumps({k: v for k, v in pairs}, indent=2)
            mime, name = "application/json", f"secrets-{project_id}.json"
        elif fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["key", "value"])
            w.writerows(pairs)
            body = buf.getvalue()
            mime, name = "text/csv", f"secrets-{project_id}.csv"
        else:
            body = "\n".join(f"{k}={v}" for k, v in pairs) + ("\n" if pairs else "")
            mime, name = "text/plain", f"secrets-{project_id}.env"
        return Response(
            body,
            mimetype=mime,
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )


    @app.post("/projects/<uuid:project_id>/import")
    @authz.login_required
    def import_secrets(project_id):
        raw = request.form.get("payload") or ""
        f = request.files.get("file")
        if f and f.filename:
            raw = f.read().decode("utf-8", errors="replace")
        back = url_for("project_detail", project_id=project_id, tab="import")
        if not raw.strip():
            flash("Paste secrets or choose a file", "error")
            return redirect(back)
        try:
            pairs = parse_secret_pairs(raw)
        except Exception as e:
            flash(f"Parse error: {e}", "error")
            return redirect(back)
        if not pairs:
            flash("No key/value pairs found", "error")
            return redirect(back)
        n_ok = 0
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(back)
            try:
                for key, val in pairs:
                    if isinstance(val, dict) and "_enc" in val:
                        sid, was_new = _upsert_secret(
                            cur,
                            project_id,
                            key,
                            val["_enc"],
                            note=val.get("note") or "",
                            already_enc=True,
                            touch_meta=False,
                        )
                    else:
                        sid, was_new = _upsert_secret(
                            cur,
                            project_id,
                            key,
                            val,
                            touch_meta=False,
                        )
                    if sid:
                        audit.log_secret(
                            cur,
                            project_id=project_id,
                            secret_id=sid,
                            secret_key=key,
                            action="created" if was_new else "updated",
                        )
                        n_ok += 1
                conn.commit()
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
                return redirect(back)
        flash(f"Imported {n_ok} secret(s)", "ok")
        return redirect(back)


    @app.post("/projects/<uuid:project_id>/tokens")
    @authz.login_required
    def create_token(project_id):
        name = request.form.get("name", "machine").strip() or "machine"
        role = (request.form.get("role") or "read-only").strip()
        if role not in config.MACHINE_TOKEN_ROLES:
            role = "read-only"
        expires_at = None
        days_raw = (request.form.get("expires_days") or "").strip()
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            # Explicit write gate (read-only can list tokens, not create them)
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))
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
                    if days > 0:
                        expires_at = datetime.now(timezone.utc) + timedelta(days=days)
                except ValueError:
                    flash("Expires days must be a positive integer", "error")
                    return redirect(
                        url_for("project_detail", project_id=project_id, tab="tokens")
                    )
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


    @app.post("/projects/<uuid:project_id>/members")
    @authz.login_required
    def add_project_member(project_id):
        email = (request.form.get("email") or "").strip().lower()
        role = (request.form.get("role") or "read").strip()
        if role not in config.PROJECT_ROLES:
            role = "read"
        if not email:
            flash("Email required", "error")
            return redirect(url_for("project_detail", project_id=project_id, tab="settings"))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="settings"))
            cur.execute("SELECT private.lookup_user(%s) AS id", (email,))
            u = cur.fetchone()
            if not u or not u.get("id"):
                flash("User not found — they must register or sign in via LDAP first", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="settings"))
            cur.execute("SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),))
            proj = cur.fetchone()
            try:
                cur.execute(
                    """
                    SELECT role FROM api.project_members
                    WHERE project_id = %s AND user_id = %s
                    """,
                    (str(project_id), str(u["id"])),
                )
                prev = cur.fetchone()
                cur.execute(
                    """
                    INSERT INTO api.project_members (project_id, user_id, role)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role
                    """,
                    (str(project_id), str(u["id"]), role),
                )
                if cur.rowcount == 0:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    action = (
                        audit.ORG_PROJECT_MEMBER_ROLE if prev else audit.ORG_PROJECT_MEMBER_ADD
                    )
                    detail = (
                        f"{email} → {role}"
                        if not prev
                        else f"{email}: {prev['role']} → {role}"
                    )
                    audit.log_org(
                        cur,
                        team_id=proj["team_id"] if proj else None,
                        project_id=project_id,
                        action=action,
                        detail=detail,
                    )
                    conn.commit()
                    flash("Project member saved", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("project_detail", project_id=project_id, tab="settings"))


    @app.post("/projects/<uuid:project_id>/members/<uuid:user_id>/remove")
    @authz.login_required
    def remove_project_member(project_id, user_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="settings"))
            cur.execute("SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),))
            proj = cur.fetchone()
            cur.execute(
                """
                DELETE FROM api.project_members
                WHERE project_id = %s AND user_id = %s
                """,
                (str(project_id), str(user_id)),
            )
            if cur.rowcount == 0:
                flash("Member not found or not permitted", "error")
            else:
                audit.log_org(
                    cur,
                    team_id=proj["team_id"] if proj else None,
                    project_id=project_id,
                    action=audit.ORG_PROJECT_MEMBER_REMOVE,
                    detail=str(user_id),
                )
                conn.commit()
                flash("Project member removed", "ok")
        return redirect(url_for("project_detail", project_id=project_id, tab="settings"))

