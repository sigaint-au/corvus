"""Webhook management: scoped listing, shared CRUD routes, and detail pages.

Listing runs as the user so RLS scopes rows; write paths additionally check
``api.can_manage_rbac`` for a clean flash instead of a naked 403.
"""

import logging
import secrets

from flask import flash, redirect, render_template, request, session, url_for

from auth import authz
from core import db
from integrations import webhooks as wh

log = logging.getLogger(__name__)


def _can_manage(cur, scope_kind: str, scope_id) -> bool:
    cur.execute(
        "SELECT api.can_manage_rbac(%s, %s::uuid) AS ok",
        (scope_kind, str(scope_id)),
    )
    return bool((cur.fetchone() or {}).get("ok"))


def _safe_back(default: str) -> str:
    raw = (request.values.get("back") or "").strip()
    if raw.startswith("/") and not raw.startswith("//"):
        return raw
    return default


def load_scope_webhooks(cur, scope_kind: str, scope_id) -> list[dict]:
    """Webhooks for one scope (+ last delivery each), filtered by ?q=."""
    q = (request.args.get("q") or "").strip()
    sql = """
        SELECT id, name, url, events, active, ssl_verify, created_at
        FROM api.webhooks
        WHERE scope_kind = %s AND scope_id = %s::uuid
    """
    args: list = [scope_kind]
    if scope_id is None:
        sql = sql.replace("AND scope_id %s::uuid", "IS NULL")
    else:
        args.append(str(scope_id))
    if q:
        needle = f"%{q}%"
        sql += " AND (name ILIKE %s OR url ILIKE %s)"
        args += [needle, needle]
    sql += " ORDER BY created_at DESC"
    try:
        cur.execute(sql, args)
        rows = list(cur.fetchall() or [])
    except Exception:
        log.exception("webhook listing failed")
        return []
    for r in rows:
        r["deliveries"] = wh.recent_deliveries(cur, str(r["id"]), limit=1)
    return rows


def _resolve_create_scope(cur) -> tuple[str, object] | None:
    """Validate ?scope=/?scope_id= for the create page; flashes on failure."""
    scope = (request.values.get("scope") or "").strip()
    if scope == "cluster":
        cur.execute("SELECT api.is_global_admin() AS ok")
        if not (cur.fetchone() or {}).get("ok"):
            flash("Global admins manage cluster webhooks", "error")
            return None
        return "cluster", None
    ref = (request.values.get("scope_id") or "").strip()
    if scope not in ("project", "team") or not ref:
        flash("Unknown webhook scope", "error")
        return None
    if not _can_manage(cur, scope, ref):
        flash("You cannot manage webhooks here", "error")
        return None
    return scope, ref


@authz.login_required
def webhook_new():
    """Create form for project/team/cluster webhooks."""
    session.setdefault("team_id", None)
    scope = ref = None
    scope_name = ""
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        got = _resolve_create_scope(cur)
        if not got:
            return redirect(_safe_back(url_for("projects_list")))
        scope, ref = got
        if scope == "project":
            cur.execute("SELECT name FROM api.projects WHERE id = %s::uuid", (str(ref),))
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            scope_name = row["name"]
        elif scope == "team":
            cur.execute("SELECT name FROM api.teams WHERE id = %s::uuid", (str(ref),))
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            scope_name = row["name"]
        else:
            scope_name = "Corvus (system-wide)"
    return render_template(
        "webhook_form.html",
        heading="Add webhook",
        mode="create",
        webhook=None,
        scope=scope,
        scope_id=ref,
        scope_name=scope_name,
        back=_safe_back(url_for("projects_list")),
    )


@authz.login_required
def webhook_create():
    """Handle the create form POST."""
    scope = (request.form.get("scope") or "").strip()
    ref_raw = (request.form.get("scope_id") or "").strip() or None
    back = _safe_back(url_for("projects_list"))
    url, events, ssl_verify, err = wh.validate_webhook_input(request.form)
    if err:
        flash(err, "error")
        return redirect(back)
    token = (request.form.get("secret_token") or "").strip()
    generated = False
    if not token:
        # ponytail: shown-once flash; rotate by editing the webhook later
        token = secrets.token_hex(32)
        generated = True
    name = (request.form.get("name") or "").strip()[:80] or "webhook"
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        got = _resolve_create_scope(cur)
        if not got:
            return redirect(back)
        cscope, cref = got
        if (cscope, cref) != (scope, ref_raw):
            flash("Scope mismatch; start again", "error")
            return redirect(back)
        cur.execute(
            """
            INSERT INTO api.webhooks (name, url, secret_token, events, scope_kind, scope_id, ssl_verify)
            VALUES (%s, %s, %s, %s, %s, %s::uuid, %s)
            """,
            (name, url, token, events, cscope, str(cref) if cref else None, ssl_verify),
        )
    flash(
        ("Signing secret (copy now, shown once): " + token) if generated
        else "Webhook created",
        "ok",
    )
    return redirect(back)


@authz.login_required
def webhook_view(webhook_id):
    """Edit page: settings form, danger zone, recent deliveries."""
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, name, url, secret_token, events, active, ssl_verify,
                   scope_kind, scope_id
            FROM api.webhooks WHERE id = %s::uuid
            """,
            (str(webhook_id),),
        )
        row = cur.fetchone()
        if not row:
            return "Not found", 404
        deliveries = wh.recent_deliveries(cur, str(webhook_id))
        scope_name = ""
        if row["scope_kind"] == "project":
            cur.execute(
                "SELECT name FROM api.projects WHERE id = %s::uuid",
                (str(row["scope_id"]),),
            )
            scope_name = (cur.fetchone() or {}).get("name") or ""
        elif row["scope_kind"] == "team":
            cur.execute(
                "SELECT name FROM api.teams WHERE id = %s::uuid",
                (str(row["scope_id"]),),
            )
            scope_name = (cur.fetchone() or {}).get("name") or ""
        else:
            scope_name = "Corvus (system-wide)"
    if row["scope_kind"] == "cluster":
        back_default = url_for("server_settings", tab="webhooks")
    else:
        back_default = url_for("projects_list")
    return render_template(
        "webhook_form.html",
        heading=row["name"],
        mode="edit",
        webhook=row,
        scope=row["scope_kind"],
        scope_id=str(row["scope_id"]) if row["scope_id"] else None,
        scope_name=scope_name,
        deliveries=deliveries,
        back=_safe_back(back_default),
    )


@authz.login_required
def webhook_update(webhook_id):
    """Save edits from the detail page."""
    back = _safe_back(url_for("projects_list"))
    url, events, ssl_verify, err = wh.validate_webhook_input(request.form)
    if err:
        flash(err, "error")
        return redirect(back)
    name = (request.form.get("name") or "").strip()[:80] or "webhook"
    active = bool(request.form.get("active"))
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE api.webhooks
            SET name = %s, url = %s, events = %s, ssl_verify = %s, active = %s
            WHERE id = %s::uuid
            """,
            (name, url, events, ssl_verify, active, str(webhook_id)),
        )
        changed = cur.rowcount
    flash("Webhook saved" if changed else "Webhook not found", "ok" if changed else "error")
    return redirect(back)


@authz.login_required
def webhook_delete(webhook_id):
    back = _safe_back(url_for("projects_list"))
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM api.webhooks WHERE id = %s::uuid", (str(webhook_id),))
        deleted = cur.rowcount
    flash("Webhook deleted" if deleted else "Webhook not found", "ok" if deleted else "error")
    return redirect(back)


def register(app):
    app.get("/webhooks/new")(webhook_new)
    app.post("/webhooks/create")(webhook_create)
    app.get("/webhooks/<uuid:webhook_id>")(webhook_view)
    app.post("/webhooks/<uuid:webhook_id>/update")(webhook_update)
    app.post("/webhooks/<uuid:webhook_id>/delete")(webhook_delete)
