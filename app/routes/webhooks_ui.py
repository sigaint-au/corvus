"""Webhook management UI routes (project and team scope)."""

import logging
import secrets

from flask import flash, redirect, request, session, url_for

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


def _create(scope_kind: str, scope_id, back_endpoint: str):
    """Shared create handler; runs as the user so RLS double-checks."""
    url, events, ssl_verify, err = wh.validate_webhook_input(request.form)
    if err:
        flash(err, "error")
        return redirect(url_for(back_endpoint, tab="webhooks", **{f"{scope_kind}_id": scope_id}))
    token = (request.form.get("secret_token") or "").strip()
    generated = False
    if not token:
        # ponytail: shown-once flash instead of a reveal-later flow; rotate by re-creating
        token = secrets.token_hex(32)
        generated = True
    name = (request.form.get("name") or "").strip()[:80] or "webhook"
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        if not _can_manage(cur, scope_kind, scope_id):
            flash("You cannot manage webhooks here", "error")
            return redirect(url_for(back_endpoint, tab="webhooks", **{f"{scope_kind}_id": scope_id}))
        cur.execute(
            """
            INSERT INTO api.webhooks (name, url, secret_token, events, scope_kind, scope_id, ssl_verify)
            VALUES (%s, %s, %s, %s, %s, %s::uuid, %s)
            """,
            (name, url, token, events, scope_kind, str(scope_id), ssl_verify),
        )
    flash(
        ("Signing secret (copy now, shown once): " + token) if generated
        else "Webhook created",
        "ok",
    )
    return redirect(url_for(back_endpoint, tab="webhooks", **{f"{scope_kind}_id": scope_id}))


def _delete_or_toggle(scope_kind: str, scope_id, webhook_id, back_endpoint: str, toggle: bool):
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        if not _can_manage(cur, scope_kind, scope_id):
            flash("You cannot manage webhooks here", "error")
        elif toggle:
            cur.execute(
                "UPDATE api.webhooks SET active = NOT active WHERE id = %s::uuid AND scope_id = %s::uuid",
                (str(webhook_id), str(scope_id)),
            )
            flash("Webhook updated", "ok")
        else:
            cur.execute(
                "DELETE FROM api.webhooks WHERE id = %s::uuid AND scope_id = %s::uuid",
                (str(webhook_id), str(scope_id)),
            )
            flash("Webhook deleted", "ok")
    return redirect(url_for(back_endpoint, tab="webhooks", **{f"{scope_kind}_id": scope_id}))


def load_scope_webhooks(cur, scope_kind: str, scope_id) -> list[dict]:
    rows: list[dict] = []
    try:
        cur.execute(
            """
            SELECT id, name, url, events, active, ssl_verify, created_at
            FROM api.webhooks
            WHERE scope_kind = %s AND scope_id = %s::uuid
            ORDER BY created_at DESC
            """,
            (scope_kind, str(scope_id)),
        )
        rows = list(cur.fetchall() or [])
    except Exception:
        log.exception("webhook listing failed")
        return []
    for r in rows:
        r["deliveries"] = wh.recent_deliveries(cur, str(r["id"]))
    return rows


@authz.login_required
def create_project_webhook(project_id):
    return _create("project", project_id, "project_detail")


@authz.login_required
def delete_project_webhook(project_id, webhook_id):
    return _delete_or_toggle("project", project_id, webhook_id, "project_detail", False)


@authz.login_required
def toggle_project_webhook(project_id, webhook_id):
    return _delete_or_toggle("project", project_id, webhook_id, "project_detail", True)


@authz.login_required
def create_team_webhook(team_id):
    return _create("team", team_id, "team_detail")


@authz.login_required
def delete_team_webhook(team_id, webhook_id):
    return _delete_or_toggle("team", team_id, webhook_id, "team_detail", False)


@authz.login_required
def toggle_team_webhook(team_id, webhook_id):
    return _delete_or_toggle("team", team_id, webhook_id, "team_detail", True)


def register(app):
    app.post("/projects/<uuid:project_id>/webhooks")(create_project_webhook)
    app.post("/projects/<uuid:project_id>/webhooks/<uuid:webhook_id>/delete")(delete_project_webhook)
    app.post("/projects/<uuid:project_id>/webhooks/<uuid:webhook_id>/toggle")(toggle_project_webhook)
    app.post("/teams/<uuid:team_id>/webhooks")(create_team_webhook)
    app.post("/teams/<uuid:team_id>/webhooks/<uuid:webhook_id>/delete")(delete_team_webhook)
    app.post("/teams/<uuid:team_id>/webhooks/<uuid:webhook_id>/toggle")(toggle_team_webhook)
