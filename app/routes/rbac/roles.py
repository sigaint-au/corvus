"""RBAC role catalogue: list, create, delete custom roles."""

from __future__ import annotations

import re

from flask import flash, redirect, render_template, request, session, url_for

import audit
from auth import authz
from core import config, db
from routes.rbac.helpers import _VALID_RESOURCES, _VALID_VERBS, load_roles_catalog, parse_rules_yaml


@authz.login_required
def rbac_roles():
    """List built-in and custom roles with their rules."""
    tab = (request.args.get("tab") or "builtin").strip().lower()
    if tab not in ("builtin", "custom", "create"):
        tab = "builtin"
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        roles, builtin, custom, can_edit = load_roles_catalog(cur)
    if tab == "create" and not can_edit:
        tab = "builtin"
    return render_template(
        "rbac_roles.html",
        roles=roles,
        builtin_roles=builtin,
        custom_roles=custom,
        can_edit=can_edit,
        active_tab=tab,
        verbs=config.RBAC_VERBS,
        resources=config.RBAC_RESOURCES,
        scope_kinds=config.RBAC_SCOPE_KINDS,
    )


@authz.login_required
def rbac_roles_create():
    """Create a custom role from form checkboxes or YAML rules text."""
    name = (request.form.get("name") or "").strip().lower().replace(" ", "-")
    description = (request.form.get("description") or "").strip()
    mode = (request.form.get("mode") or "form").strip().lower()
    redirect_tab = (request.form.get("tab") or "custom").strip() or "custom"

    rules: list[tuple[list[str], list[str]]] = []
    try:
        if mode == "yaml":
            rules = parse_rules_yaml(request.form.get("rules_yaml") or "")
        else:
            resources = [r for r in request.form.getlist("resources") if r in _VALID_RESOURCES]
            verbs = [v for v in request.form.getlist("verbs") if v in _VALID_VERBS]
            if not resources or not verbs:
                raise ValueError("Select at least one resource and one verb")
            rules = [(resources, verbs)]
    except ValueError:
        flash("Could not update roles or bindings. Try again.", "error")
        return redirect(url_for("rbac_roles", tab="create"))

    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
        flash("Name must use lowercase letters, numbers, and hyphens", "error")
        return redirect(url_for("rbac_roles", tab="create"))
    if not name:
        flash("Name is required", "error")
        return redirect(url_for("rbac_roles", tab="create"))
    if name in config.RBAC_BUILTIN_ROLES:
        flash("That name is reserved for a built-in role", "error")
        return redirect(url_for("rbac_roles", tab="create"))
    scopes = [s for s in request.form.getlist("scopes") if s in config.RBAC_SCOPE_KINDS]
    if not scopes:
        flash("Select at least one scope this role can be assigned at", "error")
        return redirect(url_for("rbac_roles", tab="create"))

    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                """
                INSERT INTO rbac.roles (name, description, built_in, scopes)
                VALUES (%s, %s, false, %s)
                RETURNING id
                """,
                (name, description, scopes),
            )
            row = cur.fetchone()
            if not row:
                flash("Permission denied creating role", "error")
                conn.rollback()
                return redirect(url_for("rbac_roles", tab="create"))
            for resources, verbs in rules:
                cur.execute(
                    """
                    INSERT INTO rbac.role_rules (role_id, resources, verbs)
                    VALUES (%s, %s, %s)
                    """,
                    (str(row["id"]), resources, verbs),
                )
            audit.log_org(
                cur,
                action="rbac_role_created",
                detail=name,
            )
            conn.commit()
            flash(f"Role “{name}” created", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update roles or bindings. Try again.", "error")
            return redirect(url_for("rbac_roles", tab="create"))
    return redirect(
        url_for(
            "rbac_roles",
            tab=redirect_tab if redirect_tab in ("builtin", "custom") else "custom",
        )
    )


@authz.login_required
def rbac_roles_delete(role_id):
    """Delete a non-built-in RBAC role and return to the role catalogue."""
    tab = (request.form.get("tab") or "custom").strip() or "custom"
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                "DELETE FROM rbac.roles WHERE id = %s AND built_in = false",
                (str(role_id),),
            )
            if cur.rowcount:
                audit.log_org(
                    cur,
                    action="rbac_role_deleted",
                    detail=str(role_id),
                )
                conn.commit()
                flash("Role deleted", "ok")
            else:
                conn.rollback()
                flash("Cannot delete built-in roles or permission denied", "error")
        except Exception:
            conn.rollback()
            flash("Could not update roles or bindings. Try again.", "error")
    return redirect(
        url_for(
            "rbac_roles",
            tab=tab if tab in ("builtin", "custom") else "custom",
        )
    )
