"""Kubernetes-style RBAC admin UI: Roles, Bindings, Access Review."""

from __future__ import annotations

import logging
import re
from uuid import UUID

from flask import flash, redirect, render_template, request, session, url_for

import audit
import authz
import config
import db

log = logging.getLogger(__name__)

_VALID_RESOURCES = set(config.RBAC_RESOURCES)
_VALID_VERBS = set(config.RBAC_VERBS)


def _role_dropdown_for_scope(scope_kind: str) -> list[tuple[str, str]]:
    if scope_kind == "cluster":
        return list(config.RBAC_CLUSTER_ROLE_DROPDOWN)
    if scope_kind == "team":
        return list(config.RBAC_TEAM_ROLE_DROPDOWN)
    if scope_kind == "project":
        return list(config.RBAC_PROJECT_ROLE_DROPDOWN)
    if scope_kind == "secret":
        return list(config.RBAC_SECRET_ROLE_DROPDOWN)
    return []


def _valid_uuid(value: str) -> bool:
    try:
        UUID(str(value))
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def _role_allowed_at_scope(role_name: str, scope_kind: str) -> bool:
    if role_name.startswith("team-"):
        return scope_kind == "team"
    if role_name.startswith("project-"):
        return scope_kind == "project"
    if role_name.startswith("secret-"):
        return scope_kind == "secret"
    if role_name.startswith("service-"):
        return scope_kind in ("project", "secret")
    if role_name in ("global-admin", "audit-viewer"):
        return scope_kind == "cluster"
    return scope_kind != "cluster"


def _split_csv(val: str) -> list[str]:
    """Split ``a, b, [c]`` style lists into tokens."""
    raw = (val or "").strip()
    if not raw:
        return []
    raw = raw.strip("[]")
    return [p.strip().strip("\"'") for p in re.split(r"[, ]+", raw) if p.strip()]


def parse_rules_yaml(text: str) -> list[tuple[list[str], list[str]]]:
    """Parse a simple multi-rule text/YAML-ish rules document.

    Format (blank line separates rules)::

        resources: secrets, projects
        verbs: get, list, reveal

        resources: *
        verbs: *

    Returns:
        List of (resources, verbs) pairs. Raises ValueError on bad input.
    """
    blocks: list[str] = []
    cur: list[str] = []
    for line in (text or "").splitlines():
        if line.strip().startswith("#"):
            continue
        if not line.strip():
            if cur:
                blocks.append("\n".join(cur))
                cur = []
            continue
        cur.append(line)
    if cur:
        blocks.append("\n".join(cur))

    rules: list[tuple[list[str], list[str]]] = []
    for block in blocks:
        resources: list[str] = []
        verbs: list[str] = []
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if key in ("resources", "resource"):
                resources = _split_csv(val)
            elif key in ("verbs", "verb"):
                verbs = _split_csv(val)
        resources = [r for r in resources if r in _VALID_RESOURCES]
        verbs = [v for v in verbs if v in _VALID_VERBS]
        if not resources or not verbs:
            raise ValueError(
                "Each rule needs valid resources: and verbs: lines "
                f"(got resources={resources!r} verbs={verbs!r})"
            )
        rules.append((resources, verbs))
    if not rules:
        raise ValueError("No rules found — add at least one resources/verbs pair")
    return rules


def register(app):
    app.get("/rbac/roles")(rbac_roles)
    app.post("/rbac/roles")(rbac_roles_create)
    app.post("/rbac/roles/<uuid:role_id>/delete")(rbac_roles_delete)
    app.get("/rbac/bindings")(rbac_bindings)
    app.post("/rbac/bindings")(rbac_bindings_create)
    app.post("/rbac/bindings/<uuid:binding_id>/delete")(rbac_bindings_delete)
    app.get("/rbac/access-review")(rbac_access_review)

def _load_roles_catalog(cur):
    """Return (roles, builtin, custom, can_edit_roles)."""
    cur.execute(
        """
        SELECT r.id, r.name, r.description, r.built_in, r.created_at,
               COALESCE(
                 (
                   SELECT json_agg(json_build_object(
                     'resources', rr.resources, 'verbs', rr.verbs
                   ) ORDER BY rr.id)
                   FROM rbac.role_rules rr WHERE rr.role_id = r.id
                 ),
                 '[]'::json
               ) AS rules
        FROM rbac.roles r
        ORDER BY r.built_in DESC, r.name
        """
    )
    roles = list(cur.fetchall() or [])
    for r in roles:
        rules = r.get("rules") or []
        if isinstance(rules, str):
            import json

            try:
                rules = json.loads(rules)
            except Exception:
                rules = []
        r["rules"] = rules or []
    cur.execute("SELECT api.can_manage_rbac('cluster', NULL) AS ok")
    can_edit_roles = bool((cur.fetchone() or {}).get("ok"))
    builtin = [r for r in roles if r.get("built_in")]
    custom = [r for r in roles if not r.get("built_in")]
    return roles, builtin, custom, can_edit_roles

@authz.login_required
def rbac_roles():
    """List built-in and custom roles with their rules."""
    tab = (request.args.get("tab") or "builtin").strip().lower()
    if tab not in ("builtin", "custom", "create"):
        tab = "builtin"
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        roles, builtin, custom, can_edit = _load_roles_catalog(cur)
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
            resources = [
                r
                for r in request.form.getlist("resources")
                if r in _VALID_RESOURCES
            ]
            verbs = [
                v for v in request.form.getlist("verbs") if v in _VALID_VERBS
            ]
            if not resources or not verbs:
                raise ValueError("Select at least one resource and one verb")
            rules = [(resources, verbs)]
    except ValueError as e:
        flash(str(e), "error")
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

    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                """
                INSERT INTO rbac.roles (name, description, built_in)
                VALUES (%s, %s, false)
                RETURNING id
                """,
                (name, description),
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
        except Exception as e:
            conn.rollback()
            flash(str(e), "error")
            return redirect(url_for("rbac_roles", tab="create"))
    return redirect(
        url_for(
            "rbac_roles",
            tab=redirect_tab if redirect_tab in ("builtin", "custom") else "custom",
        )
    )

@authz.login_required
def rbac_roles_delete(role_id):
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
        except Exception as e:
            conn.rollback()
            flash(str(e), "error")
    return redirect(
        url_for(
            "rbac_roles",
            tab=tab if tab in ("builtin", "custom") else "custom",
        )
    )

@authz.login_required
def rbac_bindings():
    """List and create bindings at a chosen scope.

    Team/project admins manage their scopes; cluster is global-admin only.
    """
    # Legacy unified-page query params
    if (request.args.get("panel") or "").strip().lower() == "roles":
        tab = (request.args.get("roles_tab") or "builtin").strip().lower()
        if tab not in ("builtin", "custom", "create"):
            tab = "builtin"
        return redirect(url_for("rbac_roles", tab=tab))

    scope_kind = (request.args.get("scope") or "team").strip().lower()
    if scope_kind not in config.RBAC_SCOPE_KINDS:
        scope_kind = "team"
    if scope_kind == "cluster" and not session.get("is_global_admin"):
        scope_kind = "team"
    scope_id = (request.args.get("scope_id") or "").strip() or None
    tid = session.get("team_id")
    # Default to active team when no scope_id selected
    if scope_kind == "team" and not scope_id and tid:
        scope_id = tid

    bindings = []
    teams = []
    projects = []
    secrets = []
    groups = []
    all_roles = []
    dropdown = []
    scope_label = None
    back_team_id = None
    back_team_name = None
    can_edit = False

    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT t.id, t.name FROM api.teams t ORDER BY t.name")
        teams = cur.fetchall() or []

        if scope_kind == "team" and not scope_id and tid:
            scope_id = tid
        if scope_kind == "cluster":
            scope_id = None

        picker_team_id = tid
        if scope_kind == "team" and scope_id:
            picker_team_id = scope_id
            back_team_id = scope_id
            for t in teams:
                if str(t["id"]) == str(scope_id):
                    scope_label = t["name"]
                    break
        elif scope_kind == "project" and scope_id:
            cur.execute(
                """
                SELECT p.name, p.team_id
                FROM api.projects p
                WHERE p.id = %s::uuid
                """,
                (scope_id,),
            )
            prow = cur.fetchone()
            if prow:
                picker_team_id = str(prow["team_id"])
                back_team_id = picker_team_id
                scope_label = prow["name"]
        elif scope_kind == "secret" and scope_id:
            cur.execute(
                """
                SELECT s.key AS name, p.team_id, p.name AS project_name
                FROM api.secrets s
                JOIN api.projects p ON p.id = s.project_id
                WHERE s.id = %s::uuid AND s.deleted_at IS NULL
                """,
                (scope_id,),
            )
            srow = cur.fetchone()
            if srow:
                picker_team_id = str(srow["team_id"])
                back_team_id = picker_team_id
                scope_label = f"{srow['project_name']} / {srow['name']}"

        if back_team_id:
            for t in teams:
                if str(t["id"]) == str(back_team_id):
                    back_team_name = t["name"]
                    break

        if picker_team_id:
            cur.execute(
                """
                SELECT p.id, p.name FROM api.projects p
                WHERE p.team_id = %s ORDER BY p.name
                """,
                (picker_team_id,),
            )
            projects = cur.fetchall() or []
        else:
            cur.execute(
                "SELECT p.id, p.name FROM api.projects p ORDER BY p.name LIMIT 500"
            )
            projects = cur.fetchall() or []

        if scope_kind == "project" and scope_id:
            cur.execute(
                """
                SELECT s.id, s.key AS name FROM api.secrets s
                WHERE s.project_id = %s AND s.deleted_at IS NULL
                ORDER BY s.key LIMIT 500
                """,
                (scope_id,),
            )
            secrets = cur.fetchall() or []
        elif scope_kind == "secret" and picker_team_id:
            cur.execute(
                """
                SELECT s.id, s.key AS name, p.name AS project_name
                FROM api.secrets s
                JOIN api.projects p ON p.id = s.project_id
                WHERE p.team_id = %s AND s.deleted_at IS NULL
                ORDER BY p.name, s.key LIMIT 500
                """,
                (picker_team_id,),
            )
            secrets = cur.fetchall() or []

        if scope_kind == "cluster":
            cur.execute(
                """
                SELECT b.id, b.subject_kind, b.subject_id, b.scope_kind, b.scope_id,
                       b.created_at, r.name AS role_name, r.built_in
                FROM rbac.bindings b
                JOIN rbac.roles r ON r.id = b.role_id
                WHERE b.scope_kind = 'cluster'
                ORDER BY b.created_at DESC
                LIMIT 200
                """
            )
        elif scope_id:
            cur.execute(
                """
                SELECT b.id, b.subject_kind, b.subject_id, b.scope_kind, b.scope_id,
                       b.created_at, r.name AS role_name, r.built_in,
                       g.name AS group_name
                FROM rbac.bindings b
                JOIN rbac.roles r ON r.id = b.role_id
                LEFT JOIN api.groups g
                  ON b.subject_kind = 'Group' AND g.id = b.subject_id
                WHERE b.scope_kind = %s AND b.scope_id = %s::uuid
                ORDER BY b.created_at DESC
                LIMIT 200
                """,
                (scope_kind, scope_id),
            )
        else:
            cur.execute("SELECT 1 WHERE false")
        bindings = list(cur.fetchall() or [])

        user_ids = [
            str(b["subject_id"])
            for b in bindings
            if b.get("subject_kind") == "User" and b.get("subject_id")
        ]
        email_map = {}
        if user_ids:
            with db.connect_admin() as aconn, aconn.cursor() as acur:
                acur.execute(
                    """
                    SELECT id, email FROM private.users
                    WHERE id = ANY(%s::uuid[])
                    """,
                    (user_ids,),
                )
                for row in acur.fetchall() or []:
                    email_map[str(row["id"])] = row["email"]
        for b in bindings:
            if b.get("subject_kind") == "User":
                b["subject_email"] = email_map.get(str(b.get("subject_id")))
            else:
                b["subject_email"] = None

        cur.execute(
            "SELECT id, name, built_in FROM rbac.roles ORDER BY built_in DESC, name"
        )
        all_roles = [
            r for r in (cur.fetchall() or [])
            if _role_allowed_at_scope(r.get("name", ""), scope_kind)
        ]

        if picker_team_id:
            cur.execute(
                "SELECT id, name FROM api.groups WHERE team_id = %s ORDER BY name",
                (picker_team_id,),
            )
            groups = cur.fetchall() or []

        if scope_kind == "cluster":
            cur.execute("SELECT api.can_manage_rbac('cluster', NULL) AS ok")
            can_edit = bool((cur.fetchone() or {}).get("ok"))
        elif scope_id:
            cur.execute(
                "SELECT api.can_manage_rbac(%s, %s::uuid) AS ok",
                (scope_kind, scope_id),
            )
            can_edit = bool((cur.fetchone() or {}).get("ok"))

        dropdown = _role_dropdown_for_scope(scope_kind)

        role_descriptions = {}
        try:
            cur.execute("SELECT name, description FROM rbac.roles")
            role_descriptions = {
                r["name"]: (r.get("description") or "")
                for r in (cur.fetchall() or [])
            }
        except Exception:
            role_descriptions = {}

    return render_template(
        "rbac_bindings.html",
        bindings=bindings,
        teams=teams,
        projects=projects,
        secrets=secrets,
        groups=groups,
        all_roles=all_roles,
        dropdown=dropdown,
        role_descriptions=role_descriptions,
        scope_kind=scope_kind,
        scope_id=scope_id,
        scope_label=scope_label,
        back_team_id=back_team_id,
        back_team_name=back_team_name,
        can_edit=can_edit,
        subject_kinds=config.RBAC_SUBJECT_KINDS,
        scope_kinds=config.RBAC_SCOPE_KINDS,
    )

@authz.login_required
def rbac_bindings_create():
    scope_kind = (request.form.get("scope_kind") or "team").strip()
    scope_id = (request.form.get("scope_id") or "").strip() or None
    role_name = (request.form.get("role_name") or "").strip()
    subject_kind = (request.form.get("subject_kind") or "User").strip()
    subject_email = (request.form.get("subject_email") or "").strip().lower()
    subject_group = (request.form.get("subject_group") or "").strip()
    subject_sa = (request.form.get("subject_sa") or "").strip()

    if scope_kind not in config.RBAC_SCOPE_KINDS:
        flash("Invalid scope", "error")
        return redirect(url_for("rbac_bindings"))
    if scope_kind == "cluster":
        if not session.get("is_global_admin"):
            flash("Only global admins can create cluster bindings", "error")
            return redirect(url_for("rbac_bindings", scope="team"))
        scope_id = None
    elif not scope_id:
        flash("Scope id required", "error")
        return redirect(url_for("rbac_bindings", scope=scope_kind))

    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                "SELECT id FROM rbac.roles WHERE name = %s", (role_name,)
            )
            role = cur.fetchone()
            if not role:
                flash("Unknown role", "error")
                return redirect(
                    url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id)
                )
            if not _role_allowed_at_scope(role_name, scope_kind):
                flash("That role cannot be assigned at this scope", "error")
                return redirect(
                    url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id)
                )

            subject_id = None
            if subject_kind == "User":
                cur.execute(
                    "SELECT private.lookup_user(%s) AS id", (subject_email,)
                )
                u = cur.fetchone()
                if not u or not u.get("id"):
                    flash("User not found — they must register first", "error")
                    return redirect(
                        url_for(
                            "rbac_bindings", scope=scope_kind, scope_id=scope_id
                        )
                    )
                subject_id = str(u["id"])
            elif subject_kind == "Group":
                if not _valid_uuid(subject_group):
                    flash("Select a valid group", "error")
                    return redirect(
                        url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id)
                    )
                cur.execute(
                    """
                    SELECT 1
                    FROM api.groups g
                    WHERE g.id = %s::uuid
                      AND (
                        %s = 'cluster'
                        OR (%s = 'team' AND g.team_id = %s::uuid)
                        OR (%s = 'project' AND EXISTS (
                          SELECT 1 FROM api.projects p
                          WHERE p.id = %s::uuid AND p.team_id = g.team_id
                        ))
                        OR (%s = 'secret' AND EXISTS (
                          SELECT 1 FROM api.secrets s
                          JOIN api.projects p ON p.id = s.project_id
                          WHERE s.id = %s::uuid AND p.team_id = g.team_id
                        ))
                      )
                    """,
                    (
                        subject_group,
                        scope_kind,
                        scope_kind,
                        scope_id or subject_group,
                        scope_kind,
                        scope_id or subject_group,
                        scope_kind,
                        scope_id or subject_group,
                    ),
                )
                if not cur.fetchone():
                    flash("Group does not belong to the selected scope", "error")
                    return redirect(
                        url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id)
                    )
                subject_id = subject_group
            elif subject_kind == "ServiceAccount":
                if not _valid_uuid(subject_sa):
                    flash("Enter a valid machine account ID", "error")
                    return redirect(
                        url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id)
                    )
                cur.execute(
                    """
                    SELECT 1
                    FROM api.machine_tokens mt
                    WHERE mt.id = %s::uuid
                      AND (
                        %s = 'cluster'
                        OR (%s = 'project' AND mt.project_id = %s::uuid)
                        OR (%s = 'secret' AND EXISTS (
                          SELECT 1 FROM api.secrets s
                          WHERE s.id = %s::uuid AND s.project_id = mt.project_id
                        ))
                        OR (%s = 'team' AND EXISTS (
                          SELECT 1 FROM api.projects p
                          WHERE p.id = mt.project_id AND p.team_id = %s::uuid
                        ))
                      )
                    """,
                    (
                        subject_sa,
                        scope_kind,
                        scope_kind,
                        scope_id or subject_sa,
                        scope_kind,
                        scope_id or subject_sa,
                        scope_kind,
                        scope_id or subject_sa,
                    ),
                )
                if not cur.fetchone():
                    flash("Machine account does not belong to the selected scope", "error")
                    return redirect(
                        url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id)
                    )
                subject_id = subject_sa
            else:
                flash("Invalid subject kind", "error")
                return redirect(
                    url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id)
                )

            # Resolve scope_id in Python — CASE %s IS NULL confuses PG type inference
            scope_uuid = None if scope_kind == "cluster" or not scope_id else str(scope_id)
            cur.execute(
                """
                INSERT INTO rbac.bindings
                  (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                VALUES (
                  %s::uuid, %s, %s::uuid, %s, %s::uuid, %s::uuid
                )
                """,
                (
                    str(role["id"]),
                    subject_kind,
                    subject_id,
                    scope_kind,
                    scope_uuid,
                    session["user_id"],
                ),
            )
            if cur.rowcount == 0:
                flash("Permission denied", "error")
                conn.rollback()
            else:
                audit.log_org(
                    cur,
                    action="rbac_binding_created",
                    detail=f"{subject_kind}:{subject_id} → {role_name} at {scope_kind}",
                    team_id=scope_id if scope_kind == "team" else None,
                    project_id=scope_id if scope_kind == "project" else None,
                )
                conn.commit()
                flash("Binding created", "ok")
        except Exception as e:
            conn.rollback()
            flash(str(e), "error")
    return redirect(
        url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id or "")
    )

@authz.login_required
def rbac_bindings_delete(binding_id):
    scope = request.form.get("scope") or "team"
    scope_id = request.form.get("scope_id") or ""
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            if scope not in config.RBAC_SCOPE_KINDS:
                scope = "team"
            if scope == "cluster":
                cur.execute(
                    "DELETE FROM rbac.bindings WHERE id = %s AND scope_kind = 'cluster'",
                    (str(binding_id),),
                )
            else:
                cur.execute(
                    """
                    DELETE FROM rbac.bindings
                    WHERE id = %s AND scope_kind = %s AND scope_id = %s::uuid
                    """,
                    (str(binding_id), scope, scope_id),
                )
            if cur.rowcount:
                audit.log_org(
                    cur,
                    action="rbac_binding_deleted",
                    detail=f"binding={binding_id} at {scope}",
                    team_id=scope_id if scope == "team" else None,
                    project_id=scope_id if scope == "project" else None,
                )
                conn.commit()
                flash("Binding removed", "ok")
            else:
                conn.rollback()
                flash("Permission denied or binding not found", "error")
        except Exception as e:
            conn.rollback()
            flash(str(e), "error")
    return redirect(url_for("rbac_bindings", scope=scope, scope_id=scope_id))

@authz.login_required
def rbac_access_review():
    """Who can do X on a resource (reverse lookup via can())."""
    verb = (request.args.get("verb") or "reveal").strip().lower()
    resource = (request.args.get("resource") or "secrets").strip().lower()
    scope_kind = (request.args.get("scope") or "project").strip().lower()
    if scope_kind not in config.RBAC_SCOPE_KINDS:
        scope_kind = "project"
    scope_id = (request.args.get("scope_id") or "").strip() or None
    results = []
    teams = []
    projects = []
    secrets = []

    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT id, name FROM api.teams ORDER BY name")
        teams = cur.fetchall() or []
        cur.execute(
            "SELECT id, name FROM api.projects ORDER BY name LIMIT 1000"
        )
        projects = cur.fetchall() or []
        if scope_kind == "secret":
            cur.execute(
                """
                SELECT s.id, s.key AS name, p.name AS project_name
                FROM api.secrets s
                JOIN api.projects p ON p.id = s.project_id
                WHERE s.deleted_at IS NULL
                ORDER BY p.name, s.key LIMIT 1000
                """
            )
            secrets = cur.fetchall() or []

    if scope_id or scope_kind == "cluster":
        # private.users is not visible under RLS JWT role — use admin DSN
        with db.connect_admin() as aconn, aconn.cursor() as acur:
            acur.execute(
                """
                SELECT DISTINCT u.id, u.email, u.name, u.is_global_admin
                FROM private.users u
                WHERE u.disabled_at IS NULL
                  AND (
                    u.is_global_admin
                    OR EXISTS (
                      SELECT 1 FROM rbac.bindings b
                      WHERE b.subject_kind = 'User' AND b.subject_id = u.id
                    )
                    OR EXISTS (
                      SELECT 1 FROM api.group_members gm
                      JOIN rbac.bindings b
                        ON b.subject_kind = 'Group' AND b.subject_id = gm.group_id
                      WHERE gm.user_id = u.id
                    )
                  )
                ORDER BY u.email
                LIMIT 300
                """
            )
            users = acur.fetchall() or []
            scope_uuid = None if scope_kind == "cluster" or not scope_id else str(scope_id)
            for u in users:
                acur.execute(
                    """
                    SELECT api.can(%s, %s, %s, %s::uuid, %s::uuid) AS ok
                    """,
                    (
                        verb,
                        resource,
                        scope_kind,
                        scope_uuid,
                        str(u["id"]),
                    ),
                )
                if (acur.fetchone() or {}).get("ok"):
                    results.append(u)

    return render_template(
        "rbac_access_review.html",
        verb=verb,
        resource=resource,
        scope_kind=scope_kind,
        scope_id=scope_id,
        results=results,
        teams=teams,
        projects=projects,
        secrets=secrets,
        verbs=config.RBAC_VERBS,
        resources=config.RBAC_RESOURCES,
        scope_kinds=config.RBAC_SCOPE_KINDS,
    )
