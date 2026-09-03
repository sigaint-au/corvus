"""RBAC bindings: list and manage role bindings at any scope."""

from __future__ import annotations

from flask import flash, redirect, render_template, request, session, url_for

import audit
from auth import authz
from core import config, db
from lib.users import lookup_user_id
from lib.validate import is_uuid
from auth.roles import role_allowed_at_scope, roles_for_scope


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
            cur.execute("SELECT p.id, p.name FROM api.projects p ORDER BY p.name LIMIT 500")
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

        cur.execute("SELECT id, name, built_in FROM rbac.roles ORDER BY built_in DESC, name")
        all_roles = [
            r
            for r in (cur.fetchall() or [])
            if role_allowed_at_scope(cur, r.get("name", ""), scope_kind)
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

        dropdown = roles_for_scope(cur, scope_kind)

        role_descriptions = {}
        try:
            cur.execute("SELECT name, description FROM rbac.roles")
            role_descriptions = {
                r["name"]: (r.get("description") or "") for r in (cur.fetchall() or [])
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
    """Create a validated RBAC binding at the requested scope."""
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
        flash("Select a scope.", "error")
        return redirect(url_for("rbac_bindings", scope=scope_kind))

    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute("SELECT id FROM rbac.roles WHERE name = %s", (role_name,))
            role = cur.fetchone()
            if not role:
                flash("Unknown role", "error")
                return redirect(url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id))
            if not role_allowed_at_scope(cur, role_name, scope_kind):
                flash("That role cannot be assigned at this scope", "error")
                return redirect(url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id))
            from auth.roles import OWNER_TIER, highest_team_role, team_role_at_least

            top_role = highest_team_role(cur) or OWNER_TIER
            if role_name == top_role:
                cur.execute("SELECT api.team_role(%s) AS r", (scope_id,))
                if not team_role_at_least(
                    cur, (cur.fetchone() or {}).get("r"), OWNER_TIER
                ) and not authz.is_global_admin(session["user_id"]):
                    flash("Only a team owner can grant the owner role", "error")
                    return redirect(url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id))

            subject_id = None
            if subject_kind == "User":
                subject_id = lookup_user_id(cur, subject_email)
                if not subject_id:
                    flash("No user with that email. They need to register first.", "error")
                    return redirect(url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id))
            elif subject_kind == "Group":
                if not is_uuid(subject_group):
                    flash("Select a valid group", "error")
                    return redirect(url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id))
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
                    return redirect(url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id))
                subject_id = subject_group
            elif subject_kind == "ServiceAccount":
                if not is_uuid(subject_sa):
                    flash("Enter a valid machine account ID", "error")
                    return redirect(url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id))
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
                    return redirect(url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id))
                subject_id = subject_sa
            else:
                flash("Invalid subject kind", "error")
                return redirect(url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id))

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
        except Exception:
            conn.rollback()
            flash("Could not update roles or bindings. Try again.", "error")
    return redirect(url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id or ""))


@authz.login_required
def rbac_bindings_delete(binding_id):
    """Delete an RBAC binding and return to its scope view."""
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
        except Exception:
            conn.rollback()
            flash("Could not update roles or bindings. Try again.", "error")
    return redirect(url_for("rbac_bindings", scope=scope, scope_id=scope_id))
