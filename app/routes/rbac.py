"""Kubernetes-style RBAC admin UI: Roles, Bindings, Access Review."""

from __future__ import annotations

import logging

from flask import flash, redirect, render_template, request, session, url_for

import authz
import config
import db

log = logging.getLogger(__name__)


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


def register(app):
    """Register RBAC management routes."""

    @app.get("/rbac/roles")
    @authz.login_required
    def rbac_roles():
        """List built-in and custom roles with their rules."""
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
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
            roles = cur.fetchall() or []
            cur.execute(
                "SELECT api.can_manage_rbac('cluster', NULL) AS ok"
            )
            can_edit = bool((cur.fetchone() or {}).get("ok"))
        return render_template(
            "rbac_roles.html",
            roles=roles,
            can_edit=can_edit,
            verbs=config.RBAC_VERBS,
            resources=config.RBAC_RESOURCES,
        )

    @app.post("/rbac/roles")
    @authz.login_required
    def rbac_roles_create():
        """Create a custom role with one rule (resources × verbs)."""
        name = (request.form.get("name") or "").strip().lower().replace(" ", "-")
        description = (request.form.get("description") or "").strip()
        resources = request.form.getlist("resources") or ["secrets"]
        verbs = request.form.getlist("verbs") or ["get"]
        resources = [r for r in resources if r in config.RBAC_RESOURCES]
        verbs = [v for v in verbs if v in config.RBAC_VERBS]
        if not name or not resources or not verbs:
            flash("Name, at least one resource, and one verb are required", "error")
            return redirect(url_for("rbac_roles"))
        if name in config.RBAC_BUILTIN_ROLES:
            flash("That name is reserved for a built-in role", "error")
            return redirect(url_for("rbac_roles"))
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
                    return redirect(url_for("rbac_roles"))
                cur.execute(
                    """
                    INSERT INTO rbac.role_rules (role_id, resources, verbs)
                    VALUES (%s, %s, %s)
                    """,
                    (str(row["id"]), resources, verbs),
                )
                conn.commit()
                flash(f"Role “{name}” created", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("rbac_roles"))

    @app.post("/rbac/roles/<uuid:role_id>/delete")
    @authz.login_required
    def rbac_roles_delete(role_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    "DELETE FROM rbac.roles WHERE id = %s AND built_in = false",
                    (str(role_id),),
                )
                if cur.rowcount:
                    conn.commit()
                    flash("Role deleted", "ok")
                else:
                    conn.rollback()
                    flash("Cannot delete built-in roles or permission denied", "error")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("rbac_roles"))

    @app.get("/rbac/bindings")
    @authz.login_required
    def rbac_bindings():
        """List and create bindings at a chosen scope."""
        scope_kind = (request.args.get("scope") or "team").strip().lower()
        if scope_kind not in config.RBAC_SCOPE_KINDS:
            scope_kind = "team"
        scope_id = (request.args.get("scope_id") or "").strip() or None
        tid = session.get("team_id")

        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            # Scope pickers
            cur.execute(
                """
                SELECT t.id, t.name FROM api.teams t ORDER BY t.name
                """
            )
            teams = cur.fetchall() or []
            projects = []
            secrets = []
            if tid:
                cur.execute(
                    """
                    SELECT p.id, p.name FROM api.projects p
                    WHERE p.team_id = %s ORDER BY p.name
                    """,
                    (tid,),
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
            elif scope_kind == "secret" and tid:
                cur.execute(
                    """
                    SELECT s.id, s.key AS name, p.name AS project_name
                    FROM api.secrets s
                    JOIN api.projects p ON p.id = s.project_id
                    WHERE p.team_id = %s AND s.deleted_at IS NULL
                    ORDER BY p.name, s.key LIMIT 500
                    """,
                    (tid,),
                )
                secrets = cur.fetchall() or []

            # Default scope_id
            if scope_kind == "team" and not scope_id and tid:
                scope_id = tid
            if scope_kind == "cluster":
                scope_id = None

            if scope_kind == "cluster":
                cur.execute(
                    """
                    SELECT b.id, b.subject_kind, b.subject_id, b.scope_kind, b.scope_id,
                           b.created_at, r.name AS role_name, r.built_in,
                           u.email AS subject_email
                    FROM rbac.bindings b
                    JOIN rbac.roles r ON r.id = b.role_id
                    LEFT JOIN private.users u
                      ON b.subject_kind = 'User' AND u.id = b.subject_id
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
                           u.email AS subject_email,
                           g.name AS group_name
                    FROM rbac.bindings b
                    JOIN rbac.roles r ON r.id = b.role_id
                    LEFT JOIN private.users u
                      ON b.subject_kind = 'User' AND u.id = b.subject_id
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
            bindings = cur.fetchall() or []

            cur.execute(
                "SELECT id, name, built_in FROM rbac.roles ORDER BY built_in DESC, name"
            )
            all_roles = cur.fetchall() or []

            groups = []
            if tid:
                cur.execute(
                    "SELECT id, name FROM api.groups WHERE team_id = %s ORDER BY name",
                    (tid,),
                )
                groups = cur.fetchall() or []

            can_edit = False
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
        return render_template(
            "rbac_bindings.html",
            bindings=bindings,
            teams=teams,
            projects=projects,
            secrets=secrets,
            groups=groups,
            all_roles=all_roles,
            dropdown=dropdown,
            scope_kind=scope_kind,
            scope_id=scope_id,
            can_edit=can_edit,
            subject_kinds=config.RBAC_SUBJECT_KINDS,
            scope_kinds=config.RBAC_SCOPE_KINDS,
        )

    @app.post("/rbac/bindings")
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
                    subject_id = subject_group
                elif subject_kind == "ServiceAccount":
                    subject_id = subject_sa
                else:
                    flash("Invalid subject kind", "error")
                    return redirect(
                        url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id)
                    )

                cur.execute(
                    """
                    INSERT INTO rbac.bindings
                      (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                    VALUES (
                      %s, %s, %s::uuid, %s,
                      CASE WHEN %s IS NULL OR %s = '' THEN NULL ELSE %s::uuid END,
                      %s::uuid
                    )
                    """,
                    (
                        str(role["id"]),
                        subject_kind,
                        subject_id,
                        scope_kind,
                        scope_id,
                        scope_id,
                        scope_id,
                        session["user_id"],
                    ),
                )
                if cur.rowcount == 0:
                    flash("Permission denied", "error")
                    conn.rollback()
                else:
                    conn.commit()
                    flash("Binding created", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(
            url_for("rbac_bindings", scope=scope_kind, scope_id=scope_id or "")
        )

    @app.post("/rbac/bindings/<uuid:binding_id>/delete")
    @authz.login_required
    def rbac_bindings_delete(binding_id):
        scope = request.form.get("scope") or "team"
        scope_id = request.form.get("scope_id") or ""
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    "DELETE FROM rbac.bindings WHERE id = %s", (str(binding_id),)
                )
                if cur.rowcount:
                    conn.commit()
                    flash("Binding removed", "ok")
                else:
                    conn.rollback()
                    flash("Permission denied or binding not found", "error")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("rbac_bindings", scope=scope, scope_id=scope_id))

    @app.get("/rbac/access-review")
    @authz.login_required
    def rbac_access_review():
        """Who can do X on a resource (reverse lookup via can())."""
        verb = (request.args.get("verb") or "reveal").strip().lower()
        resource = (request.args.get("resource") or "secrets").strip().lower()
        scope_kind = (request.args.get("scope") or "project").strip().lower()
        scope_id = (request.args.get("scope_id") or "").strip() or None
        results = []
        teams = []
        projects = []

        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT id, name FROM api.teams ORDER BY name")
            teams = cur.fetchall() or []
            tid = session.get("team_id")
            if tid:
                cur.execute(
                    """
                    SELECT id, name FROM api.projects
                    WHERE team_id = %s ORDER BY name
                    """,
                    (tid,),
                )
                projects = cur.fetchall() or []

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
                for u in users:
                    acur.execute(
                        """
                        SELECT api.can(
                          %s, %s, %s,
                          CASE WHEN %s IS NULL OR %s = '' THEN NULL ELSE %s::uuid END,
                          %s::uuid
                        ) AS ok
                        """,
                        (
                            verb,
                            resource,
                            scope_kind,
                            scope_id,
                            scope_id,
                            scope_id,
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
            verbs=config.RBAC_VERBS,
            resources=config.RBAC_RESOURCES,
            scope_kinds=config.RBAC_SCOPE_KINDS,
        )
