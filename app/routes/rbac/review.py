"""RBAC access review: who can do a verb on a resource at a scope."""

from __future__ import annotations

from flask import render_template, request, session

from auth import authz
from core import config, db


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
        cur.execute("SELECT id, name FROM api.projects ORDER BY name LIMIT 1000")
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
