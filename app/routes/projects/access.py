"""Project member, group-role, and access-binding routes."""

from __future__ import annotations

from flask import (
    flash,
    redirect,
    request,
    session,
    url_for,
)

import audit
from auth import authz
from core import config, db
from lib.users import lookup_user_id


def _project_access_url(project_id):
    return url_for("project_detail", project_id=project_id, tab="access")


@authz.login_required
def add_project_binding(project_id):
    """Add or update a project member via RBAC binding (User + project-* role).

    Body: email + role (admin|write|read). Writes ``rbac.bindings`` only.
    """
    email = (request.form.get("email") or "").strip().lower()
    role = (request.form.get("role") or "project-read").strip()
    project_role_names = config.RBAC_PROJECT_ROLE_NAMES
    if role not in project_role_names:
        role = "project-read"
    dest = _project_access_url(project_id)
    if not email:
        flash("Enter an email address.", "error")
        return redirect(dest)
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
            (str(project_id),),
        )
        if not (cur.fetchone() or {}).get("ok"):
            flash("You don't have permission to do that", "error")
            return redirect(dest)
        uid = lookup_user_id(cur, email)
        if not uid:
            flash(
                "User not found — they must register or sign in via LDAP first",
                "error",
            )
            return redirect(dest)
        cur.execute(
            "SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),)
        )
        proj = cur.fetchone()
        try:
            from auth import rbac_sync

            rbac_sync.sync_user_project_binding(
                cur,
                user_id=uid,
                project_id=project_id,
                role=role,
                created_by=session["user_id"],
            )
            audit.log_org(
                cur,
                team_id=proj["team_id"] if proj else None,
                project_id=project_id,
                action=audit.ORG_PROJECT_MEMBER_ADD,
                detail=f"{email} → {role} (rbac)",
            )
            conn.commit()
            flash(f"Bound {email} as project-{role}", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update project access. Try again.", "error")
    return redirect(dest)


@authz.login_required
def remove_project_binding(project_id, user_id):
    """Remove a user project-scope RBAC binding."""
    dest = _project_access_url(project_id)
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
            (str(project_id),),
        )
        if not (cur.fetchone() or {}).get("ok"):
            flash("You don't have permission to do that", "error")
            return redirect(dest)
        cur.execute(
            "SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),)
        )
        proj = cur.fetchone()
        try:
            from auth import rbac_sync

            rbac_sync.sync_user_project_binding(
                cur, user_id=user_id, project_id=project_id, role=None
            )
            audit.log_org(
                cur,
                team_id=proj["team_id"] if proj else None,
                project_id=project_id,
                action=audit.ORG_PROJECT_MEMBER_REMOVE,
                detail=str(user_id),
            )
            conn.commit()
            flash("Project binding removed", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update project access. Try again.", "error")
    return redirect(dest)


@authz.login_required
def add_project_group_role(project_id):
    """Grant a team group a project role via RBAC binding only."""
    group_id = (request.form.get("group_id") or "").strip()
    role = (request.form.get("role") or "project-read").strip()
    project_role_names = config.RBAC_PROJECT_ROLE_NAMES
    if role not in project_role_names:
        role = "project-read"
    dest = _project_access_url(project_id)
    if not group_id:
        flash("Select a group.", "error")
        return redirect(dest)
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
            (str(project_id),),
        )
        if not (cur.fetchone() or {}).get("ok"):
            flash("You don't have permission to do that", "error")
            return redirect(dest)
        cur.execute(
            """
            SELECT p.team_id, g.name
            FROM api.projects p
            JOIN api.groups g ON g.team_id = p.team_id AND g.id = %s
            WHERE p.id = %s
            """,
            (group_id, str(project_id)),
        )
        row = cur.fetchone()
        if not row:
            flash("Group not found on this team", "error")
            return redirect(dest)
        try:
            from auth import rbac_sync

            rbac_sync.sync_group_project_binding(
                cur,
                group_id=group_id,
                project_id=project_id,
                role=role,
                created_by=session["user_id"],
            )
            audit.log_org(
                cur,
                team_id=row["team_id"],
                project_id=project_id,
                action="project_group_role",
                detail=f"{row['name']} → {role} (rbac)",
            )
            conn.commit()
            flash(f"Bound group “{row['name']}” as project-{role}", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update project access. Try again.", "error")
    return redirect(dest)


@authz.login_required
def remove_project_group_role(project_id, group_id):
    """Remove a group project-scope RBAC binding."""
    dest = _project_access_url(project_id)
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
            (str(project_id),),
        )
        if not (cur.fetchone() or {}).get("ok"):
            flash("You don't have permission to do that", "error")
            return redirect(dest)
        cur.execute(
            "SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),)
        )
        proj = cur.fetchone()
        try:
            from auth import rbac_sync

            rbac_sync.sync_group_project_binding(
                cur,
                group_id=group_id,
                project_id=project_id,
                role=None,
                created_by=session.get("user_id"),
            )
            audit.log_org(
                cur,
                team_id=proj["team_id"] if proj else None,
                project_id=project_id,
                action="project_group_role_remove",
                detail=str(group_id),
            )
            conn.commit()
            flash("Group project binding removed", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update project access. Try again.", "error")
    return redirect(dest)


@authz.login_required
def project_access_binding_create(project_id):
    """Create a project-scope role binding (User / Group / ServiceAccount)."""
    dest = _project_access_url(project_id)
    role_name = (request.form.get("role_name") or "").strip()
    subject_kind = (request.form.get("subject_kind") or "User").strip()
    subject_email = (request.form.get("subject_email") or "").strip().lower()
    subject_group = (request.form.get("subject_group") or "").strip()
    subject_sa = (request.form.get("subject_sa") or "").strip()
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
            (str(project_id),),
        )
        if not (cur.fetchone() or {}).get("ok"):
            flash("Only project admins can manage role bindings", "error")
            return redirect(dest)
        cur.execute(
            "SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),)
        )
        proj = cur.fetchone()
        if not proj:
            flash("Project not found", "error")
            return redirect(url_for("projects"))
        try:
            from auth import rbac_sync

            if role_name not in rbac_sync.PROJECT_ROLE_NAMES:
                flash("Unknown role", "error")
                return redirect(dest)

            subject_id = None
            detail_who = None
            if subject_kind == "User":
                subject_id = lookup_user_id(cur, subject_email)
                if not subject_id:
                    flash("User not found — they must register first", "error")
                    return redirect(dest)
                detail_who = subject_email
                rbac_sync.sync_user_project_binding(
                    cur,
                    user_id=subject_id,
                    project_id=project_id,
                    role=role_name,
                    created_by=session["user_id"],
                )
            elif subject_kind == "Group":
                if not subject_group:
                    flash("Select a group", "error")
                    return redirect(dest)
                cur.execute(
                    """
                    SELECT id, name FROM api.groups
                    WHERE id = %s AND team_id = %s
                    """,
                    (subject_group, str(proj["team_id"])),
                )
                g = cur.fetchone()
                if not g:
                    flash("Group not found on this team", "error")
                    return redirect(dest)
                subject_id = str(g["id"])
                detail_who = f"group {g['name']}"
                rbac_sync.sync_group_project_binding(
                    cur,
                    group_id=subject_group,
                    project_id=project_id,
                    role=role_name,
                    created_by=session["user_id"],
                )
            elif subject_kind == "ServiceAccount":
                subject_id = subject_sa
                detail_who = f"sa {subject_sa}"
                if not subject_id:
                    flash("Enter a machine account ID.", "error")
                    return redirect(dest)
                rid = rbac_sync.role_id(cur, role_name)
                if not rid:
                    flash("Unknown role", "error")
                    return redirect(dest)
                cur.execute(
                    """
                    INSERT INTO rbac.bindings
                      (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                    VALUES (%s::uuid, 'ServiceAccount', %s::uuid, 'project', %s::uuid, %s::uuid)
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        rid,
                        subject_id,
                        str(project_id),
                        session["user_id"],
                    ),
                )
            else:
                flash("Invalid subject kind", "error")
                return redirect(dest)

            audit.log_org(
                cur,
                team_id=proj["team_id"],
                project_id=project_id,
                action=audit.ORG_PROJECT_MEMBER_ADD,
                detail=f"{detail_who} → {role_name}",
            )
            conn.commit()
            flash("Binding created", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update project access. Try again.", "error")
    return redirect(dest)


@authz.login_required
def project_access_binding_delete(project_id, binding_id):
    """Remove a project-scope role binding."""
    dest = _project_access_url(project_id)
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
            (str(project_id),),
        )
        if not (cur.fetchone() or {}).get("ok"):
            flash("Only project admins can manage role bindings", "error")
            return redirect(dest)
        cur.execute(
            "SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),)
        )
        proj = cur.fetchone()
        try:
            cur.execute(
                """
                DELETE FROM rbac.bindings
                WHERE id = %s::uuid
                  AND scope_kind = 'project'
                  AND scope_id = %s::uuid
                RETURNING subject_kind, subject_id
                """,
                (str(binding_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                flash("Binding not found or not permitted", "error")
                conn.rollback()
            else:
                audit.log_org(
                    cur,
                    team_id=proj["team_id"] if proj else None,
                    project_id=project_id,
                    action=audit.ORG_PROJECT_MEMBER_REMOVE,
                    detail=f"{row['subject_kind']}:{row['subject_id']}",
                )
                conn.commit()
                flash("Binding removed", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update project access. Try again.", "error")
    return redirect(dest)
