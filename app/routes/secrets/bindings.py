"""Secret access-binding routes."""

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
from core import config
from core import db
from lib.users import lookup_user_id
from secret_svc.secret_ops import (
    _parse_access_mode,
    _parse_requires_approval,
)


@authz.login_required
def update_secret_access(project_id, secret_id):
    """Set per-secret access mode and reveal-approval override (project admin only)."""
    mode = _parse_access_mode(request.form)
    req_appr = _parse_requires_approval(request.form)
    access_url = url_for(
        "secret_view",
        project_id=project_id,
        secret_id=secret_id,
        tab="access",
    )
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
        if not (cur.fetchone() or {}).get("a"):
            flash("Only project admins can change secret access", "error")
            return redirect(access_url)
        cur.execute(
            """
            UPDATE api.secrets
            SET access_mode = %s, requires_approval = %s
            WHERE id = %s AND project_id = %s AND deleted_at IS NULL
            RETURNING key
            """,
            (mode, req_appr, str(secret_id), str(project_id)),
        )
        row = cur.fetchone()
        if not row:
            flash("Secret not found or not permitted", "error")
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
            label = config.ACCESS_MODE_LABELS.get(mode, mode)
            flash(f"Access settings saved ({label})", "ok")
    return redirect(access_url)


@authz.login_required
def add_secret_access_binding(project_id, secret_id):
    """Bind a user, group, or service account to a secret role (project admin).

    Uses the same subject/role vocabulary as every other binding form:
    ``subject_kind`` + ``subject_email`` / ``subject_group`` / ``subject_sa``
    and a ``role_name`` (``secret-*`` or a custom role).
    """
    subject_kind = (request.form.get("subject_kind") or "User").strip()
    if subject_kind not in ("User", "Group", "ServiceAccount"):
        subject_kind = "User"
    email = (request.form.get("subject_email") or "").strip().lower()
    group_id = (request.form.get("subject_group") or "").strip()
    sa_id = (request.form.get("subject_sa") or "").strip()
    role_name = (request.form.get("role_name") or "").strip()
    if not role_name:
        role_name = "secret-reveal"
    access_url = url_for(
        "secret_view",
        project_id=project_id,
        secret_id=secret_id,
        tab="access",
    )
    if subject_kind == "User" and not email:
        flash("User email required", "error")
        return redirect(access_url)
    if subject_kind == "Group" and not group_id:
        flash("Select a group", "error")
        return redirect(access_url)
    if subject_kind == "ServiceAccount" and not sa_id:
        flash("Enter a machine account ID", "error")
        return redirect(access_url)
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
        if not (cur.fetchone() or {}).get("a"):
            flash("Only project admins can manage secret bindings", "error")
            return redirect(access_url)
        cur.execute(
            """
            SELECT s.id, s.key, s.access_mode, p.team_id
            FROM api.secrets s
            JOIN api.projects p ON p.id = s.project_id
            WHERE s.id = %s AND s.project_id = %s AND s.deleted_at IS NULL
            """,
            (str(secret_id), str(project_id)),
        )
        sec = cur.fetchone()
        if not sec:
            flash("Secret not found", "error")
            return redirect(
                url_for("project_detail", project_id=project_id, tab="secrets")
            )
        cur.execute(
            "SELECT id FROM rbac.roles WHERE name = %s", (role_name,)
        )
        role = cur.fetchone()
        if not role:
            flash(f"Built-in role {role_name} missing — run schema ensure", "error")
            return redirect(access_url)
        try:
            if subject_kind == "User":
                subject_id = lookup_user_id(cur, email)
                if not subject_id:
                    flash(
                        "User not found — they must register or sign in first",
                        "error",
                    )
                    return redirect(access_url)
                who = email
            elif subject_kind == "Group":
                cur.execute(
                    """
                    SELECT id, name FROM api.groups
                    WHERE id = %s AND team_id = %s
                    """,
                    (group_id, str(sec["team_id"])),
                )
                g = cur.fetchone()
                if not g:
                    flash("Group not found on this team", "error")
                    return redirect(access_url)
                subject_id, who = str(g["id"]), f"group {g['name']}"
            else:
                cur.execute(
                    """
                    SELECT mt.id
                    FROM api.machine_tokens mt
                    WHERE mt.id = %s::uuid
                      AND mt.project_id = %s
                    """,
                    (sa_id, str(project_id)),
                )
                sa = cur.fetchone()
                if not sa:
                    flash("Machine account not found in this project", "error")
                    return redirect(access_url)
                subject_id, who = str(sa["id"]), f"machine account {sa_id[:8]}"
            external_user = False
            if subject_kind == "User":
                cur.execute(
                    """
                    SELECT api.can('list', 'secrets', 'team', %s::uuid, %s::uuid)
                      AS member
                    """,
                    (str(sec["team_id"]), subject_id),
                )
                external_user = not bool((cur.fetchone() or {}).get("member"))
                if external_user:
                    cur.execute(
                        "SELECT api.secret_requires_approval(%s::uuid) AS a",
                        (str(secret_id),),
                    )
                    if bool((cur.fetchone() or {}).get("a")):
                        flash(
                            "Cannot share secrets that require reveal approval "
                            "with users outside the team. Turn off reveal approval "
                            "on this secret (or the project default), or add them "
                            "to the team first.",
                            "error",
                        )
                        return redirect(access_url)
            # Replace any existing secret-scope binding for this subject
            cur.execute(
                """
                DELETE FROM rbac.bindings
                WHERE scope_kind = 'secret' AND scope_id = %s::uuid
                  AND subject_kind = %s AND subject_id = %s::uuid
                """,
                (str(secret_id), subject_kind, subject_id),
            )
            cur.execute(
                """
                INSERT INTO rbac.bindings
                  (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                VALUES (%s::uuid, %s, %s::uuid, 'secret', %s::uuid, %s::uuid)
                """,
                (
                    str(role["id"]),
                    subject_kind,
                    subject_id,
                    str(secret_id),
                    session["user_id"],
                ),
            )
            # Restricted mode if not already — bindings only apply as exclusive when restricted
            if (sec.get("access_mode") or "inherit") != "restricted":
                cur.execute(
                    """
                    UPDATE api.secrets SET access_mode = 'restricted'
                    WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                    """,
                    (str(secret_id), str(project_id)),
                )
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=secret_id,
                secret_key=sec["key"],
                action="updated",
            )
            conn.commit()
            if external_user:
                flash(
                    f"Bound {who} as {role_name}. They are not on this team - "
                    "they will only see this secret under Workspace → Shared secrets.",
                    "ok",
                )
            else:
                flash(f"Bound {who} as {role_name}", "ok")
        except Exception as e:
            conn.rollback()
            flash(str(e), "error")
    return redirect(access_url)


@authz.login_required
def delete_secret_access_binding(project_id, secret_id, grant_id):
    """Remove a secret-scope role binding (project admin only)."""
    access_url = url_for(
        "secret_view",
        project_id=project_id,
        secret_id=secret_id,
        tab="access",
    )
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
        if not (cur.fetchone() or {}).get("a"):
            flash("Only project admins can manage secret bindings", "error")
            return redirect(access_url)
        cur.execute(
            """
            DELETE FROM rbac.bindings b
            USING api.secrets s
            WHERE b.id = %s::uuid
              AND b.scope_kind = 'secret'
              AND b.scope_id = s.id
              AND s.id = %s::uuid AND s.project_id = %s::uuid
            RETURNING s.key
            """,
            (str(grant_id), str(secret_id), str(project_id)),
        )
        row = cur.fetchone()
        if not row:
            flash("Binding not found", "error")
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
            flash("Binding removed", "ok")
    return redirect(access_url)
