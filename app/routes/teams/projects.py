"""Team-scoped project create/delete routes."""

from __future__ import annotations

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import audit
from auth import authz
from core import db


@authz.login_required
def new_project_wizard(team_id):
    """Render the project onboarding wizard (Basics → Encryption → Create).

    Args:
        team_id: UUID of the parent team.

    Returns:
        HTML onboarding page, or redirect to the team when not permitted.

    Example:
        GET /teams/<team_id>/projects/new
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        from auth.roles import MANAGE_TIER, MEMBER_TIER, team_role_at_least

        team = db.team(cur, team_id)
        if not team:
            return "Not found", 404
        cur.execute("SELECT api.team_role(%s::uuid) AS r", (str(team_id),))
        my_role = (cur.fetchone() or {}).get("r") or ""
        can_create = team_role_at_least(cur, my_role, MEMBER_TIER)
        can_manage_team = team_role_at_least(cur, my_role, MANAGE_TIER)
    if not can_create:
        flash("You don't have permission to create projects", "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
    hsm_slots = []
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM api.list_hsm_slots()")
            hsm_slots = cur.fetchall() or []
    except Exception:
        hsm_slots = []
    return render_template(
        "team_new_project.html",
        team=team,
        my_role=my_role,
        can_manage_team=can_manage_team,
        encryption="managed",
        hsm_available=bool(hsm_slots),
        hsm_slots=hsm_slots,
    )


@authz.login_required
def create_project(team_id):
    """Create a project under the given team.

    Args:
        team_id: UUID of the parent team.

    Returns:
        Redirect to the new project detail page, or back to the team on error.

    Example:
        POST /teams/<team_id>/projects with form fields name=My Project,
        encryption=byok
    """
    name = request.form.get("name", "").strip()
    description = (request.form.get("description") or "").strip()[:500]
    encryption = (request.form.get("encryption") or "managed").strip().lower()
    hsm_slot = (request.form.get("hsm_slot") or "").strip() or None
    pid = None
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                """
                INSERT INTO api.projects (team_id, name, description)
                VALUES (%s, %s, %s) RETURNING id
                """,
                (str(team_id), name, description),
            )
            row = cur.fetchone()
            if not row:
                flash("Permission denied", "error")
                conn.rollback()
                return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
            pid = row["id"]
            conn.commit()
        except Exception:
            flash("Could not update the project. Try again.", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
    if encryption in ("byok", "project", "hsm"):
        from crypto import project_keys

        provider = "hsm" if encryption == "hsm" else "local"
        if provider == "hsm" and not hsm_slot:
            try:
                with db.connect_admin() as aconn, aconn.cursor() as acur:
                    acur.execute("DELETE FROM api.projects WHERE id = %s", (str(pid),))
            except Exception:
                pass
            flash(
                "External HSM requires a named slot; choose Server key or Project key, "
                "or configure an HSM slot first.",
                "error",
            )
            return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
        try:
            project_keys.ensure_project_key(pid, provider=provider, hsm_slot_id=hsm_slot)
        except Exception as e:
            # Roll back the creation: remove the project so we never leave a
            # project that advertised BYOK but has no key. CASCADE clears any
            # partially-created key row.
            try:
                with db.connect_admin() as aconn, aconn.cursor() as acur:
                    acur.execute("DELETE FROM api.projects WHERE id = %s", (str(pid),))
            except Exception:
                pass
            flash(
                f"Could not create the project key ({e}); project creation was rolled back",
                "error",
            )
            return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            audit.log_org(
                cur,
                team_id=team_id,
                project_id=pid,
                action="project_key_created",
                detail=f"byok ({provider} key)",
            )
            conn.commit()
    return redirect(url_for("project_detail", project_id=pid))


@authz.login_required
def delete_project_from_team(team_id, project_id):
    """Delete a project from a team. Owner/admin only — RLS projects_delete enforces.

    Args:
        team_id: UUID of the parent team.
        project_id: UUID of the project to delete.

    Returns:
        Redirect to the team projects tab.

    Example:
        POST /teams/<team_id>/projects/<project_id>/delete
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        from auth.roles import MANAGE_TIER, team_role_at_least

        cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
        row = cur.fetchone()
        if not row or not team_role_at_least(cur, row["r"], MANAGE_TIER):
            flash("Only team owners or admins can delete projects", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
        cur.execute(
            "DELETE FROM api.projects WHERE id = %s AND team_id = %s",
            (str(project_id), str(team_id)),
        )
        if cur.rowcount == 0:
            flash("Permission denied", "error")
            conn.rollback()
        else:
            conn.commit()
            flash("Project deleted", "ok")
    return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
