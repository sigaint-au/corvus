"""Team-scoped project create/delete routes."""

from __future__ import annotations

from flask import (
    flash,
    redirect,
    request,
    session,
    url_for,
)
import authz
import db


@authz.login_required
def create_project(team_id):
    """Create a project under the given team.

    Args:
        team_id: UUID of the parent team.

    Returns:
        Redirect to the new project detail page, or back to the team on error.

    Example:
        POST /teams/<team_id>/projects with form field name=My Project
    """
    name = request.form["name"].strip()
    description = (request.form.get("description") or "").strip()[:500]
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
                flash("You don't have permission to do that", "error")
                conn.rollback()
                return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
            pid = row["id"]
            conn.commit()
        except Exception as e:
            flash(str(e), "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
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
        cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
        row = cur.fetchone()
        if not row or row["r"] not in ("team-owner", "team-admin"):
            flash("Only team owners or admins can delete projects", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
        cur.execute(
            "DELETE FROM api.projects WHERE id = %s AND team_id = %s",
            (str(project_id), str(team_id)),
        )
        if cur.rowcount == 0:
            flash("You don't have permission to do that", "error")
            conn.rollback()
        else:
            conn.commit()
            flash("Project deleted", "ok")
    return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
