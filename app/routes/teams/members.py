"""Team member and access-binding routes."""

from __future__ import annotations

from flask import (
    flash,
    redirect,
    request,
    session,
    url_for,
)

import audit
from auth import authz, rbac_sync
from core import config, db
from lib.users import lookup_user_id


@authz.login_required
def team_access_binding_create(team_id):
    """Create a team-scope role binding (team admin)."""
    access_url = url_for("team_detail", team_id=team_id, tab="access")
    role_name = (request.form.get("role_name") or "").strip()
    subject_kind = (request.form.get("subject_kind") or "User").strip()
    subject_email = (request.form.get("subject_email") or "").strip().lower()
    subject_group = (request.form.get("subject_group") or "").strip()
    subject_sa = (request.form.get("subject_sa") or "").strip()
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT api.can_manage_rbac('team', %s::uuid) AS ok",
            (str(team_id),),
        )
        if not (cur.fetchone() or {}).get("ok"):
            flash("Only team admins can manage role bindings", "error")
            return redirect(access_url)
        try:
            cur.execute("SELECT id FROM rbac.roles WHERE name = %s", (role_name,))
            role = cur.fetchone()
            if not role:
                flash("Unknown role", "error")
                return redirect(access_url)
            subject_id = None
            if subject_kind == "User":
                subject_id = lookup_user_id(cur, subject_email)
                if not subject_id:
                    flash("User not found — they must register first", "error")
                    return redirect(access_url)
            elif subject_kind == "Group":
                cur.execute(
                    """
                    SELECT id FROM api.groups
                    WHERE id = %s::uuid AND team_id = %s::uuid
                    """,
                    (subject_group, str(team_id)),
                )
                g = cur.fetchone()
                if not g:
                    flash("Group not found on this team", "error")
                    return redirect(access_url)
                subject_id = str(g["id"])
            elif subject_kind == "ServiceAccount":
                subject_id = subject_sa
            else:
                flash("Invalid subject kind", "error")
                return redirect(access_url)
            if not subject_id:
                flash("Subject required", "error")
                return redirect(access_url)
            cur.execute(
                """
                INSERT INTO rbac.bindings
                  (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                VALUES (%s::uuid, %s, %s::uuid, 'team', %s::uuid, %s::uuid)
                """,
                (
                    str(role["id"]),
                    subject_kind,
                    subject_id,
                    str(team_id),
                    session["user_id"],
                ),
            )
            conn.commit()
            flash("Binding created", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update team membership. Try again.", "error")
    return redirect(access_url)


@authz.login_required
def team_access_binding_delete(team_id, binding_id):
    """Remove a team-scope role binding (team admin)."""
    access_url = url_for("team_detail", team_id=team_id, tab="access")
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT api.can_manage_rbac('team', %s::uuid) AS ok",
            (str(team_id),),
        )
        if not (cur.fetchone() or {}).get("ok"):
            flash("Only team admins can manage role bindings", "error")
            return redirect(access_url)
        try:
            cur.execute(
                """
                DELETE FROM rbac.bindings
                WHERE id = %s::uuid
                  AND scope_kind = 'team'
                  AND scope_id = %s::uuid
                """,
                (str(binding_id), str(team_id)),
            )
            if cur.rowcount:
                conn.commit()
                flash("Binding removed", "ok")
            else:
                conn.rollback()
                flash("Binding not found or not permitted", "error")
        except Exception:
            conn.rollback()
            flash("Could not update team membership. Try again.", "error")
    return redirect(access_url)


@authz.login_required
def add_team_binding(team_id):
    """Add or update a team member by email and role.

    Args:
        team_id: UUID of the team to modify.

    Returns:
        Redirect to the team members tab.

    Example:
        POST /teams/<team_id>/members with email and role form fields
    """
    email = request.form.get("email", "").strip().lower()
    role = request.form.get("role", "team-member")
    role_names = config.RBAC_TEAM_ROLE_NAMES
    if role not in role_names:
        role = "team-member"
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        # M1: only team owners may assign owner (admins cannot self-promote)
        cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
        my_role = (cur.fetchone() or {}).get("r")
        if role == "team-owner" and my_role != "team-owner":
            flash("Only a team owner can grant the owner role", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="members"))
        uid = lookup_user_id(cur, email)
        if not uid:
            flash("User not found — they must register or sign in via LDAP first", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="members"))
        try:
            # Check for existing binding to determine add vs update
            rname = role
            cur.execute("SELECT id FROM rbac.roles WHERE name = %s", (rname,))
            role_row = cur.fetchone()
            if not role_row:
                flash(f"Built-in role {rname} missing — run schema ensure", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="members"))
            # Check existing team binding for this user
            cur.execute(
                """
                SELECT b.id, r.name AS role_name
                FROM rbac.bindings b
                JOIN rbac.roles r ON r.id = b.role_id
                WHERE b.subject_kind = 'User' AND b.subject_id = %s::uuid
                  AND b.scope_kind = 'team' AND b.scope_id = %s::uuid
                  AND r.name IN ('team-owner','team-admin','team-member','team-viewer')
                """,
                (uid, str(team_id)),
            )
            prev = cur.fetchone()
            rbac_sync.sync_user_team_binding(
                cur,
                user_id=uid,
                team_id=team_id,
                role=role,
                created_by=session["user_id"],
            )
            action = audit.ORG_MEMBER_ROLE if prev else audit.ORG_MEMBER_ADD
            detail = f"{email} → {role}"
            if prev:
                detail = f"{email}: {prev['role_name']} → {role}"
            audit.log_org(cur, team_id=team_id, action=action, detail=detail)
            conn.commit()
            flash(f"Bound {email} as {role}", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update team membership. Try again.", "error")
    return redirect(url_for("team_detail", team_id=team_id, tab="members"))


@authz.login_required
def remove_team_binding(team_id, user_id):
    """Remove a member from a team.

    Args:
        team_id: UUID of the team.
        user_id: UUID of the user to remove.

    Returns:
        Redirect to the team members tab.

    Example:
        POST /teams/<team_id>/members/<user_id>/remove
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            # Find existing team binding for this user
            cur.execute(
                """
                SELECT b.id, r.name AS role_name
                FROM rbac.bindings b
                JOIN rbac.roles r ON r.id = b.role_id
                WHERE b.subject_kind = 'User' AND b.subject_id = %s::uuid
                  AND b.scope_kind = 'team' AND b.scope_id = %s::uuid
                  AND r.name IN ('team-owner','team-admin','team-member','team-viewer')
                """,
                (str(user_id), str(team_id)),
            )
            row = cur.fetchone()
            if not row:
                flash("Member not found", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="members"))
            rbac_sync.sync_user_team_binding(
                cur, user_id=user_id, team_id=team_id, role=None
            )
            audit.log_org(
                cur,
                team_id=team_id,
                action=audit.ORG_MEMBER_REMOVE,
                detail=f"user {user_id} ({row['role_name']})",
            )
            conn.commit()
            flash("Member removed", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update team membership. Try again.", "error")
    return redirect(url_for("team_detail", team_id=team_id, tab="members"))


@authz.login_required
def transfer_team_ownership(team_id):
    """Transfer team ownership to another registered user by email.

    Args:
        team_id: UUID of the team whose ownership is transferred.

    Returns:
        Redirect to the team settings tab.

    Example:
        POST /teams/<team_id>/transfer with form field email=newowner@example.com
    """
    email = (request.form.get("email") or "").strip().lower()
    if not email:
        flash("Enter an email address.", "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
        if (cur.fetchone() or {}).get("r") != "team-owner":
            flash("Only owners can transfer ownership", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
        new_uid = lookup_user_id(cur, email)
        if not new_uid:
            flash("User not found — they must already be registered", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
        if new_uid == session["user_id"]:
            flash("Already owner", "ok")
            return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
        try:
            # Promote new owner first (avoids last-owner guard)
            rbac_sync.sync_user_team_binding(
                cur,
                user_id=new_uid,
                team_id=team_id,
                role="team-owner",
                created_by=session["user_id"],
            )
            rbac_sync.sync_user_team_binding(
                cur,
                user_id=session["user_id"],
                team_id=team_id,
                role="team-admin",
                created_by=session["user_id"],
            )
            audit.log_org(
                cur,
                team_id=team_id,
                action=audit.ORG_OWNERSHIP,
                detail=f"ownership → {email}",
            )
            conn.commit()
            flash(f"Ownership transferred to {email}", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update team membership. Try again.", "error")
    return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
