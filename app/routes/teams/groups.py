"""Team group management routes."""

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
from auth import authz, rbac_sync
from core import db
from lib.users import lookup_user_id


def _group_detail_url(team_id, group_id, **extra):
    return url_for("team_group_detail", team_id=team_id, group_id=group_id, **extra)


@authz.login_required
def team_group_detail(team_id, group_id):
    """Group settings and membership (dedicated page with member search)."""
    session["team_id"] = str(team_id)
    q = (request.args.get("q") or "").strip()
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM api.teams WHERE id = %s", (str(team_id),))
        team = cur.fetchone()
        if not team:
            return "Not found", 404
        cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
        my_role = (cur.fetchone() or {}).get("r")
        is_admin = my_role in ("team-owner", "team-admin") or bool(
            session.get("is_global_admin")
        )
        cur.execute(
            """
            SELECT id, name, source, external_key, created_at
            FROM api.groups
            WHERE id = %s AND team_id = %s
            """,
            (str(group_id), str(team_id)),
        )
        group = cur.fetchone()
        if group:
            group["team_role"] = rbac_sync.group_team_roles_map(cur, team_id).get(
                str(group_id)
            )
        if not group:
            flash("Group not found", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="groups"))
        try:
            cur.execute(
                "SELECT * FROM private.group_member_rows(%s::uuid)",
                (str(group_id),),
            )
            members = list(cur.fetchall() or [])
        except Exception:
            members = []
        if q:
            ql = q.lower()
            members = [
                m
                for m in members
                if ql in (m.get("email") or "").lower()
                or ql in (m.get("name") or "").lower()
                or ql in (m.get("source") or "").lower()
            ]
    return render_template(
        "team_group.html",
        team=team,
        group=group,
        group_members=members,
        search_q=q,
        my_role=my_role,
        is_admin=is_admin,
    )


@authz.login_required
def create_team_group(team_id):
    """Create a team-scoped group (manual or LDAP/OIDC-mapped).

    Group membership only; grant team access via Members (Group subject binding).
    """
    name = (request.form.get("name") or "").strip()
    source = (request.form.get("source") or "manual").strip().lower()
    if source not in ("manual", "ldap", "oidc"):
        source = "manual"
    external_key = (request.form.get("external_key") or "").strip() or None
    if source == "manual":
        external_key = None
    elif not external_key:
        flash("External group key required for LDAP/OIDC groups", "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="groups"))
    if not name:
        flash("Group name required", "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="groups"))
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                """
                INSERT INTO api.groups (team_id, name, source, external_key)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (str(team_id), name, source, external_key),
            )
            gid = cur.fetchone()["id"]
            audit.log_org(
                cur,
                team_id=team_id,
                action="group_add",
                detail=f"{name} ({source})",
            )
            conn.commit()
            flash(
                f"Group “{name}” created — bind it under Members as subject Group",
                "ok",
            )
            return redirect(_group_detail_url(team_id, gid))
        except Exception:
            conn.rollback()
            flash("Could not update the group. Try again.", "error")
    return redirect(url_for("team_detail", team_id=team_id, tab="groups"))


@authz.login_required
def update_team_group(team_id, group_id):
    """Update group name or external mapping (not team role — use RBAC binding)."""
    name = (request.form.get("name") or "").strip()
    external_key = (request.form.get("external_key") or "").strip() or None
    if not name:
        flash("Group name required", "error")
        return redirect(_group_detail_url(team_id, group_id))
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                """
                UPDATE api.groups
                SET name = %s,
                    external_key = CASE
                      WHEN source = 'manual' THEN NULL
                      ELSE COALESCE(%s, external_key)
                    END
                WHERE id = %s AND team_id = %s
                RETURNING name
                """,
                (name, external_key, str(group_id), str(team_id)),
            )
            row = cur.fetchone()
            if not row:
                flash("Group not found or not permitted", "error")
                conn.rollback()
            else:
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action="group_update",
                    detail=name,
                )
                conn.commit()
                flash("Group updated", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update the group. Try again.", "error")
    return redirect(_group_detail_url(team_id, group_id))


@authz.login_required
def delete_team_group(team_id, group_id):
    """Delete a team group and its memberships/grants."""
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM api.groups
            WHERE id = %s AND team_id = %s
            RETURNING name
            """,
            (str(group_id), str(team_id)),
        )
        row = cur.fetchone()
        if not row:
            flash("Group not found or not permitted", "error")
            conn.rollback()
        else:
            audit.log_org(
                cur,
                team_id=team_id,
                action="group_delete",
                detail=row["name"],
            )
            conn.commit()
            flash(f"Group “{row['name']}” deleted", "ok")
    return redirect(url_for("team_detail", team_id=team_id, tab="groups"))


@authz.login_required
def add_group_member(team_id, group_id):
    """Add a manual member to a group."""
    email = (request.form.get("email") or "").strip().lower()
    if not email:
        flash("Enter an email address.", "error")
        return redirect(_group_detail_url(team_id, group_id))
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, source FROM api.groups WHERE id = %s AND team_id = %s",
            (str(group_id), str(team_id)),
        )
        g = cur.fetchone()
        if not g:
            flash("Group not found", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="groups"))
        uid = lookup_user_id(cur, email)
        if not uid:
            flash("User not found — they must register or sign in first", "error")
            return redirect(_group_detail_url(team_id, group_id))
        try:
            cur.execute(
                """
                INSERT INTO api.group_members (group_id, user_id, source)
                VALUES (%s, %s, 'manual')
                ON CONFLICT (group_id, user_id) DO UPDATE
                  SET source = 'manual'
                """,
                (str(group_id), uid),
            )
            audit.log_org(
                cur,
                team_id=team_id,
                action="group_member_add",
                detail=email,
            )
            conn.commit()
            flash(f"Added {email}", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update the group. Try again.", "error")
    return redirect(_group_detail_url(team_id, group_id))


@authz.login_required
def remove_group_member(team_id, group_id, user_id):
    """Remove a member from a group."""
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM api.group_members gm
            USING api.groups g
            WHERE gm.group_id = g.id
              AND g.id = %s AND g.team_id = %s
              AND gm.user_id = %s
            """,
            (str(group_id), str(team_id), str(user_id)),
        )
        if cur.rowcount:
            audit.log_org(
                cur,
                team_id=team_id,
                action="group_member_remove",
                detail=str(user_id),
            )
            conn.commit()
            flash("Member removed from group", "ok")
        else:
            flash("Member not found or not permitted", "error")
            conn.rollback()
    return redirect(_group_detail_url(team_id, group_id))
