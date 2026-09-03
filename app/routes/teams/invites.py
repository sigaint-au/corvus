"""Team invite and join-request routes."""

from __future__ import annotations

import secrets
from datetime import (
    datetime,
    timedelta,
    timezone,
)

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
from crypto import sha256_hex

from .members import members_response


@authz.login_required
def create_team_invite(team_id):
    """Create a single-use team invite link with role and expiry.

    Args:
        team_id: UUID of the team to invite users into.

    Returns:
        Redirect to the team members tab; invite URL is stored once in session.

    Example:
        POST /teams/<team_id>/invites with role and expires_days form fields
    """
    role = request.form.get("role", "team-member")
    if role not in config.INVITE_ROLES:
        role = "team-member"
    days = 7
    raw_days = (request.form.get("expires_days") or "7").strip()
    try:
        days = max(1, min(90, int(raw_days)))
    except ValueError:
        days = 7
    raw = secrets.token_urlsafe(24)
    thash = sha256_hex(raw)
    expires = datetime.now(timezone.utc) + timedelta(days=days)
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                """
                INSERT INTO api.team_invites
                  (team_id, token_hash, role, expires_at, created_by)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    str(team_id),
                    thash,
                    role,
                    expires,
                    session["user_id"],
                ),
            )
            row = cur.fetchone()
            if not row:
                flash("Permission denied", "error")
                conn.rollback()
                return members_response(team_id)
            audit.log_org(
                cur,
                team_id=team_id,
                action=audit.ORG_INVITE_CREATE,
                detail=f"role={role} expires={days}d",
            )
            conn.commit()
        except Exception:
            flash("Could not update the invitation. Try again.", "error")
            return members_response(team_id)
    session["new_invite_url"] = url_for("redeem_invite", token=raw, _external=True)
    flash("Invite link created. Copy it now; it shows only this once.", "ok")
    return members_response(team_id)


@authz.login_required
def revoke_team_invite(team_id, invite_id):
    """Revoke an outstanding team invite.

    Args:
        team_id: UUID of the team that owns the invite.
        invite_id: UUID of the invite to revoke.

    Returns:
        Redirect to the team members tab.

    Example:
        POST /teams/<team_id>/invites/<invite_id>/revoke
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE api.team_invites SET revoked_at = now()
            WHERE id = %s AND team_id = %s AND revoked_at IS NULL
            """,
            (str(invite_id), str(team_id)),
        )
        if cur.rowcount:
            audit.log_org(
                cur,
                team_id=team_id,
                action=audit.ORG_INVITE_REVOKE,
                detail=str(invite_id),
            )
            conn.commit()
            flash("Invite revoked", "ok")
        else:
            flash("Invite not found or already revoked", "error")
    return members_response(team_id)


def redeem_invite(token):
    """Redeem a team invite token and create a pending join request.

    Args:
        token: Raw invite token from the invite URL.

    Returns:
        Redirect to login (if unauthenticated), team detail (if already a
        member), or the teams list after submitting a join request.

    Example:
        GET /invite/<token>
    """
    # Preserve invite across login (bearer token in URL is lost if bounced without context)
    if not session.get("user_id"):
        session["invite_token"] = token
        flash("Sign in to accept this team invite", "ok")
        return redirect(url_for("login"))
    thash = sha256_hex(token)
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM private.lookup_invite(%s)", (thash,))
        inv = cur.fetchone()
        if not inv:
            flash("Invite invalid or expired", "error")
            return redirect(url_for("teams"))
        # Already a member?
        cur.execute(
            """
            SELECT 1
            FROM rbac.bindings b
            JOIN rbac.roles r ON r.id = b.role_id
            WHERE b.scope_kind = 'team' AND b.scope_id = %s::uuid
              AND b.subject_kind = 'User' AND b.subject_id = %s::uuid
              AND r.name IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')
            """,
            (str(inv["team_id"]), session["user_id"]),
        )
        if cur.fetchone():
            flash(f"You are already a member of {inv['team_name']}", "ok")
            return redirect(url_for("team_detail", team_id=inv["team_id"]))
        try:
            cur.execute(
                """
                INSERT INTO api.team_join_requests
                  (team_id, invite_id, user_id, role, status)
                SELECT %s, %s, %s, %s, 'pending'
                WHERE NOT EXISTS (
                  SELECT 1 FROM api.team_join_requests
                  WHERE team_id = %s AND user_id = %s AND status = 'pending'
                )
                """,
                (
                    str(inv["team_id"]),
                    str(inv["invite_id"]),
                    session["user_id"],
                    inv["role"],
                    str(inv["team_id"]),
                    session["user_id"],
                ),
            )
            audit.log_org(
                cur,
                team_id=inv["team_id"],
                action=audit.ORG_JOIN_REQUEST,
                detail=f"via invite role={inv['role']}",
            )
            conn.commit()
            flash(
                f"Join request sent for team “{inv['team_name']}”. "
                "An owner or admin must approve it.",
                "ok",
            )
        except Exception:
            conn.rollback()
            flash("Could not update the invitation. Try again.", "error")
    return redirect(url_for("teams"))


@authz.login_required
def approve_join_request(team_id, req_id):
    """Approve a pending team join request and add the user as a member.

    Args:
        team_id: UUID of the team.
        req_id: UUID of the join request to approve.

    Returns:
        Redirect to the team members tab.

    Example:
        POST /teams/<team_id>/join-requests/<req_id>/approve
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
        if (cur.fetchone() or {}).get("r") not in ("team-owner", "team-admin"):
            flash("Only owners or admins can approve join requests", "error")
            return members_response(team_id)
        cur.execute(
            """
            SELECT id, user_id, role, status FROM api.team_join_requests
            WHERE id = %s AND team_id = %s
            """,
            (str(req_id), str(team_id)),
        )
        req = cur.fetchone()
        if not req or req["status"] != "pending":
            flash("Request not found", "error")
            return members_response(team_id)
        try:
            # Role in request row can be 'team-member' or legacy 'member'
            req_role = req["role"]
            if req_role not in config.RBAC_TEAM_ROLE_NAMES:
                legacy_map = {
                    "owner": "team-owner",
                    "admin": "team-admin",
                    "member": "team-member",
                    "viewer": "team-viewer",
                }
                req_role = legacy_map.get(req_role, "team-member")
            rbac_sync.sync_user_team_binding(
                cur,
                user_id=req["user_id"],
                team_id=team_id,
                role=req_role,
                created_by=session["user_id"],
            )
            cur.execute(
                """
                UPDATE api.team_join_requests
                SET status = 'approved', resolved_at = now(), resolved_by = %s
                WHERE id = %s
                """,
                (session["user_id"], str(req_id)),
            )
            audit.log_org(
                cur,
                team_id=team_id,
                action=audit.ORG_JOIN_APPROVE,
                detail=f"user={req['user_id']} role={req['role']}",
            )
            conn.commit()
            flash("Join request approved", "ok")
        except Exception:
            conn.rollback()
            flash("Could not update the invitation. Try again.", "error")
    return members_response(team_id)


@authz.login_required
def reject_join_request(team_id, req_id):
    """Reject a pending team join request.

    Args:
        team_id: UUID of the team.
        req_id: UUID of the join request to reject.

    Returns:
        Redirect to the team members tab.

    Example:
        POST /teams/<team_id>/join-requests/<req_id>/reject
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
        if (cur.fetchone() or {}).get("r") not in ("team-owner", "team-admin"):
            flash("Only owners or admins can reject join requests", "error")
            return members_response(team_id)
        cur.execute(
            """
            UPDATE api.team_join_requests
            SET status = 'rejected', resolved_at = now(), resolved_by = %s
            WHERE id = %s AND team_id = %s AND status = 'pending'
            """,
            (session["user_id"], str(req_id), str(team_id)),
        )
        if cur.rowcount:
            audit.log_org(
                cur,
                team_id=team_id,
                action=audit.ORG_JOIN_REJECT,
                detail=str(req_id),
            )
            conn.commit()
            flash("Join request rejected", "ok")
        else:
            flash("Request not found", "error")
    return members_response(team_id)
