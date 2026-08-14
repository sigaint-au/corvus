"""Management API team routes."""

from __future__ import annotations

from flask import (
    jsonify,
    request,
)
import audit
import authz
import config
import db
import rbac_sync
import settings_svc
from lib.users import lookup_user_id
from .helpers import (
    _require_pat,
    _resolve_team,
    _row,
)


def mgmt_list_teams():
    """List teams the PAT user can access.

    Args:
        None (optional query ``q``).

    Returns:
        JSON ``{"items":[…]}``.
    """
    uid, err = _require_pat()
    if err:
        return err
    q = (request.args.get("q") or "").strip()
    like = f"%{q}%" if q else None
    with db.as_user(uid) as conn, conn.cursor() as cur:
        sql = """
            SELECT t.id, t.name, t.created_at,
              COALESCE(api.team_role(t.id), 'team-owner') AS role,
              (SELECT count(*) FROM api.projects p WHERE p.team_id = t.id) AS project_count
            FROM api.teams t
            WHERE (%s OR api.is_team_member(t.id))
        """
        params: list = [authz.is_global_admin(uid)]
        if like:
            sql += " AND t.name ILIKE %s"
            params.append(like)
        cur.execute(sql + " ORDER BY t.name", params)
        rows = [_row(r) for r in (cur.fetchall() or [])]
    return jsonify({"items": rows})


def mgmt_create_team():
    """Create a team. Body: ``{"name":"…"}``.

    Returns:
        JSON team id/name or error.
    """
    uid, err = _require_pat()
    if err:
        return err
    if not settings_svc.can_create_team(authz.is_global_admin(uid)):
        return jsonify({"error": "not allowed to create teams"}), 403
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    with db.connect(autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT private.create_team(%s::uuid, %s) AS id",
            (uid, name),
        )
        tid = str(cur.fetchone()["id"])
    return jsonify({"ok": True, "id": tid, "name": name}), 201


def mgmt_get_team(team_ref):
    """Get team detail including members and projects."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT * FROM api.teams WHERE id = %s::uuid", (tid,))
        team = _row(cur.fetchone())
        members = rbac_sync.list_scope_bindings(cur, "team", tid)
        rbac_sync.enrich_binding_emails(members)
        members = [
            {
                "user_id": str(item["subject_id"]),
                "email": item.get("subject_email") or "",
                "role": item.get("role_name"),
            }
            for item in members
            if item.get("subject_kind") == "User"
        ]
        cur.execute(
            """
            SELECT id, name, created_at FROM api.projects
             WHERE team_id = %s::uuid ORDER BY name
            """,
            (tid,),
        )
        projects = [_row(r) for r in (cur.fetchall() or [])]
    return jsonify({"team": team, "members": members, "projects": projects})


def mgmt_delete_team(team_ref):
    """Delete a team (owner/admin)."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        cur.execute("DELETE FROM api.teams WHERE id = %s::uuid", (tid,))
        if cur.rowcount == 0:
            return jsonify({"error": "forbidden"}), 403
        conn.commit()
    return jsonify({"ok": True, "id": tid})


def mgmt_list_team_members(team_ref):
    """List team members."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        items = rbac_sync.list_scope_bindings(cur, "team", tid)
        rbac_sync.enrich_binding_emails(items)
        items = [
            {
                "user_id": str(item["subject_id"]),
                "email": item.get("subject_email") or "",
                "role": item.get("role_name"),
                "source": item.get("source", "manual"),
            }
            for item in items
            if item.get("subject_kind") == "User"
        ]
    return jsonify({"items": items})


def mgmt_add_team_binding(team_ref):
    """Add/update team member. Body: ``{"email":"…","role":"team-member"}``."""
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    role = (body.get("role") or "team-member").strip()
    role_names = config.RBAC_TEAM_ROLE_NAMES
    if role not in role_names:
        role = "team-member"
    if not email:
        return jsonify({"error": "email required"}), 400
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT api.can_manage_rbac('team', %s::uuid) AS ok", (tid,))
        if not (cur.fetchone() or {}).get("ok"):
            return jsonify({"error": "forbidden"}), 403
        # M1: only team owners may assign owner
        cur.execute("SELECT api.team_role(%s::uuid) AS r", (tid,))
        my_role = (cur.fetchone() or {}).get("r")
        if role == "team-owner" and my_role != "team-owner":
            return jsonify({"error": "only a team owner can grant owner"}), 403
        mid = lookup_user_id(cur, email)
        if not mid:
            return jsonify({"error": "user not found"}), 404
        cur.execute(
            """
            SELECT r.name AS role_name
            FROM rbac.bindings b
            JOIN rbac.roles r ON r.id = b.role_id
            WHERE b.scope_kind = 'team' AND b.scope_id = %s::uuid
              AND b.subject_kind = 'User' AND b.subject_id = %s::uuid
              AND r.name IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')
            """,
            (tid, mid),
        )
        prev = cur.fetchone()
        rbac_sync.sync_user_team_binding(
            cur, user_id=mid, team_id=tid, role=role, created_by=uid
        )
        if not cur.rowcount:
            return jsonify({"error": "forbidden"}), 403
        action = audit.ORG_MEMBER_ROLE if prev else audit.ORG_MEMBER_ADD
        detail = f"{email} → {role}"
        if prev:
            detail = f"{email}: {prev['role_name']} → {role}"
        audit.log_org(cur, team_id=tid, action=action, detail=detail)
        conn.commit()
    return jsonify({"ok": True, "email": email, "role": role})


def mgmt_remove_team_binding(team_ref, member_ref):
    """Remove team member by email or user id."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT api.can_manage_rbac('team', %s::uuid) AS ok", (tid,))
        if not (cur.fetchone() or {}).get("ok"):
            return jsonify({"error": "forbidden"}), 403
        mid = lookup_user_id(cur, member_ref)
        if not mid:
            return jsonify({"error": "user not found"}), 404
        cur.execute(
            """
            SELECT 1 FROM rbac.bindings b
            JOIN rbac.roles r ON r.id = b.role_id
            WHERE b.scope_kind = 'team' AND b.scope_id = %s::uuid
              AND b.subject_kind = 'User' AND b.subject_id = %s::uuid
              AND r.name IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')
            """,
            (tid, mid),
        )
        if not cur.fetchone():
            return jsonify({"error": "member not found"}), 404
        rbac_sync.sync_user_team_binding(
            cur, user_id=mid, team_id=tid, role=None, created_by=uid
        )
        audit.log_org(
            cur,
            team_id=tid,
            action=audit.ORG_MEMBER_REMOVE,
            detail=member_ref,
        )
        conn.commit()
    return jsonify({"ok": True})


def mgmt_transfer_team(team_ref):
    """Transfer team ownership. Body: ``{"email":"…"}``."""
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email required"}), 400
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT api.can_manage_rbac('team', %s::uuid) AS ok", (tid,))
        if not (cur.fetchone() or {}).get("ok"):
            return jsonify({"error": "forbidden"}), 403
        mid = lookup_user_id(cur, email)
        if not mid:
            return jsonify({"error": "user not found"}), 404
        # Promote the new owner first, then demote existing owners.
        rbac_sync.sync_user_team_binding(
            cur, user_id=mid, team_id=tid, role="team-owner", created_by=uid
        )
        cur.execute(
            """
            SELECT b.subject_id
            FROM rbac.bindings b
            JOIN rbac.roles r ON r.id = b.role_id
            WHERE b.scope_kind = 'team' AND b.scope_id = %s::uuid
              AND b.subject_kind = 'User' AND r.name = 'team-owner'
              AND b.subject_id <> %s::uuid
            """,
            (tid, mid),
        )
        for owner in cur.fetchall() or []:
            rbac_sync.sync_user_team_binding(
                cur,
                user_id=owner["subject_id"],
                team_id=tid,
                role="team-admin",
                created_by=uid,
            )
        audit.log_org(
            cur,
            team_id=tid,
            action=audit.ORG_OWNERSHIP,
            detail=f"owner → {email}",
        )
        conn.commit()
    return jsonify({"ok": True, "owner": email})
