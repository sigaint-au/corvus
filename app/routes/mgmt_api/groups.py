"""Management API team-group routes (PAT only, RLS-gated)."""

from __future__ import annotations

from flask import jsonify, request

import audit
from core import db
from lib.users import lookup_user_id

from .helpers import (
    _require_pat,
    _resolve_team,
    _row,
)


def _find_group(cur, team_id, ref):
    if not ref:
        return None
    cur.execute(
        """
        SELECT id, name, source, external_key, created_at
          FROM api.groups
         WHERE team_id = %s::uuid
           AND (id = %s::uuid OR name = %s)
         ORDER BY created_at LIMIT 2
        """,
        (team_id, ref, ref),
    )
    rows = (cur.fetchall() or [])
    return rows[0] if len(rows) == 1 else None


def mgmt_list_groups(team_ref):
    """List groups for a team."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            SELECT id, name, source, external_key, created_at
              FROM api.groups
             WHERE team_id = %s::uuid ORDER BY name
            """,
            (tid,),
        )
        items = [_row(r) for r in (cur.fetchall() or [])]
    return jsonify({"items": items})


def mgmt_create_group(team_ref):
    """Create a team-scoped group. Body: ``{"name", "source": manual|ldap|oidc,
    "external_key"}`` (source/external_key optional; ldap/oidc need external_key)."""
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    source = (body.get("source") or "manual").strip().lower()
    if source not in ("manual", "ldap", "oidc"):
        source = "manual"
    external_key = (body.get("external_key") or "").strip() or None
    if source == "manual":
        external_key = None
    elif not external_key:
        return jsonify({"error": "external_key required for ldap/oidc groups"}), 400
    if not name:
        return jsonify({"error": "name required"}), 400
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            INSERT INTO api.groups (team_id, name, source, external_key)
            VALUES (%s::uuid, %s, %s, %s) RETURNING id
            """,
            (tid, name, source, external_key),
        )
        g = cur.fetchone()
        if not g:
            return jsonify({"error": "forbidden"}), 403
        audit.log_org(
            cur, team_id=tid, action="group_add", detail=f"{name} ({source})"
        )
        conn.commit()
    return jsonify({"ok": True, "id": str(g["id"]), "name": name, "source": source})


def mgmt_delete_group(team_ref, group_ref):
    """Delete a team group and its memberships/grants."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        g = _find_group(cur, tid, group_ref)
        if not g:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            "DELETE FROM api.groups WHERE id = %s::uuid", (str(g["id"]),)
        )
        if cur.rowcount == 0:
            return jsonify({"error": "forbidden"}), 403
        audit.log_org(cur, team_id=tid, action="group_delete", detail=g["name"])
        conn.commit()
    return jsonify({"ok": True, "id": str(g["id"]), "name": g["name"]})


def mgmt_add_group_member(team_ref, group_ref):
    """Add a manual member to a group. Body: ``{"email": "…"}``."""
    uid, err = _require_pat()
    if err:
        return err
    email = (request.get_json(silent=True) or {}).get("email") or ""
    email = email.strip().lower()
    if not email:
        return jsonify({"error": "email required"}), 400
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        g = _find_group(cur, tid, group_ref)
        if not g:
            return jsonify({"error": "not found"}), 404
        subject_id = lookup_user_id(cur, email)
        if not subject_id:
            return jsonify({"error": "user not found — they must register first"}), 404
        cur.execute(
            """
            INSERT INTO api.group_members (group_id, user_id, source)
            VALUES (%s::uuid, %s::uuid, 'manual')
            ON CONFLICT (group_id, user_id) DO UPDATE SET source = 'manual'
            """,
            (str(g["id"]), subject_id),
        )
        audit.log_org(cur, team_id=tid, action="group_member_add", detail=email)
        conn.commit()
    return jsonify({"ok": True, "group": g["name"], "email": email})


def mgmt_remove_group_member(team_ref, group_ref, member_ref):
    """Remove a member from a group (``member_ref`` = user id or email)."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        g = _find_group(cur, tid, group_ref)
        if not g:
            return jsonify({"error": "not found"}), 404
        mid = lookup_user_id(cur, member_ref)
        if not mid:
            return jsonify({"error": "member not found"}), 404
        cur.execute(
            """
            DELETE FROM api.group_members gm
             USING api.groups g
             WHERE gm.group_id = g.id AND g.id = %s::uuid AND g.team_id = %s::uuid
               AND gm.user_id = %s::uuid
            """,
            (str(g["id"]), tid, mid),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
        audit.log_org(cur, team_id=tid, action="group_member_remove", detail=mid)
        conn.commit()
    return jsonify({"ok": True, "group": g["name"], "member": member_ref})
