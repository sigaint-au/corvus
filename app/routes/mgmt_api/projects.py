"""Management API project routes."""

from __future__ import annotations

from flask import (
    jsonify,
    request,
)

import audit
from auth import rbac_sync
from core import config, db
from lib.users import lookup_user_id

from .helpers import (
    _require_pat,
    _resolve_project,
    _resolve_team,
    _row,
)


def mgmt_create_project(team_ref):
    """Create project under team. Body: ``{"name":"…"}``."""
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    encryption = (body.get("encryption") or "managed").strip().lower()
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        try:
            cur.execute(
                """
                INSERT INTO api.projects (team_id, name)
                VALUES (%s::uuid, %s)
                RETURNING id, name, team_id, created_at
                """,
                (tid, name),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "forbidden"}), 403
            conn.commit()
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    if encryption in ("byok", "project"):
        from crypto import project_keys

        try:
            project_keys.ensure_project_key(str(row["id"]))
        except Exception:
            # Compensate (see ui create_project for rationale).
            try:
                with db.connect_admin() as aconn, aconn.cursor() as acur:
                    acur.execute(
                        "DELETE FROM api.projects WHERE id = %s",
                        (str(row["id"]),),
                    )
            except Exception:
                pass
            return jsonify({"error": "could not create project key; creation rolled back"}), 400
        with db.as_user(uid) as conn, conn.cursor() as cur:
            audit.log_org(
                cur,
                team_id=tid,
                project_id=row["id"],
                action="project_key_created",
                detail="byok (local key)",
            )
            conn.commit()
    return jsonify({"ok": True, **(_row(row) or {})}), 201


def mgmt_get_project(project_ref):
    """Get project detail with members and machine token metadata."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            SELECT p.id, p.name, p.team_id, p.created_at, t.name AS team_name
              FROM api.projects p
              JOIN api.teams t ON t.id = p.team_id
             WHERE p.id = %s::uuid
            """,
            (pid,),
        )
        proj = _row(cur.fetchone())
        members = rbac_sync.list_scope_bindings(cur, "project", pid)
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
            SELECT id, name, token_prefix, role, expires_at, last_used_at, created_at
              FROM api.machine_tokens
             WHERE project_id = %s::uuid
             ORDER BY created_at DESC
            """,
            (pid,),
        )
        tokens = [_row(r) for r in (cur.fetchall() or [])]
    return jsonify({"project": proj, "members": members, "tokens": tokens})


def mgmt_delete_project(project_ref):
    """Delete a project."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute("DELETE FROM api.projects WHERE id = %s::uuid", (pid,))
        if cur.rowcount == 0:
            return jsonify({"error": "forbidden"}), 403
        conn.commit()
    return jsonify({"ok": True, "id": pid})


def mgmt_list_project_members(project_ref):
    """List project-scoped members."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404

        bindings = rbac_sync.list_scope_bindings(cur, "project", pid)
        rbac_sync.enrich_binding_emails(bindings)
        items = []
        for b in bindings:
            if b.get("subject_kind") != "User":
                continue
            items.append(
                {
                    "user_id": str(b.get("subject_id")),
                    "email": b.get("subject_email"),
                    "role": b.get("role_short") or b.get("role_name"),
                    "role_name": b.get("role_name"),
                }
            )
    return jsonify({"items": items})


def mgmt_add_project_binding(project_ref):
    """Add project member. Body: ``{"email":"…","role":"project-read|project-write|project-admin"}``."""
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    role = (body.get("role") or "project-read").strip()
    role_names = config.RBAC_PROJECT_ROLE_NAMES
    if role not in role_names:
        role = "project-read"
    if not email:
        return jsonify({"error": "email required"}), 400
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        mid = lookup_user_id(cur, email)
        if not mid:
            return jsonify({"error": "user not found"}), 404
        cur.execute("SELECT api.can_manage_rbac('project', %s::uuid) AS ok", (pid,))
        if not (cur.fetchone() or {}).get("ok"):
            return jsonify({"error": "forbidden"}), 403

        rbac_sync.sync_user_project_binding(
            cur, user_id=mid, project_id=pid, role=role, created_by=uid
        )
        audit.log_org(
            cur,
            project_id=pid,
            action=audit.ORG_PROJECT_MEMBER_ADD,
            detail=f"{email} → {role} (rbac)",
        )
        conn.commit()
    return jsonify({"ok": True, "email": email, "role": role})


def mgmt_remove_project_binding(project_ref, member_ref):
    """Remove project member by email or id."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        mid = lookup_user_id(cur, member_ref)
        if not mid:
            return jsonify({"error": "user not found"}), 404
        cur.execute("SELECT api.can_manage_rbac('project', %s::uuid) AS ok", (pid,))
        if not (cur.fetchone() or {}).get("ok"):
            return jsonify({"error": "forbidden"}), 403

        rbac_sync.sync_user_project_binding(
            cur, user_id=mid, project_id=pid, role=None, created_by=uid
        )
        audit.log_org(
            cur,
            project_id=pid,
            action=audit.ORG_PROJECT_MEMBER_REMOVE,
            detail=member_ref,
        )
        conn.commit()
    return jsonify({"ok": True})


def mgmt_update_project_settings(project_ref):
    """Update project reveal-approval default, description, default access mode.

    Body: ``{"require_reveal_approval": bool, "description": str,
             "default_access_mode": "inherit|restricted"}`` (all optional;
    omitted fields are left unchanged). Mirrors UI ``update_project_settings``.
    """
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT api.can_admin_project(%s) AS a", (pid,))
        if not (cur.fetchone() or {}).get("a"):
            return jsonify({"error": "forbidden"}), 403

        sets, args, audit_parts = [], [], []
        if "require_reveal_approval" in body:
            req = bool(body["require_reveal_approval"])
            sets.append("require_reveal_approval = %s")
            args.append(req)
            audit_parts.append(f"require_reveal_approval={req}")
        if "description" in body:
            desc = (body["description"] or "")[:500]
            sets.append("description = %s")
            args.append(desc)
        if "default_access_mode" in body:
            mode = (body["default_access_mode"] or "inherit").strip().lower()
            if mode not in ("inherit", "restricted"):
                mode = "inherit"
            sets.append("default_access_mode = %s")
            args.append(mode)
            audit_parts.append(f"default_access_mode={mode}")
        if not sets:
            return jsonify({"error": "no update fields"}), 400
        args.append(pid)
        cur.execute(
            f"UPDATE api.projects SET {', '.join(sets)} WHERE id = %s::uuid",
            tuple(args),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT team_id FROM api.projects WHERE id = %s::uuid", (pid,))
        proj = cur.fetchone()
        audit.log_org(
            cur,
            team_id=str(proj["team_id"]) if proj and proj.get("team_id") else None,
            project_id=pid,
            action="project_settings",
            detail=", ".join(audit_parts),
        )
        conn.commit()
    return jsonify({"ok": True, "project": pid})
