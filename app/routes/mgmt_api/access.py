"""Management API secret-access settings and scope bindings (PAT only)."""

from __future__ import annotations

from flask import jsonify, request

import audit
from core import db
from lib.users import lookup_user_id
from secret_svc.secret_ops import _parse_access_mode, _parse_requires_approval

from .helpers import _require_pat, _resolve_project


def _resolve_secret(cur, pid, key):
    cur.execute(
        """
        SELECT id, key FROM api.secrets
         WHERE project_id = %s::uuid AND key = %s AND deleted_at IS NULL
        """,
        (pid, key),
    )
    row = cur.fetchone()
    return (str(row["id"]), row["key"]) if row else (None, None)


def _is_project_admin(cur, pid):
    cur.execute("SELECT api.can_admin_project(%s) AS a", (pid,))
    return bool((cur.fetchone() or {}).get("a"))


def mgmt_update_secret_access(project_ref, key):
    """Set per-secret access_mode and reveal-approval override (project admin).

    Body: ``{"access_mode": "inherit|restricted",
             "requires_approval": bool|null}``. Mirrors UI ``update_secret_access``.
    """
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    mode = _parse_access_mode(body)
    req_appr = _parse_requires_approval(body)
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        if not _is_project_admin(cur, pid):
            return jsonify({"error": "forbidden"}), 403
        sid, skey = _resolve_secret(cur, pid, key)
        if not sid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            UPDATE api.secrets
              SET access_mode = %s, requires_approval = %s
             WHERE id = %s::uuid AND project_id = %s::uuid AND deleted_at IS NULL
            """,
            (mode, req_appr, sid, pid),
        )
        audit.log_secret(
            cur,
            project_id=pid,
            secret_id=sid,
            secret_key=skey,
            action="updated",
        )
        conn.commit()
    return jsonify(
        {"ok": True, "key": key, "access_mode": mode, "requires_approval": req_appr}
    )


def mgmt_add_secret_binding(project_ref, key):
    """Bind a User/Group/ServiceAccount to a secret role (project admin).

    Body: ``{"subject_kind","subject_id","role": "secret-reveal"|…}``.
    User → ``subject_id`` is email; Group → group UUID; ServiceAccount → token UUID.
    Replaces any existing secret-scope binding for the subject; sets the secret
    to ``restricted`` mode. Mirrors UI ``add_secret_access_binding``.
    """
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    subject_kind = (body.get("subject_kind") or "User").strip()
    if subject_kind not in ("User", "Group", "ServiceAccount"):
        subject_kind = "User"
    subject = (body.get("subject_id") or body.get("subject") or "").strip()
    role_name = (body.get("role") or body.get("role_name") or "secret-reveal").strip()
    if not subject:
        return jsonify({"error": "subject_id is required"}), 400
    if subject_kind == "User":
        subject = subject.lower()

    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        if not _is_project_admin(cur, pid):
            return jsonify({"error": "forbidden"}), 403
        sid, _skey = _resolve_secret(cur, pid, key)
        if not sid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """SELECT s.id, s.key, s.access_mode, p.team_id
                 FROM api.secrets s JOIN api.projects p ON p.id = s.project_id
                WHERE s.id = %s::uuid AND s.project_id = %s::uuid
                  AND s.deleted_at IS NULL""",
            (sid, pid),
        )
        sec = cur.fetchone()
        cur.execute("SELECT id FROM rbac.roles WHERE name = %s", (role_name,))
        role = cur.fetchone()
        if not role:
            return jsonify({"error": f"unknown role {role_name!r}"}), 400

        try:
            external_user = False
            if subject_kind == "User":
                subject_id = lookup_user_id(cur, subject)
                if not subject_id:
                    return jsonify(
                        {"error": "user not found — they must register first"}
                    ), 400
                who = subject
                cur.execute(
                    """SELECT api.can('list','secrets','team',%s::uuid,%s::uuid) AS m""",
                    (str(sec["team_id"]), subject_id),
                )
                external_user = not bool((cur.fetchone() or {}).get("m"))
                if external_user:
                    cur.execute(
                        "SELECT api.secret_requires_approval(%s::uuid) AS a",
                        (str(sec["id"]),),
                    )
                    if bool((cur.fetchone() or {}).get("a")):
                        return (
                            jsonify(
                                {
                                    "error": "cannot share an approval-required "
                                    "secret with a user outside the team"
                                }
                            ),
                            400,
                        )
            elif subject_kind == "Group":
                cur.execute(
                    """
                    SELECT id, name FROM api.groups
                     WHERE id = %s::uuid AND team_id = %s::uuid
                    """,
                    (subject, str(sec["team_id"])),
                )
                g = cur.fetchone()
                if not g:
                    return jsonify({"error": "group not found on this team"}), 404
                subject_id, who = str(g["id"]), f"group {g['name']}"
            else:
                cur.execute(
                    """
                    SELECT id FROM api.machine_tokens
                     WHERE id = %s::uuid AND project_id = %s::uuid
                    """,
                    (str(subject), pid),
                )
                sa = cur.fetchone()
                if not sa:
                    return jsonify({"error": "machine account not found"}), 404
                subject_id, who = str(sa["id"]), f"machine account {subject[:8]}"

            # Replace any existing secret-scope binding for this subject
            cur.execute(
                """
                DELETE FROM rbac.bindings
                 WHERE scope_kind = 'secret' AND scope_id = %s::uuid
                   AND subject_kind = %s AND subject_id = %s::uuid
                """,
                (str(sec["id"]), subject_kind, subject_id),
            )
            cur.execute(
                """
                INSERT INTO rbac.bindings
                  (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                VALUES (%s::uuid, %s, %s::uuid, 'secret', %s::uuid, %s::uuid)
                """,
                (str(role["id"]), subject_kind, subject_id, str(sec["id"]), uid),
            )
            if (sec.get("access_mode") or "inherit") != "restricted":
                cur.execute(
                    "UPDATE api.secrets SET access_mode = 'restricted' WHERE id = %s::uuid",
                    (str(sec["id"]),),
                )
            audit.log_secret(
                cur,
                project_id=pid,
                secret_id=sec["id"],
                secret_key=sec["key"],
                action="updated",
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return jsonify({"ok": True, "key": key, "subject": who, "role": role_name})


def mgmt_delete_secret_binding(project_ref, key, binding_id):
    """Remove a secret-scope role binding (project admin)."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        if not _is_project_admin(cur, pid):
            return jsonify({"error": "forbidden"}), 403
        sid, skey = _resolve_secret(cur, pid, key)
        if not sid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            DELETE FROM rbac.bindings b
             USING api.secrets s
             WHERE b.id = %s::uuid
               AND b.scope_kind = 'secret' AND b.scope_id = s.id
               AND s.id = %s::uuid AND s.project_id = %s::uuid
            """,
            (binding_id, sid, pid),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "binding not found"}), 404
        audit.log_secret(
            cur,
            project_id=pid,
            secret_id=sid,
            secret_key=skey,
            action="updated",
        )
        conn.commit()
    return jsonify({"ok": True, "key": key, "binding_id": binding_id})
