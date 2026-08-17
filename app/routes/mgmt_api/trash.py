"""Management API trash routes."""

from __future__ import annotations

from flask import jsonify, request

import audit
from core import db

from .helpers import (
    _require_pat,
    _resolve_project,
    _row,
)


def mgmt_list_trash(project_ref):
    """List soft-deleted secrets in a project."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            SELECT id, key, note, kind, deleted_at, updated_at
              FROM api.secrets
             WHERE project_id = %s::uuid AND deleted_at IS NOT NULL
             ORDER BY deleted_at DESC
            """,
            (pid,),
        )
        items = [_row(r) for r in (cur.fetchall() or [])]
    return jsonify({"items": items})


def mgmt_restore_trash(project_ref, secret_id):
    """Restore a soft-deleted secret by id."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            UPDATE api.secrets SET deleted_at = NULL
             WHERE id = %s::uuid AND project_id = %s::uuid
               AND deleted_at IS NOT NULL
            RETURNING id, key
            """,
            (secret_id, pid),
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "not found or forbidden"}), 404
        audit.log_secret(
            cur,
            project_id=pid,
            action="restored",
            secret_key=row["key"],
            secret_id=row["id"],
        )
        conn.commit()
    return jsonify({"ok": True, "id": str(row["id"]), "key": row["key"]})


def mgmt_purge_trash(project_ref, secret_id):
    """Permanently purge a soft-deleted secret."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        row = None
        cur.execute(
            """
            SELECT id, key, api.can_admin_project(project_id) AS is_admin
              FROM api.secrets
             WHERE id = %s::uuid AND project_id = %s::uuid
               AND deleted_at IS NOT NULL
            """,
            (secret_id, pid),
        )
        found = cur.fetchone()
        # Purging permanently deletes a secret — require project admin, not writer.
        if found and found.get("is_admin"):
            row = found
        if not row:
            return jsonify({"error": "not found or forbidden"}), 404
        cur.execute(
            "DELETE FROM api.secrets WHERE id = %s::uuid",
            (str(row["id"]),),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "forbidden"}), 403
        audit.log_secret(
            cur,
            project_id=pid,
            action="purged",
            secret_key=row["key"],
            secret_id=row["id"],
        )
        conn.commit()
    return jsonify({"ok": True, "id": str(row["id"]), "key": row["key"]})


def mgmt_bulk_trash(project_ref):
    """Bulk restore or purge soft-deleted secrets.

    Body: ``{"action": "restore|purge", "ids": [uuid…]}``. Empty ``ids`` acts
    on all trashed secrets in the project. Returns counts.
    """
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    action = (body.get("action") or "").strip().lower()
    if action not in ("restore", "purge"):
        return jsonify({"error": "action must be restore or purge"}), 400
    ids = [str(x) for x in (body.get("ids") or []) if str(x).strip()]
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        if action == "restore":
            if ids:
                cur.execute(
                    """
                    UPDATE api.secrets SET deleted_at = NULL
                     WHERE project_id = %s::uuid AND deleted_at IS NOT NULL
                       AND id = ANY(%s::uuid[])
                    RETURNING id, key
                    """,
                    (pid, ids),
                )
            else:
                cur.execute(
                    """
                    UPDATE api.secrets SET deleted_at = NULL
                     WHERE project_id = %s::uuid AND deleted_at IS NOT NULL
                    RETURNING id, key
                    """,
                    (pid,),
                )
            rows = cur.fetchall() or []
            for r in rows:
                audit.log_secret(
                    cur,
                    project_id=pid,
                    secret_id=str(r["id"]),
                    secret_key=r["key"],
                    action="restored",
                )
        else:
            if ids:
                cur.execute(
                    """
                    SELECT id, key FROM api.secrets
                     WHERE project_id = %s::uuid AND deleted_at IS NOT NULL
                       AND api.can_admin_project(project_id)
                       AND id = ANY(%s::uuid[])
                    """,
                    (pid, ids),
                )
            else:
                cur.execute(
                    """
                    SELECT id, key FROM api.secrets
                     WHERE project_id = %s::uuid AND deleted_at IS NOT NULL
                       AND api.can_admin_project(project_id)
                    """,
                    (pid,),
                )
            rows = cur.fetchall() or []
            for r in rows:
                cur.execute(
                    "DELETE FROM api.secrets WHERE id = %s::uuid",
                    (str(r["id"]),),
                )
                audit.log_secret(
                    cur,
                    project_id=pid,
                    secret_id=str(r["id"]),
                    secret_key=r["key"],
                    action="purged",
                )
        conn.commit()
    return jsonify({"ok": True, "action": action, "count": len(rows)})
