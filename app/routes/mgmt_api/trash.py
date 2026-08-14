"""Management API trash routes."""

from __future__ import annotations

from flask import jsonify
import audit
import db
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
        cur.execute(
            """
            SELECT id, key FROM api.secrets
             WHERE id = %s::uuid AND project_id = %s::uuid
               AND deleted_at IS NOT NULL
            """,
            (secret_id, pid),
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
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
