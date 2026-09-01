"""Management API folder routes (PAT only, RLS-gated)."""

from __future__ import annotations

from flask import jsonify, request

from core import db
from secret_svc.folders import (
    delete_empty_folder,
    materialize_folder_path,
    parse_secret_path,
)

from .helpers import (
    _require_pat,
    _resolve_project,
    _row,
)


def mgmt_list_folders(project_ref):
    """List folders for a project."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            SELECT id, parent_id, name, path, access_mode, created_at, updated_at
              FROM api.folders
             WHERE project_id = %s::uuid
             ORDER BY path
            """,
            (pid,),
        )
        items = [_row(r) for r in (cur.fetchall() or [])]
    return jsonify({"items": items})


def mgmt_create_folder(project_ref):
    """Create a folder. Body: ``{"path": "ops/prod"}``."""
    uid, err = _require_pat()
    if err:
        return err
    body = (request.get_json(silent=True) or {})
    path = (body.get("path") or "").strip()
    if not path:
        return jsonify({"error": "path required"}), 400
    try:
        segments, _ = parse_secret_path(path)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not segments:
        return jsonify({"error": "path must have at least one segment"}), 400
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        folder_id = materialize_folder_path(cur, pid, segments)
        if folder_id:
            cur.execute(
                "SELECT id, parent_id, name, path, access_mode, created_at, updated_at"
                "  FROM api.folders WHERE id = %s::uuid",
                (str(folder_id),),
            )
            row = cur.fetchone()
            conn.commit()
            if row:
                return jsonify(_row(row)), 201
        conn.commit()
    return jsonify({"id": str(folder_id) if folder_id else None}), 201


def mgmt_delete_folder(project_ref, folder_id):
    """Delete an empty folder and its empty descendants."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        try:
            deleted = delete_empty_folder(cur, pid, folder_id)
        except ValueError as e:
            return jsonify({"error": str(e)}), 409
        conn.commit()
    if deleted:
        return jsonify({"ok": True, "id": str(deleted)})
    return jsonify({"error": "not found"}), 404
