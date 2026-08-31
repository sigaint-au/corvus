"""Management API folder routes (PAT/session only)."""

from __future__ import annotations

from flask import jsonify, request
from werkzeug.exceptions import HTTPException

from core import db
from lib.validate import is_uuid
from secret_svc import folder_ops

from .helpers import (
    _require_pat,
    _resolve_project,
)


def _resolve_folder(cur, pid, ref):
    """Resolve folder by id (or path under the project)."""
    ref = (ref or "").strip()
    if not ref:
        return None
    if is_uuid(ref):
        cur.execute(
            "SELECT id, path FROM api.folders WHERE id = %s::uuid AND project_id = %s::uuid",
            (ref, str(pid)),
        )
        row = cur.fetchone()
        return row if row else None
    cur.execute(
        "SELECT id, path FROM api.folders WHERE project_id = %s::uuid AND path = %s",
        (str(pid), ref.strip("/")),
    )
    return cur.fetchone()


def _can_manage_folder(cur, fid):
    cur.execute("SELECT api.can_manage_rbac('folder', %s) AS ok", (str(fid),))
    return bool((cur.fetchone() or {}).get("ok"))


def mgmt_list_folders(project_ref):
    """List direct children of a folder (or project root when parent omitted)."""
    uid, err = _require_pat()
    if err:
        return err
    parent = (request.args.get("parent") or "").strip()
    if parent == "-":
        parent = ""
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        parent_id = None
        if parent and is_uuid(parent):
            folder = _resolve_folder(cur, pid, parent)
            if not folder:
                return jsonify({"error": "folder not found"}), 404
            parent_id = str(folder["id"])
        elif parent:
            parent_id = parent
            if _resolve_folder(cur, pid, parent) is None:
                return jsonify({"error": "folder not found"}), 404
        _rows, _pager, folders, secrets = folder_ops.list_children(
            cur, pid, parent_id, 1, ""
        )
        return jsonify(
            {
                "folders": [
                    {"id": f["id"], "name": f["name"], "path": f["path"],
                     "parent_id": f["parent_id"]}
                    for f in folders
                ],
                "secrets": [
                    {"key": s["key"], "id": s["id"]} for s in secrets
                ],
            }
        )


def mgmt_create_folder(project_ref):
    """Create a folder (and ancestors) for a project.

    Body: ``{"path": "prod/db"}``."""
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    path = (body.get("path") or "").strip()
    if not path:
        return jsonify({"error": "path is required"}), 400
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        try:
            fid = folder_ops.create_folder(cur, pid, path)
            conn.commit()
        except ValueError as exc:
            conn.rollback()
            return jsonify({"error": str(exc)}), 400
        except HTTPException as exc:
            conn.rollback()
            return jsonify({"error": exc.description}), exc.code
        except Exception as exc:
            conn.rollback()
            if "folder path" in str(exc):
                return jsonify({"error": str(exc)}), 400
            raise
    return jsonify({"ok": True, "folder_id": fid, "path": path})


def mgmt_move_folder(project_ref, folder_ref):
    """Move/rename a folder to a new path.

    Body: ``{"path": "staging/db"}``."""
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    new_path = (body.get("path") or "").strip()
    if not new_path:
        return jsonify({"error": "path is required"}), 400
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        folder = _resolve_folder(cur, pid, folder_ref)
        if not folder:
            return jsonify({"error": "folder not found"}), 404
        try:
            folder_ops.move_folder(cur, str(folder["id"]), new_path, project_id=pid)
            conn.commit()
        except ValueError as exc:
            conn.rollback()
            return jsonify({"error": str(exc)}), 400
        except HTTPException as exc:
            conn.rollback()
            return jsonify({"error": exc.description}), exc.code
    return jsonify({"ok": True, "folder_id": str(folder["id"]), "path": new_path})


def mgmt_delete_folder(project_ref, folder_ref):
    """Delete a folder. Pass ``?recursive=1`` to trash its descendant secrets first."""
    uid, err = _require_pat()
    if err:
        return err
    recursive = request.args.get("recursive") == "1"
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        folder = _resolve_folder(cur, pid, folder_ref)
        if not folder:
            return jsonify({"error": "folder not found"}), 404
        try:
            folder_ops.delete_folder(
                cur, str(folder["id"]), project_id=pid, recursive=recursive
            )
            conn.commit()
        except HTTPException as exc:
            conn.rollback()
            return jsonify({"error": exc.description}), exc.code
        except Exception as exc:
            conn.rollback()
            if "not empty" in str(exc):
                return jsonify({"error": str(exc)}), 409
            raise
    return jsonify({"ok": True, "folder_id": str(folder["id"])})
