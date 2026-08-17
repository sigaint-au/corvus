"""Management API secret-history and audit routes."""

from __future__ import annotations

from flask import (
    jsonify,
    request,
)

import audit
from core import db

from .helpers import (
    _require_pat,
    _resolve_project,
    _row,
)


def mgmt_secret_history(project_ref, key):
    """List archived versions for a secret (metadata only)."""
    uid, err = _require_pat()
    if err:
        return err
    key = (key or "").strip()
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            SELECT s.id AS secret_id FROM api.secrets s
             WHERE s.project_id = %s::uuid AND s.key = %s
               AND s.deleted_at IS NULL
            """,
            (pid, key),
        )
        srow = cur.fetchone()
        if not srow:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            SELECT id, note, created_at
              FROM api.secret_versions
             WHERE secret_id = %s::uuid
             ORDER BY created_at DESC
             LIMIT 50
            """,
            (str(srow["secret_id"]),),
        )
        items = [_row(r) for r in (cur.fetchall() or [])]
    return jsonify({"key": key, "items": items})


def mgmt_project_audit(project_ref):
    """List secret audit for a project (member access)."""
    uid, err = _require_pat()
    if err:
        return err
    q = (request.args.get("q") or "").strip()
    actor = (request.args.get("actor") or "").strip()
    action = (request.args.get("action") or "").strip()
    since = (request.args.get("since") or "").strip()
    until = (request.args.get("until") or "").strip()
    limit = min(200, max(1, int(request.args.get("limit") or 50)))
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        rows = audit.list_for_project(
            cur,
            pid,
            limit=limit,
            q=q,
            actor=actor,
            action=action,
            since=since,
            until=until,
        )
        items = [_row(r) for r in rows]
    return jsonify({"items": items})
