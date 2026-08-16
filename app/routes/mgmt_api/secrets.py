"""Management API secret metadata routes (PAT only)."""

from __future__ import annotations

import re

from flask import (
    jsonify,
    request,
)

import audit
from core import db

from .helpers import (
    _require_pat,
    _resolve_project,
)

_META_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_META_VALUE_MAX = 2000


def _resolve_secret(cur, pid, key):
    """Return secret id for a live secret in a project, else None."""
    cur.execute(
        """
        SELECT id FROM api.secrets
         WHERE project_id = %s::uuid AND key = %s AND deleted_at IS NULL
        """,
        (pid, key),
    )
    row = cur.fetchone()
    return str(row["id"]) if row else None


def _can_write(cur, secret_id):
    cur.execute(
        "SELECT api.can_access_secret(%s, 'write') AS w", (secret_id,)
    )
    return bool((cur.fetchone() or {}).get("w"))


def mgmt_upsert_secret_meta(project_ref, key):
    """Add or update one custom metadata field (writers).

    Body: ``{"key": str, "value": str}``. Mirrors UI ``upsert_secret_meta``.
    """
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    meta_key = (body.get("key") or "").strip()
    if not _META_KEY_RE.match(meta_key):
        return (
            jsonify(
                {
                    "error": "metadata key must start with a letter/digit and use "
                    "only A-Z a-z 0-9 . _ - (max 64)"
                }
            ),
            400,
        )
    value = (body.get("value") or "")[:_META_VALUE_MAX]
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        secret_id = _resolve_secret(cur, pid, key)
        if not secret_id:
            return jsonify({"error": "not found"}), 404
        if not _can_write(cur, secret_id):
            return jsonify({"error": "forbidden"}), 403
        try:
            cur.execute(
                """
                INSERT INTO api.secret_meta (secret_id, key, value, updated_at)
                VALUES (%s, %s, %s, now())
                ON CONFLICT (secret_id, key) DO UPDATE
                  SET value = EXCLUDED.value, updated_at = now()
                """,
                (secret_id, meta_key, value),
            )
            audit.log_secret(
                cur,
                project_id=pid,
                secret_id=secret_id,
                secret_key=key,
                action="updated",
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return jsonify({"ok": True, "key": key, "meta_key": meta_key, "value": value})


def mgmt_delete_secret_meta(project_ref, key, meta_key):
    """Remove a custom metadata field (writers)."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        secret_id = _resolve_secret(cur, pid, key)
        if not secret_id:
            return jsonify({"error": "not found"}), 404
        if not _can_write(cur, secret_id):
            return jsonify({"error": "forbidden"}), 403
        cur.execute(
            """
            SELECT 1 FROM api.secret_meta
            WHERE secret_id = %s AND key = %s
            """,
            (secret_id, meta_key),
        )
        if cur.fetchone() is None:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            "DELETE FROM api.secret_meta WHERE secret_id = %s AND key = %s",
            (secret_id, meta_key),
        )
        audit.log_secret(
            cur,
            project_id=pid,
            secret_id=secret_id,
            secret_key=key,
            action="updated",
        )
        conn.commit()
    return jsonify({"ok": True, "key": key, "meta_key": meta_key})
