"""Shared management-API helpers (auth, resolution, rows)."""

from __future__ import annotations

from flask import jsonify
import authz
import pats
from lib.auth_tokens import classify_token
from lib.serialize import row_to_dict
from lib.validate import is_uuid
from routes.eso import bearer_raw


def _require_pat():
    """Resolve a PAT (or session) user id for management routes.

    Returns:
        Tuple ``(user_id, None)`` or ``(None, (jsonify, status))``.
    """
    raw = bearer_raw()
    if raw and raw.startswith(pats.PREFIX):
        kind, uid = classify_token(raw)
        if kind != "pat" or not uid:
            return None, (jsonify({"error": "unauthorized"}), 401)
        return uid, None
    # allow session for completeness
    from flask import session

    if session.get("user_id"):
        return str(session["user_id"]), None
    return None, (jsonify({"error": "unauthorized — use a pat_… token"}), 401)


def _require_global_admin(uid: str):
    """Return error response if uid is not a global admin, else None."""
    if not authz.is_global_admin(uid):
        return jsonify({"error": "global admin required"}), 403
    return None


def _row(r: dict | None) -> dict | None:
    if not r:
        return None
    return row_to_dict(r)


def _resolve_team(cur, ref: str) -> str | None:
    """Resolve team UUID from id or unique name under RLS."""
    ref = (ref or "").strip()
    if not ref:
        return None
    if is_uuid(ref):
        cur.execute("SELECT id FROM api.teams WHERE id = %s::uuid", (ref,))
        r = cur.fetchone()
        return str(r["id"]) if r else None
    cur.execute(
        "SELECT id FROM api.teams WHERE name = %s ORDER BY created_at LIMIT 2",
        (ref,),
    )
    rows = cur.fetchall() or []
    return str(rows[0]["id"]) if len(rows) == 1 else None


def _resolve_project(cur, ref: str) -> str | None:
    """Resolve project UUID from id or unique name under RLS."""
    ref = (ref or "").strip()
    if not ref:
        return None
    if is_uuid(ref):
        cur.execute("SELECT id FROM api.projects WHERE id = %s::uuid", (ref,))
        r = cur.fetchone()
        return str(r["id"]) if r else None
    cur.execute(
        "SELECT id FROM api.projects WHERE name = %s ORDER BY created_at LIMIT 2",
        (ref,),
    )
    rows = cur.fetchall() or []
    return str(rows[0]["id"]) if len(rows) == 1 else None
