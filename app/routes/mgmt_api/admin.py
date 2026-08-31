"""Management API admin user/audit routes."""

from __future__ import annotations

from uuid import UUID

from flask import (
    jsonify,
    request,
)

import audit
from auth import admin_ops
from core import db

from .helpers import (
    _require_global_admin,
    _require_pat,
    _row,
)


def mgmt_admin_users():
    """List users (global admin). Optional ``q`` filter."""
    uid, err = _require_pat()
    if err:
        return err
    gerr = _require_global_admin(uid)
    if gerr:
        return gerr
    q = (request.args.get("q") or "").strip()
    like = f"%{q}%" if q else None
    with db.connect_admin() as conn, conn.cursor() as cur:
        if like:
            cur.execute(
                """
                SELECT id, email, name, is_global_admin, auth_source,
                       disabled_at, created_at, totp_enabled_at
                  FROM private.users
                 WHERE email ILIKE %s OR name ILIKE %s
                 ORDER BY email
                 LIMIT 200
                """,
                (like, like),
            )
        else:
            cur.execute(
                """
                SELECT id, email, name, is_global_admin, auth_source,
                       disabled_at, created_at, totp_enabled_at
                  FROM private.users
                 ORDER BY email
                 LIMIT 500
                """
            )
        items = [_row(r) for r in (cur.fetchall() or [])]
    return jsonify({"items": items})


def mgmt_admin_audit():
    """List org or secret audit (global admin).

    Query: ``source=org|secret|access``, ``q``, ``actor``, ``since``, ``until``.
    """
    uid, err = _require_pat()
    if err:
        return err
    gerr = _require_global_admin(uid)
    if gerr:
        return gerr
    source = (request.args.get("source") or "org").strip().lower()
    q = (request.args.get("q") or "").strip()
    actor = (request.args.get("actor") or "").strip()
    since = (request.args.get("since") or "").strip()
    until = (request.args.get("until") or "").strip()
    limit = min(500, max(1, int(request.args.get("limit") or 100)))
    with db.connect_admin() as conn, conn.cursor() as cur:
        if source == "access":
            items = [_row(r) for r in audit.access_review_rows(cur)]
        elif source == "secret":
            # global secret audit — recent across projects
            extra = []
            params: list = []
            if q:
                extra.append(
                    "(a.secret_key ILIKE %s OR a.action ILIKE %s OR a.actor_email ILIKE %s)"
                )
                params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
            if actor:
                extra.append("a.actor_email ILIKE %s")
                params.append(f"%{actor}%")
            where = ("WHERE " + " AND ".join(extra)) if extra else ""
            cur.execute(
                f"""
                SELECT a.id, a.project_id, a.secret_key, a.action,
                       a.actor_email, a.created_at
                  FROM api.secret_audit a
                {where}
                 ORDER BY a.created_at DESC
                 LIMIT %s
                """,
                (*params, limit),
            )
            items = [_row(r) for r in (cur.fetchall() or [])]
        else:
            items = [
                _row(r)
                for r in audit.list_org_audit(
                    cur,
                    q=q,
                    actor=actor,
                    since=since,
                    until=until,
                    limit=limit,
                )
            ]
    return jsonify({"source": source, "items": items})


def _admin_auth():
    """Authenticate a PAT + require global admin. Returns (uid, None) or (None, resp)."""
    uid, err = _require_pat()
    if err:
        return None, err
    gerr = _require_global_admin(uid)
    if gerr:
        return None, gerr
    return uid, None


def mgmt_admin_disable_user(user_id: UUID):
    """POST /api/v1/manage/admin/users/<uuid>/disable"""
    uid, err = _admin_auth()
    if err:
        return err
    ok, msg = admin_ops.disable_user(str(user_id), uid)
    if ok:
        return jsonify({"ok": True})
    return jsonify({"error": msg}), 400


def mgmt_admin_enable_user(user_id: UUID):
    """POST /api/v1/manage/admin/users/<uuid>/enable"""
    uid, err = _admin_auth()
    if err:
        return err
    ok, msg = admin_ops.enable_user(str(user_id))
    if ok:
        return jsonify({"ok": True})
    return jsonify({"error": msg}), 400 if "not found" in msg else 400


def mgmt_admin_promote_user(user_id: UUID):
    """POST /api/v1/manage/admin/users/<uuid>/promote

    Body may include ``email`` as a convenience alias.
    """
    uid, err = _admin_auth()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    if not email:
        return jsonify({"error": "email required"}), 400
    ok, msg = admin_ops.promote_user(email, uid)
    if ok:
        return jsonify({"ok": True})
    if "No user" in msg:
        return jsonify({"error": msg}), 404
    return jsonify({"error": msg}), 400


def mgmt_admin_demote_user(user_id: UUID):
    """POST /api/v1/manage/admin/users/<uuid>/demote"""
    uid, err = _admin_auth()
    if err:
        return err
    ok, msg = admin_ops.demote_user(str(user_id), uid)
    if ok:
        return jsonify({"ok": True})
    return jsonify({"error": msg}), 400


def mgmt_admin_reset_password(user_id: UUID):
    """POST /api/v1/manage/admin/users/<uuid>/reset-password"""
    uid, err = _admin_auth()
    if err:
        return err
    token, err_msg = admin_ops.reset_user_password(str(user_id))
    if not token:
        return jsonify({"error": err_msg}), 400
    from flask import url_for

    link = url_for("reset_password", token=token, _external=True)
    return jsonify({"ok": True, "reset_link": link})


def mgmt_admin_reset_2fa(user_id: UUID):
    """POST /api/v1/manage/admin/users/<uuid>/reset-2fa"""
    uid, err = _admin_auth()
    if err:
        return err
    ok, msg = admin_ops.reset_user_2fa(str(user_id))
    if ok:
        return jsonify({"ok": True})
    return jsonify({"error": msg}), 400
