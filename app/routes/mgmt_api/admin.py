"""Management API admin user/audit routes."""

from __future__ import annotations

from flask import (
    jsonify,
    request,
)

import audit
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
