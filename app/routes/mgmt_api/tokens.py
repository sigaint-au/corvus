"""Management API machine-token routes."""

from __future__ import annotations

import secrets
from datetime import (
    datetime,
    timedelta,
    timezone,
)

from flask import (
    jsonify,
    request,
)

from core import config, db, settings_svc
from crypto import sha256_hex

from .helpers import (
    _require_pat,
    _resolve_project,
    _row,
)


def mgmt_list_tokens(project_ref):
    """List machine tokens (prefix only; raw secret never stored)."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            SELECT id, name, token_prefix, role, expires_at, last_used_at, created_at
              FROM api.machine_tokens
             WHERE project_id = %s::uuid
             ORDER BY created_at DESC
            """,
            (pid,),
        )
        items = [_row(r) for r in (cur.fetchall() or [])]
        tids = [it["id"] for it in items if it.get("id")]
        scope_map: dict = {}
        if tids:
            try:
                cur.execute(
                    """
                    SELECT token_id, secret_key, key_pattern
                      FROM api.machine_token_scope
                     WHERE token_id = ANY(%s::uuid[])
                    """,
                    (tids,),
                )
                for sc in cur.fetchall() or []:
                    scope_map.setdefault(str(sc["token_id"]), []).append(_row(sc))
            except Exception:
                scope_map = {}
        for it in items:
            it["scope"] = scope_map.get(str(it.get("id")), [])
    return jsonify({"items": items})


def mgmt_create_token(project_ref):
    """Create machine token. Body: name, role, expires_days.

    Returns the raw ``token`` once in the JSON body.
    """
    uid, err = _require_pat()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "machine").strip() or "machine"
    role = (body.get("role") or "service-read").strip()
    if role not in config.MACHINE_TOKEN_ROLES:
        role = "service-read"
    expires_at = None
    require_expiry, max_days = settings_svc.token_expiry_policy("machine")
    days = body.get("expires_days")
    if days is None:
        if require_expiry:
            return jsonify({"error": "expires_days is required"}), 400
    else:
        try:
            days = int(days)
        except (TypeError, ValueError):
            return jsonify({"error": "expires_days must be int"}), 400
        if days < 1 or days > max_days:
            return jsonify({"error": f"expires_days must be between 1 and {max_days}"}), 400
        expires_at = datetime.now(timezone.utc) + timedelta(days=days)
    raw = "ss_" + secrets.token_urlsafe(32)
    thash = sha256_hex(raw)
    prefix = raw[:11]
    # scope: list of exact keys / globs, or newline-separated string
    scope_raw = body.get("scope") or body.get("scopes") or body.get("scope_keys") or ""
    if isinstance(scope_raw, list):
        scope_raw = "\n".join(str(x) for x in scope_raw)
    from routes.project_tokens import insert_token_scopes, parse_token_scope_lines

    scopes = parse_token_scope_lines(str(scope_raw))
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT api.can_admin_project(%s) AS w", (pid,))
        if not (cur.fetchone() or {}).get("w"):
            return jsonify({"error": "forbidden"}), 403
        cur.execute(
            """
            INSERT INTO api.machine_tokens
              (project_id, name, token_hash, token_prefix, role, expires_at)
            VALUES (%s::uuid, %s, %s, %s, %s, %s)
            RETURNING id, name, token_prefix, role, expires_at, created_at
            """,
            (pid, name, thash, prefix, role, expires_at),
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "forbidden"}), 403
        insert_token_scopes(cur, str(row["id"]), scopes)
        conn.commit()
    out = _row(row) or {}
    out["ok"] = True
    out["token"] = raw  # shown once
    out["scope"] = [
        {"secret_key": v} if k == "key" else {"key_pattern": v} for k, v in scopes
    ]
    return jsonify(out), 201


def mgmt_delete_token(project_ref, token_id):
    """Delete a machine token by id."""
    uid, err = _require_pat()
    if err:
        return err
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT api.can_admin_project(%s) AS w", (pid,))
        if not (cur.fetchone() or {}).get("w"):
            return jsonify({"error": "forbidden"}), 403
        cur.execute(
            """
            DELETE FROM api.machine_tokens
             WHERE id = %s::uuid AND project_id = %s::uuid
            """,
            (token_id, pid),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "not found or forbidden"}), 404
        conn.commit()
    return jsonify({"ok": True, "id": token_id})
