"""ESO secret access-request routes."""

from __future__ import annotations

from flask import (
    jsonify,
    request,
)

from core import config, db, settings_svc

from .helpers import (
    _audit,
    _require_auth,
    _resolve_project_ref,
)


def eso_request_secret_access(project_ref, key):
    """Request approval to reveal a secret (PAT only).

    Body JSON optional: ``{"reason": "..."}``.

    Machine tokens are exempt from approval and should not use this.
    """
    auth, err = _require_auth()
    if err:
        return err
    kind, ident = auth
    if kind != "pat":
        return jsonify({"error": "PAT required"}), 403
    key = (key or "").strip()
    body = request.get_json(silent=True) or {}
    reason = (body.get("reason") or request.form.get("reason") or "").strip()
    if len(reason) > 500:
        reason = reason[:500]
    with db.as_user(ident) as conn, conn.cursor() as cur:
        pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=None)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            SELECT id, key FROM api.secrets
            WHERE project_id = %s AND key = %s AND deleted_at IS NULL
            """,
            (pid, key),
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT api.can_reveal_secret(%s) AS ok", (str(row["id"]),))
        if (cur.fetchone() or {}).get("ok"):
            return jsonify(
                {
                    "ok": True,
                    "status": "allowed",
                    "message": "You already have access to reveal this secret",
                    "key": row["key"],
                }
            )
        cur.execute(
            """
            SELECT id, status, created_at FROM api.secret_access_requests
            WHERE secret_id = %s AND user_id = %s AND status = 'pending'
            LIMIT 1
            """,
            (str(row["id"]), str(ident)),
        )
        existing = cur.fetchone()
        if existing:
            return jsonify(
                {
                    "ok": True,
                    "status": "pending",
                    "id": str(existing["id"]),
                    "key": row["key"],
                    "message": "Access request already pending approval",
                }
            )
        cur.execute(
            """
            INSERT INTO api.secret_access_requests
              (project_id, secret_id, user_id, reason, status)
            VALUES (%s, %s, %s, %s, 'pending')
            RETURNING id, status, created_at
            """,
            (pid, str(row["id"]), str(ident), reason),
        )
        created = cur.fetchone()
        _audit(
            cur,
            project_id=pid,
            action="access_requested",
            secret_key=row["key"],
            secret_id=row["id"],
        )
        conn.commit()
    return jsonify(
        {
            "ok": True,
            "status": "pending",
            "id": str(created["id"]),
            "key": row["key"],
            "message": "Access request submitted. You'll be notified when approved.",
        }
    ), 201


def eso_list_access_requests(project_ref):
    """List secret access requests for a project (PAT).

    Admins see all; others see their own. Query ``status=pending`` optional.
    """
    auth, err = _require_auth()
    if err:
        return err
    kind, ident = auth
    if kind != "pat":
        return jsonify({"error": "PAT required"}), 403
    status = (request.args.get("status") or "").strip().lower()
    with db.as_user(ident) as conn, conn.cursor() as cur:
        pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=None)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            "SELECT * FROM private.secret_access_request_rows(%s::uuid)",
            (pid,),
        )
        rows = cur.fetchall() or []
    items = []
    for r in rows:
        if status and (r.get("status") or "") != status:
            continue
        items.append(
            {
                "id": str(r["id"]),
                "secret_id": str(r["secret_id"]) if r.get("secret_id") else None,
                "secret_key": r.get("secret_key") or "",
                "user_id": str(r["user_id"]) if r.get("user_id") else None,
                "email": r.get("email") or "",
                "name": r.get("name") or "",
                "status": r.get("status"),
                "reason": r.get("reason") or "",
                "created_at": r.get("created_at"),
                "resolved_at": r.get("resolved_at"),
                "approved_until": r.get("approved_until"),
            }
        )
    return jsonify({"items": items})


def eso_approve_access_request(project_ref, req_id):
    """Approve a pending access request (project admin / team owner, PAT)."""
    auth, err = _require_auth()
    if err:
        return err
    kind, ident = auth
    if kind != "pat":
        return jsonify({"error": "PAT required"}), 403
    body = request.get_json(silent=True) or {}
    try:
        if body.get("minutes") is not None:
            minutes = int(body["minutes"])
        elif body.get("hours") is not None:
            minutes = int(body["hours"]) * 60
        else:
            minutes = settings_svc.reveal_access_grant_minutes()
    except (TypeError, ValueError):
        minutes = settings_svc.reveal_access_grant_minutes()
    if minutes not in config.REVEAL_ACCESS_GRANT_CHOICES:
        minutes = settings_svc.reveal_access_grant_minutes()
    with db.as_user(ident) as conn, conn.cursor() as cur:
        pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=None)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT api.can_admin_project(%s) AS a", (pid,))
        if not (cur.fetchone() or {}).get("a"):
            return jsonify({"error": "forbidden"}), 403
        cur.execute(
            """
            SELECT r.id, r.secret_id, r.status, s.key AS secret_key, r.user_id
            FROM api.secret_access_requests r
            LEFT JOIN api.secrets s ON s.id = r.secret_id
            WHERE r.id = %s::uuid AND r.project_id = %s
            """,
            (str(req_id), pid),
        )
        req = cur.fetchone()
        if not req or req["status"] != "pending":
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            UPDATE api.secret_access_requests
            SET status = 'approved',
                resolved_at = now(),
                resolved_by = %s,
                approved_until = now() + (%s || ' minutes')::interval
            WHERE id = %s AND status = 'pending'
            RETURNING approved_until
            """,
            (str(ident), str(minutes), str(req_id)),
        )
        updated = cur.fetchone()
        if not updated:
            return jsonify({"error": "not found"}), 404
        _audit(
            cur,
            project_id=pid,
            action="access_approved",
            secret_key=req.get("secret_key") or "",
            secret_id=req.get("secret_id"),
        )
        conn.commit()
    return jsonify(
        {
            "ok": True,
            "status": "approved",
            "id": str(req_id),
            "minutes": minutes,
            "approved_until": updated.get("approved_until"),
            "message": f"Approved. Requester has {minutes} minutes to reveal.",
        }
    )


def eso_deny_access_request(project_ref, req_id):
    """Deny a pending access request (project admin / team owner, PAT)."""
    auth, err = _require_auth()
    if err:
        return err
    kind, ident = auth
    if kind != "pat":
        return jsonify({"error": "PAT required"}), 403
    with db.as_user(ident) as conn, conn.cursor() as cur:
        pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=None)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT api.can_admin_project(%s) AS a", (pid,))
        if not (cur.fetchone() or {}).get("a"):
            return jsonify({"error": "forbidden"}), 403
        cur.execute(
            """
            SELECT r.id, r.secret_id, r.status, s.key AS secret_key
            FROM api.secret_access_requests r
            LEFT JOIN api.secrets s ON s.id = r.secret_id
            WHERE r.id = %s::uuid AND r.project_id = %s
            """,
            (str(req_id), pid),
        )
        req = cur.fetchone()
        if not req or req["status"] != "pending":
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            UPDATE api.secret_access_requests
            SET status = 'denied',
                resolved_at = now(),
                resolved_by = %s,
                approved_until = NULL
            WHERE id = %s AND status = 'pending'
            """,
            (str(ident), str(req_id)),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
        _audit(
            cur,
            project_id=pid,
            action="access_denied",
            secret_key=req.get("secret_key") or "",
            secret_id=req.get("secret_id"),
        )
        conn.commit()
    return jsonify({"ok": True, "status": "denied", "id": str(req_id)})
