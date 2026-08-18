"""ESO secret get and list routes."""

from __future__ import annotations

from flask import jsonify

import crypto
from core import db
from lib.validate import is_uuid
from secret_svc.secret_ops import fetch_project_reveal_enc_rows, fetch_secret_enc

from .helpers import (
    _audit,
    _machine_actor,
    _meta_item,
    _meta_list_query,
    _require_auth,
    _resolve_project_ref,
)


def eso_get_secret(project_ref, key):
    """Fetch a single secret (value + metadata) for ESO or CLI.

    Successful plaintext returns are audited as ``revealed`` (same as UI).

    Args:
        project_ref: Project UUID (machine) or UUID/name (PAT).
        key: Secret key path within the project.

    Returns:
        flask.Response: JSON with ``value``, ``key``, ``id``, ``note``,
            ``kind``, ``expires_at``, ``created_at``, ``updated_at``;
            401 unauthorized or 404 not found on failure.

    Example:
        GET /eso/v1/projects/<project_ref>/secrets/<key>
        Authorization: Bearer ss_… | pat_…
    """
    auth, err = _require_auth()
    if err:
        return err
    kind, ident = auth
    key = (key or "").strip()

    if kind == "machine":
        thash = ident
        if not is_uuid((project_ref or "").strip()):
            return jsonify({"error": "unauthorized"}), 401
        with db.connect() as conn, conn.cursor() as cur:
            pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=thash)
            if not pid:
                return jsonify({"error": "unauthorized"}), 401
            # Defense in depth: reject service-read tokens at the app layer too.
            cur.execute(
                "SELECT private.machine_role(%s::uuid, %s) AS role",
                (pid, thash),
            )
            mrole = (cur.fetchone() or {}).get("role")
            if mrole == "service-read":
                return jsonify({"error": "token does not have reveal access"}), 403
            cur.execute(
                "SELECT * FROM private.machine_get_row(%s::uuid, %s, %s)",
                (pid, thash, key),
            )
            row = cur.fetchone()
            if row and row.get("value_enc"):
                plaintext = crypto.decrypt_for_project(
                    pid, row["value_enc"], row.get("crypto_provider") or "master"
                )
                actor = _machine_actor(cur, pid, thash)
                _audit(
                    cur,
                    project_id=pid,
                    action="revealed",
                    secret_key=row.get("key") or key,
                    secret_id=row.get("id"),
                    actor_email=actor,
                )
                conn.commit()
                return jsonify(_meta_item(row, value=plaintext))
        return jsonify({"error": "not found"}), 404

    with db.as_user(ident) as conn, conn.cursor() as cur:
        pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=None)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute(
            """
            SELECT id, key, note, kind, expires_at,
                   rotation_interval_days, rotation_owner, rotation_next_at, rotated_at,
                   created_at, updated_at, last_accessed_at, crypto_provider
              FROM api.secrets
             WHERE project_id = %s AND key = %s AND deleted_at IS NULL
            """,
            (pid, key),
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        row = dict(row)
        # PAT human path: per-secret ACL then reveal-approval (machine tokens exempt)
        cur.execute(
            "SELECT api.can_access_secret(%s, 'reveal') AS ok",
            (str(row["id"]),),
        )
        if not (cur.fetchone() or {}).get("ok"):
            return (
                jsonify(
                    {
                        "error": "forbidden",
                        "message": ("You do not have permission to reveal this secret"),
                        "key": row["key"],
                    }
                ),
                403,
            )
        cur.execute("SELECT api.can_reveal_secret(%s) AS ok", (str(row["id"]),))
        if not (cur.fetchone() or {}).get("ok"):
            cur.execute(
                """
                SELECT status FROM api.secret_access_requests
                WHERE secret_id = %s AND user_id = %s AND status = 'pending'
                LIMIT 1
                """,
                (str(row["id"]), str(ident)),
            )
            pending = cur.fetchone()
            return (
                jsonify(
                    {
                        "error": "approval_required",
                        "message": (
                            "Access request pending approval"
                            if pending
                            else "Reveal requires approval; request access first"
                        ),
                        "key": row["key"],
                        "pending": bool(pending),
                    }
                ),
                403,
            )
        try:
            cur.execute(
                "SELECT * FROM private.secret_meta_rows(%s::uuid)",
                (str(row["id"]),),
            )
            row["metadata"] = {m["key"]: m["value"] for m in (cur.fetchall() or [])}
        except Exception:
            row["metadata"] = {}
        try:
            cur.execute(
                "SELECT private.touch_secret_access(%s::uuid)",
                (str(row["id"]),),
            )
        except Exception:
            pass
        enc = fetch_secret_enc(cur, row["id"])
        if not enc:
            return jsonify({"error": "forbidden"}), 403
        value = crypto.decrypt_for_project(
            pid, enc["value_enc"], enc.get("crypto_provider") or "master"
        )
        _audit(
            cur,
            project_id=pid,
            action="revealed",
            secret_key=row["key"],
            secret_id=row["id"],
        )
        conn.commit()
    return jsonify(_meta_item(row, value=value))


def eso_list_secrets(project_ref):
    """List project secrets for ESO bulk sync or CLI metadata listing.

    Default (ESO-compatible): ``{"secrets": {key: value, ...}}`` — bulk
    plaintext is audited as ``exported``.

    CLI mode — pass ``meta=1`` (or ``format=meta`` / ``include_values=0``):
    ``{"items": [...]}`` without decrypting values.

    Args:
        project_ref: Project UUID (machine) or UUID/name (PAT).

    Returns:
        flask.Response: JSON list/map on success; 401 if token invalid.

    Example:
        GET /eso/v1/projects/<id>/secrets?meta=1&q=db
        Authorization: Bearer ss_… | pat_…
    """
    auth, err = _require_auth()
    if err:
        return err
    kind, ident = auth
    meta, q = _meta_list_query()

    if kind == "machine":
        thash = ident
        with db.connect() as conn, conn.cursor() as cur:
            pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=thash)
            if not pid:
                return jsonify({"error": "unauthorized"}), 401
            actor = _machine_actor(cur, pid, thash)
            if meta:
                cur.execute(
                    "SELECT * FROM private.machine_list_meta(%s::uuid, %s, %s)",
                    (pid, thash, q),
                )
                rows = cur.fetchall() or []
                detail = f"machine/meta n={len(rows)}"
                if q:
                    detail += f" q={q[:80]}"
                _audit(
                    cur,
                    project_id=pid,
                    action="exported",
                    secret_key=detail,
                    actor_email=actor,
                )
                conn.commit()
                return jsonify({"items": [_meta_item(r) for r in rows]})
            # Defense in depth: reject service-read for bulk value listing.
            cur.execute(
                "SELECT private.machine_role(%s::uuid, %s) AS role",
                (pid, thash),
            )
            mrole = (cur.fetchone() or {}).get("role")
            if mrole == "service-read":
                return jsonify({"error": "token does not have reveal access"}), 403
            cur.execute(
                "SELECT * FROM private.machine_list_enc(%s::uuid, %s)",
                (pid, thash),
            )
            rows = cur.fetchall() or []
            data = {
                r["key"]: crypto.decrypt_for_project(
                    pid, r["value_enc"], r.get("crypto_provider") or "master"
                )
                for r in rows
            }
            _audit(
                cur,
                project_id=pid,
                action="exported",
                secret_key=f"machine/values n={len(rows)}",
                actor_email=actor,
            )
            conn.commit()
        return jsonify({"secrets": data})

    with db.as_user(ident) as conn, conn.cursor() as cur:
        pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=None)
        if not pid:
            return jsonify({"error": "not found"}), 404
        if meta:
            where = "s.project_id = %s AND s.deleted_at IS NULL"
            params: list = [pid]
            if q:
                like = f"%{q}%"
                where += """
                  AND (
                    s.key ILIKE %s OR s.note ILIKE %s
                    OR EXISTS (
                      SELECT 1 FROM api.secret_meta m
                      WHERE m.secret_id = s.id
                        AND (m.key ILIKE %s OR m.value ILIKE %s)
                    )
                  )
                """
                params.extend([like, like, like, like])
            cur.execute(
                f"""
                SELECT s.id, s.key, s.note, s.kind, s.expires_at,
                       s.rotation_interval_days, s.rotation_owner, s.rotation_next_at, s.rotated_at,
                       s.created_at, s.updated_at, s.last_accessed_at,
                       COALESCE(
                         (
                           SELECT jsonb_object_agg(m.key, m.value)
                           FROM api.secret_meta m
                           WHERE m.secret_id = s.id
                         ),
                         '{{}}'::jsonb
                       ) AS metadata
                  FROM api.secrets s
                 WHERE {where}
                 ORDER BY s.key
                """,
                params,
            )
            rows = cur.fetchall() or []
            items = []
            for r in rows:
                r = dict(r)
                md = r.get("metadata")
                if isinstance(md, str):
                    import json as _json

                    try:
                        r["metadata"] = _json.loads(md)
                    except Exception:
                        r["metadata"] = {}
                items.append(_meta_item(r))
            detail = f"cli/meta n={len(rows)}"
            if q:
                detail += f" q={q[:80]}"
            _audit(cur, project_id=pid, action="exported", secret_key=detail)
            conn.commit()
            return jsonify({"items": items})
        # PAT bulk values: only secrets the caller may reveal (ACL + approval)
        rows = fetch_project_reveal_enc_rows(cur, pid)
        data = {}
        for r in rows:
            try:
                data[r["key"]] = crypto.decrypt_for_project(
                    pid, r["value_enc"], r.get("crypto_provider") or "master"
                )
            except Exception:
                data[r["key"]] = ""
        _audit(
            cur,
            project_id=pid,
            action="exported",
            secret_key=f"cli/values n={len(rows)}",
        )
        conn.commit()
    return jsonify({"secrets": data})
