"""ESO secret upsert/put/patch/delete routes."""

from __future__ import annotations

import logging
from flask import (
    jsonify,
    request,
)
import config
import crypto
import db
from secret_ops import _upsert_secret
from .helpers import (
    _audit,
    _machine_actor,
    _meta_item,
    _parse_auth,
    _parse_expires_from_body,
    _pat_can_write,
    _require_machine_write,
    _resolve_project_ref,
    _upsert_body,
)
log = logging.getLogger(__name__)


def eso_upsert_secret(project_ref):
    """Create or update a secret (machine write role or PAT with write access).

    Audited as ``machine_upsert``.

    Args:
        project_ref: Project UUID (machine) or UUID/name (PAT).

    Returns:
        flask.Response: JSON secret metadata + ``ok``/``value`` on success;
            400/401/403 on validation or auth errors.

    Example:
        POST /eso/v1/projects/<project_ref>/secrets
        Authorization: Bearer ss_… | pat_…
        {"key": "db-password", "value": "s3cret", "note": "prod", "kind": "plain"}
    """
    body = request.get_json(silent=True) or {}
    key = (body.get("key") or "").strip()
    return _upsert_body(project_ref, key, body)


def eso_put_secret(project_ref, key):
    """Create or replace a secret by key (CLI-friendly RESTful edit/upsert).

    Audited as ``machine_upsert``.

    Args:
        project_ref: Project UUID (machine) or UUID/name (PAT).
        key: Secret key to create or replace.

    Returns:
        flask.Response: JSON secret metadata + value on success.

    Example:
        PUT /eso/v1/projects/<project_ref>/secrets/API_KEY
        Authorization: Bearer ss_… | pat_…
        {"value": "new-value", "note": "rotated"}
    """
    body = request.get_json(silent=True) or {}
    return _upsert_body(project_ref, key, body)


def eso_patch_secret(project_ref, key):
    """Partially update a secret: merge note/kind/expiry; value optional.

    Audited as ``machine_upsert``. Requires the secret to already exist.

    Args:
        project_ref: Project UUID (machine) or UUID/name (PAT).
        key: Existing secret key.

    Returns:
        flask.Response: Updated secret metadata (+ value if returned);
            404 if missing; 400/401/403 on other errors.

    Example:
        PATCH /eso/v1/projects/<project_ref>/secrets/API_KEY
        {"note": "rotated in CI", "expires_days": 90}
    """
    kind, ident = _parse_auth()
    if kind is None:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    key = (key or "").strip()
    if not key:
        return jsonify({"error": "key required"}), 400

    if kind == "machine":
        thash = ident
        with db.connect() as conn, conn.cursor() as cur:
            pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=thash)
            if not pid:
                return jsonify({"error": "unauthorized"}), 401
            _, err = _require_machine_write(cur, pid, thash)
            if err:
                return err
            cur.execute(
                "SELECT * FROM private.machine_get_row(%s::uuid, %s, %s)",
                (pid, thash, key),
            )
            existing = cur.fetchone()
            if not existing or not existing.get("value_enc"):
                return jsonify({"error": "not found"}), 404

            if "value" in body and body.get("value") is not None:
                value = str(body["value"])
                value_enc = crypto.encrypt(value)
            else:
                value_enc = existing["value_enc"]
                value = crypto.decrypt(value_enc)

            if "note" in body:
                note = str(body.get("note") or "").strip()
            else:
                note = existing.get("note") or ""

            if "kind" in body:
                kind_s = (body.get("kind") or "plain").strip().lower()
                if kind_s not in config.SECRET_KINDS:
                    return (
                        jsonify(
                            {
                                "error": f"kind must be one of: {', '.join(config.SECRET_KINDS)}"
                            }
                        ),
                        400,
                    )
            else:
                kind_s = existing.get("kind") or "plain"

            expires_at, set_expires, exp_err = _parse_expires_from_body(body)
            if exp_err:
                return jsonify({"error": exp_err}), 400
            if not set_expires:
                expires_at = existing.get("expires_at")
                set_expires = True

            cur.execute(
                """
                SELECT private.machine_upsert_enc(
                  %s::uuid, %s, %s, %s, %s, %s, %s, %s
                ) AS id
                """,
                (
                    pid,
                    thash,
                    key,
                    value_enc,
                    note,
                    kind_s,
                    expires_at,
                    set_expires,
                ),
            )
            out = cur.fetchone()
            if not out or not out["id"]:
                return jsonify({"error": "forbidden"}), 403
            actor = _machine_actor(cur, pid, thash)
            _audit(
                cur,
                project_id=pid,
                action="machine_upsert",
                secret_key=key,
                secret_id=out["id"],
                actor_email=actor,
            )
            cur.execute(
                "SELECT * FROM private.machine_get_row(%s::uuid, %s, %s)",
                (pid, thash, key),
            )
            row = cur.fetchone() or {}
            conn.commit()
        item = _meta_item(row, value=value)
        item["ok"] = True
        return jsonify(item), 200

    with db.as_user(ident) as conn, conn.cursor() as cur:
        pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=None)
        if not pid:
            return jsonify({"error": "not found"}), 404
        if not _pat_can_write(cur, pid):
            return jsonify({"error": "forbidden"}), 403
        cur.execute(
            """
            SELECT id, key, value_enc, note, kind, expires_at, created_at, updated_at
              FROM api.secrets
             WHERE project_id = %s AND key = %s AND deleted_at IS NULL
            """,
            (pid, key),
        )
        existing = cur.fetchone()
        if not existing:
            return jsonify({"error": "not found"}), 404
        if "value" in body and body.get("value") is not None:
            value = str(body["value"])
            value_enc = crypto.encrypt(value)
        else:
            value_enc = existing["value_enc"]
            value = crypto.decrypt(value_enc)
        note = (
            str(body.get("note") or "").strip()
            if "note" in body
            else (existing.get("note") or "")
        )
        if "kind" in body:
            kind_s = (body.get("kind") or "plain").strip().lower()
            if kind_s not in config.SECRET_KINDS:
                return jsonify(
                    {
                        "error": f"kind must be one of: {', '.join(config.SECRET_KINDS)}"
                    }
                ), 400
        else:
            kind_s = existing.get("kind") or "plain"
        expires_at, set_expires, exp_err = _parse_expires_from_body(body)
        if exp_err:
            return jsonify({"error": exp_err}), 400
        if not set_expires:
            expires_at = existing.get("expires_at")
        try:
            sid, _ = _upsert_secret(
                cur,
                pid,
                key,
                value_enc,
                note=note,
                expires_at=expires_at,
                kind=kind_s,
                already_enc=True,
            )
        except Exception as e:
            log.exception("pat patch failed")
            return jsonify({"error": str(e) or "forbidden"}), 403
        _audit(
            cur,
            project_id=pid,
            action="machine_upsert",
            secret_key=key,
            secret_id=sid,
        )
        cur.execute(
            """
            SELECT id, key, note, kind, expires_at, created_at, updated_at
              FROM api.secrets WHERE id = %s
            """,
            (str(sid),),
        )
        row = cur.fetchone() or existing
        conn.commit()
    item = _meta_item(row, value=value)
    item["ok"] = True
    return jsonify(item), 200


def eso_delete_secret(project_ref, key):
    """Soft-delete a secret by key (write role / PAT write). Moves it to trash.

    Audited as ``deleted``.

    Args:
        project_ref: Project UUID (machine) or UUID/name (PAT).
        key: Secret key to delete.

    Returns:
        flask.Response: ``{"ok": true, "id": ..., "key": ...}`` on success;
            404 if not found; 401/403 on auth errors.

    Example:
        DELETE /eso/v1/projects/<project_ref>/secrets/API_KEY
        Authorization: Bearer ss_… | pat_…
    """
    kind, ident = _parse_auth()
    if kind is None:
        return jsonify({"error": "unauthorized"}), 401
    key = (key or "").strip()
    if not key:
        return jsonify({"error": "key required"}), 400

    if kind == "machine":
        thash = ident
        with db.connect() as conn, conn.cursor() as cur:
            pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=thash)
            if not pid:
                return jsonify({"error": "unauthorized"}), 401
            _, err = _require_machine_write(cur, pid, thash)
            if err:
                return err
            cur.execute(
                "SELECT * FROM private.machine_get_row(%s::uuid, %s, %s)",
                (pid, thash, key),
            )
            existing = cur.fetchone()
            if not existing:
                return jsonify({"error": "not found"}), 404
            cur.execute(
                "SELECT private.machine_delete(%s::uuid, %s, %s) AS id",
                (pid, thash, key),
            )
            out = cur.fetchone()
            if not out or not out["id"]:
                return jsonify({"error": "forbidden"}), 403
            actor = _machine_actor(cur, pid, thash)
            _audit(
                cur,
                project_id=pid,
                action="deleted",
                secret_key=key,
                secret_id=out["id"],
                actor_email=actor,
            )
            conn.commit()
        return jsonify({"ok": True, "id": str(out["id"]), "key": key}), 200

    with db.as_user(ident) as conn, conn.cursor() as cur:
        pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=None)
        if not pid:
            return jsonify({"error": "not found"}), 404
        if not _pat_can_write(cur, pid):
            return jsonify({"error": "forbidden"}), 403
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
        cur.execute(
            """
            UPDATE api.secrets SET deleted_at = now()
             WHERE id = %s AND project_id = %s AND deleted_at IS NULL
            """,
            (str(row["id"]), pid),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "forbidden"}), 403
        _audit(
            cur,
            project_id=pid,
            action="deleted",
            secret_key=row["key"],
            secret_id=row["id"],
        )
        conn.commit()
    return jsonify({"ok": True, "id": str(row["id"]), "key": row["key"]}), 200
