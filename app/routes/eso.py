"""OpenShift External Secrets Operator webhook + health + machine/CLI secret API."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from flask import jsonify, request

import audit
import config
import crypto
import db
from crypto import sha256_hex

log = logging.getLogger(__name__)


def bearer_hash():
    """Extract and hash the Bearer token from the Authorization header.

    Args:
        None

    Returns:
        str | None: SHA-256 hex digest of the Bearer token, or None if the
            header is missing or not a Bearer token.

    Example:
        >>> # Called from an ESO route with Authorization: Bearer <token>
        >>> thash = bearer_hash()
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return sha256_hex(auth[7:].strip())


def _iso(dt) -> str | None:
    """Format a datetime as UTC ISO-8601, or None.

    Args:
        dt: A datetime (aware or naive) or None.

    Returns:
        ISO-8601 string, or None when ``dt`` is None.

    Example:
        >>> _iso(None) is None
        True
    """
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _meta_item(row: dict, *, value: str | None = None) -> dict:
    """Build a CLI-friendly secret metadata (and optional value) dict.

    Args:
        row: DB row with id/key/note/kind/timestamps (and optionally value_enc).
        value: When provided, include plaintext ``value`` in the result.

    Returns:
        JSON-serializable dict for machine/CLI responses.

    Example:
        >>> _meta_item({"id": "...", "key": "K", "note": "", "kind": "plain",
        ...             "expires_at": None, "created_at": None, "updated_at": None})
        {'id': '...', 'key': 'K', ...}
    """
    out = {
        "id": str(row["id"]) if row.get("id") is not None else None,
        "key": row.get("key"),
        "note": row.get("note") or "",
        "kind": row.get("kind") or "plain",
        "expires_at": _iso(row.get("expires_at")),
        "created_at": _iso(row.get("created_at")),
        "updated_at": _iso(row.get("updated_at")),
    }
    if value is not None:
        out["value"] = value
    return out


def _machine_actor(cur, project_id, thash: str) -> str:
    """Resolve a stable audit actor label for a machine token.

    Args:
        cur: Open DB cursor.
        project_id: Project UUID the token is scoped to.
        thash: SHA-256 hex of the Bearer token.

    Returns:
        String like ``machine:eso-pull:ss_abc12xyz``, or ``machine`` if unknown.

    Example:
        >>> actor = _machine_actor(cur, pid, thash)
        >>> actor.startswith("machine")
        True
    """
    try:
        cur.execute(
            "SELECT private.machine_token_label(%s::uuid, %s) AS label",
            (str(project_id), thash),
        )
        row = cur.fetchone() or {}
        label = (row.get("label") or "").strip()
        if label:
            return f"machine:{label}"
    except Exception:
        log.warning("machine_token_label failed", exc_info=True)
    return "machine"


def _audit_machine(
    cur,
    *,
    project_id,
    action: str,
    secret_key: str = "",
    secret_id=None,
    actor_email: str = "machine",
) -> None:
    """Write a secret_audit row for a machine/CLI API operation.

    Args:
        cur: Open DB cursor (caller must commit).
        project_id: Project UUID.
        action: One of ``audit.ACTIONS`` (e.g. revealed, machine_upsert, deleted).
        secret_key: Secret key name or export detail string.
        secret_id: Optional secret UUID.
        actor_email: Actor label (prefer :func:`_machine_actor` result).

    Returns:
        None.

    Example:
        >>> _audit_machine(cur, project_id=pid, action="revealed",
        ...                secret_key="API_KEY", secret_id=sid, actor_email=actor)
    """
    audit.log_secret(
        cur,
        project_id=project_id,
        action=action,
        secret_key=secret_key or "",
        secret_id=secret_id,
        actor_email=actor_email or "machine",
    )


def _parse_expires_from_body(body: dict) -> tuple[datetime | None, bool, str | None]:
    """Parse optional expiry fields from a JSON body.

    Accepts ``expires_at`` (ISO date/datetime), ``expires_days`` (int from now),
    or ``clear_expires`` to clear. When none of these keys are present, expiry
    is left unchanged on update.

    Args:
        body: Request JSON dict.

    Returns:
        Tuple ``(expires_at, set_expires, error)``. ``error`` is a message when
        invalid; otherwise None. ``set_expires`` is True when the client asked
        to set or clear expiry.

    Example:
        >>> _parse_expires_from_body({"expires_days": 30})[1]
        True
    """
    if body.get("clear_expires") in (True, 1, "1", "true", "on", "yes"):
        return None, True, None

    has_at = "expires_at" in body
    has_days = "expires_days" in body
    if not has_at and not has_days:
        return None, False, None

    if has_days:
        try:
            days = int(body.get("expires_days"))
        except (TypeError, ValueError):
            return None, False, "expires_days must be an integer"
        if days < 1 or days > config.MAX_EXPIRY_DAYS:
            return (
                None,
                False,
                f"expires_days must be between 1 and {config.MAX_EXPIRY_DAYS}",
            )
        exp = datetime.now(timezone.utc) + timedelta(days=days)
        return exp, True, None

    raw = body.get("expires_at")
    if raw is None or raw == "":
        return None, True, None
    if not isinstance(raw, str):
        return None, False, "expires_at must be an ISO date/datetime string"
    try:
        exp = datetime.fromisoformat(raw.strip())
    except ValueError:
        return None, False, "expires_at must be YYYY-MM-DD or ISO datetime"
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    cap = datetime.now(timezone.utc) + timedelta(days=config.MAX_EXPIRY_DAYS)
    if exp > cap:
        return None, False, f"expires_at must be within {config.MAX_EXPIRY_DAYS} days"
    return exp, True, None


def _require_write_role(cur, project_id, thash) -> tuple[str | None, tuple | None]:
    """Check machine token has write role.

    Args:
        cur: Open DB cursor.
        project_id: Project UUID.
        thash: SHA-256 of the Bearer token.

    Returns:
        ``(role, None)`` when authorized for write, or
        ``(None, (jsonify(...), status))`` error response when not.

    Example:
        >>> role, err = _require_write_role(cur, pid, thash)
        >>> if err:
        ...     return err
    """
    cur.execute(
        "SELECT private.machine_role(%s::uuid, %s) AS role",
        (str(project_id), thash),
    )
    row = cur.fetchone()
    role = row["role"] if row else None
    if role is None:
        return None, (jsonify({"error": "unauthorized"}), 401)
    if role != "write":
        return None, (jsonify({"error": "token is read-only"}), 403)
    return role, None


def _upsert_body(project_id, key: str, body: dict):
    """Shared create/update logic for POST and PUT machine API.

    Args:
        project_id: Project UUID.
        key: Secret key to upsert.
        body: JSON body with value (required), optional note/kind/expires_*.

    Returns:
        Flask ``(response, status)`` tuple.
    """
    thash = bearer_hash()
    if not thash:
        return jsonify({"error": "unauthorized"}), 401

    key = (key or "").strip()
    value = body.get("value")
    note = body.get("note")
    if note is None:
        note = ""
    else:
        note = str(note).strip()
    kind = (body.get("kind") or "plain").strip().lower()
    if kind not in config.SECRET_KINDS:
        return jsonify({"error": f"kind must be one of: {', '.join(config.SECRET_KINDS)}"}), 400
    if not key or value is None:
        return jsonify({"error": "key and value required"}), 400

    expires_at, set_expires, exp_err = _parse_expires_from_body(body)
    if exp_err:
        return jsonify({"error": exp_err}), 400

    with db.connect() as conn, conn.cursor() as cur:
        role, err = _require_write_role(cur, project_id, thash)
        if err:
            return err
        cur.execute(
            """
            SELECT private.machine_upsert_enc(
              %s::uuid, %s, %s, %s, %s, %s, %s, %s
            ) AS id
            """,
            (
                str(project_id),
                thash,
                key,
                crypto.encrypt(str(value)),
                note,
                kind,
                expires_at,
                set_expires,
            ),
        )
        out = cur.fetchone()
        if not out or not out["id"]:
            return jsonify({"error": "forbidden"}), 403
        actor = _machine_actor(cur, project_id, thash)
        _audit_machine(
            cur,
            project_id=project_id,
            action="machine_upsert",
            secret_key=key,
            secret_id=out["id"],
            actor_email=actor,
        )
        cur.execute(
            "SELECT * FROM private.machine_get_row(%s::uuid, %s, %s)",
            (str(project_id), thash, key),
        )
        row = cur.fetchone() or {}
        conn.commit()

    item = _meta_item(row, value=str(value))
    item["ok"] = True
    return jsonify(item), 200


def register(app):
    """Register ESO webhook, machine/CLI secret API, and health routes.

    Args:
        app: Flask application instance to attach routes to.

    Returns:
        None

    Example:
        >>> from routes.eso import register
        >>> register(app)
    """

    @app.get("/eso/v1/projects/<uuid:project_id>/secrets/<path:key>")
    def eso_get_secret(project_id, key):
        """Fetch a single secret (value + metadata) for ESO or CLI.

        Successful plaintext returns are audited as ``revealed`` (same as UI).

        Args:
            project_id: UUID of the project that owns the secret.
            key: Secret key path within the project.

        Returns:
            flask.Response: JSON with ``value``, ``key``, ``id``, ``note``,
                ``kind``, ``expires_at``, ``created_at``, ``updated_at``;
                401 unauthorized or 404 not found on failure.

        Example:
            GET /eso/v1/projects/<project_id>/secrets/<key>
            Authorization: Bearer <machine-token>
        """
        thash = bearer_hash()
        if not thash:
            return jsonify({"error": "unauthorized"}), 401
        with db.connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM private.machine_get_row(%s::uuid, %s, %s)",
                (str(project_id), thash, key),
            )
            row = cur.fetchone()
            if row and row.get("value_enc"):
                plaintext = crypto.decrypt(row["value_enc"])
                actor = _machine_actor(cur, project_id, thash)
                _audit_machine(
                    cur,
                    project_id=project_id,
                    action="revealed",
                    secret_key=row.get("key") or key,
                    secret_id=row.get("id"),
                    actor_email=actor,
                )
                conn.commit()
                return jsonify(_meta_item(row, value=plaintext))
            cur.execute(
                "SELECT private.auth_machine(%s::uuid, %s) AS ok",
                (str(project_id), thash),
            )
            auth = cur.fetchone()
            if not auth or not auth["ok"]:
                return jsonify({"error": "unauthorized"}), 401
        return jsonify({"error": "not found"}), 404

    @app.get("/eso/v1/projects/<uuid:project_id>/secrets")
    def eso_list_secrets(project_id):
        """List project secrets for ESO bulk sync or CLI metadata listing.

        Default (ESO-compatible): ``{"secrets": {key: value, ...}}`` — bulk
        plaintext is audited as ``exported`` (same class as UI export).

        CLI mode — pass ``meta=1`` (or ``format=meta`` / ``include_values=0``):
        ``{"items": [...]}`` without decrypting values. Metadata-only lists are
        audited as ``exported`` with detail ``machine/meta n=…`` so every API
        access leaves a trail.

        Args:
            project_id: UUID of the project whose secrets to list.

        Returns:
            flask.Response: JSON list/map on success; 401 if token invalid.

        Example:
            GET /eso/v1/projects/<id>/secrets
            GET /eso/v1/projects/<id>/secrets?meta=1&q=db
            Authorization: Bearer <machine-token>
        """
        thash = bearer_hash()
        if not thash:
            return jsonify({"error": "unauthorized"}), 401

        meta = (
            request.args.get("meta") in ("1", "true", "yes")
            or request.args.get("format") == "meta"
            or request.args.get("include_values") in ("0", "false", "no")
        )
        q = (request.args.get("q") or "").strip() or None

        with db.connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT private.auth_machine(%s::uuid, %s) AS ok",
                (str(project_id), thash),
            )
            auth = cur.fetchone()
            if not auth or not auth["ok"]:
                return jsonify({"error": "unauthorized"}), 401

            actor = _machine_actor(cur, project_id, thash)

            if meta:
                cur.execute(
                    "SELECT * FROM private.machine_list_meta(%s::uuid, %s, %s)",
                    (str(project_id), thash, q),
                )
                rows = cur.fetchall() or []
                detail = f"machine/meta n={len(rows)}"
                if q:
                    detail += f" q={q[:80]}"
                _audit_machine(
                    cur,
                    project_id=project_id,
                    action="exported",
                    secret_key=detail,
                    actor_email=actor,
                )
                conn.commit()
                return jsonify({"items": [_meta_item(r) for r in rows]})

            cur.execute(
                "SELECT * FROM private.machine_list_enc(%s::uuid, %s)",
                (str(project_id), thash),
            )
            rows = cur.fetchall() or []
            data = {r["key"]: crypto.decrypt(r["value_enc"]) for r in rows}
            _audit_machine(
                cur,
                project_id=project_id,
                action="exported",
                secret_key=f"machine/values n={len(rows)}",
                actor_email=actor,
            )
            conn.commit()
        return jsonify({"secrets": data})

    @app.post("/eso/v1/projects/<uuid:project_id>/secrets")
    def eso_upsert_secret(project_id):
        """Create or update a secret via the machine write API (CLI/CI).

        Audited as ``machine_upsert``.

        Args:
            project_id: UUID of the project to write the secret into.

        Returns:
            flask.Response: JSON secret metadata + ``ok``/``value`` on success;
                400/401/403 on validation or auth errors.

        Example:
            POST /eso/v1/projects/<project_id>/secrets
            Authorization: Bearer <machine-token-role=write>
            {"key": "db-password", "value": "s3cret", "note": "prod", "kind": "plain"}
        """
        body = request.get_json(silent=True) or {}
        key = (body.get("key") or "").strip()
        return _upsert_body(project_id, key, body)

    @app.put("/eso/v1/projects/<uuid:project_id>/secrets/<path:key>")
    def eso_put_secret(project_id, key):
        """Create or replace a secret by key (CLI-friendly RESTful modify).

        Audited as ``machine_upsert``.

        Args:
            project_id: UUID of the project.
            key: Secret key to create or replace.

        Returns:
            flask.Response: JSON secret metadata + value on success.

        Example:
            PUT /eso/v1/projects/<project_id>/secrets/API_KEY
            Authorization: Bearer <write-token>
            {"value": "new-value", "note": "rotated"}
        """
        body = request.get_json(silent=True) or {}
        return _upsert_body(project_id, key, body)

    @app.patch("/eso/v1/projects/<uuid:project_id>/secrets/<path:key>")
    def eso_patch_secret(project_id, key):
        """Partially update a secret: merge note/kind/expiry; value optional.

        Audited as ``machine_upsert``. Requires the secret to already exist.

        Args:
            project_id: UUID of the project.
            key: Existing secret key.

        Returns:
            flask.Response: Updated secret metadata (+ value if returned);
                404 if missing; 400/401/403 on other errors.

        Example:
            PATCH /eso/v1/projects/<id>/secrets/API_KEY
            {"note": "rotated in CI", "expires_days": 90}
        """
        thash = bearer_hash()
        if not thash:
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        key = (key or "").strip()
        if not key:
            return jsonify({"error": "key required"}), 400

        with db.connect() as conn, conn.cursor() as cur:
            role, err = _require_write_role(cur, project_id, thash)
            if err:
                return err
            cur.execute(
                "SELECT * FROM private.machine_get_row(%s::uuid, %s, %s)",
                (str(project_id), thash, key),
            )
            existing = cur.fetchone()
            if not existing or not existing.get("value_enc"):
                return jsonify({"error": "not found"}), 404

            # Reuse existing ciphertext when value is not in the body so Fernet
            # does not rotate the token (would archive a spurious secret_version).
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
                kind = (body.get("kind") or "plain").strip().lower()
                if kind not in config.SECRET_KINDS:
                    return (
                        jsonify(
                            {
                                "error": f"kind must be one of: {', '.join(config.SECRET_KINDS)}"
                            }
                        ),
                        400,
                    )
            else:
                kind = existing.get("kind") or "plain"

            expires_at, set_expires, exp_err = _parse_expires_from_body(body)
            if exp_err:
                return jsonify({"error": exp_err}), 400
            if not set_expires:
                expires_at = existing.get("expires_at")
                set_expires = True  # re-apply current so SQL keeps it explicitly

            cur.execute(
                """
                SELECT private.machine_upsert_enc(
                  %s::uuid, %s, %s, %s, %s, %s, %s, %s
                ) AS id
                """,
                (
                    str(project_id),
                    thash,
                    key,
                    value_enc,
                    note,
                    kind,
                    expires_at,
                    set_expires,
                ),
            )
            out = cur.fetchone()
            if not out or not out["id"]:
                return jsonify({"error": "forbidden"}), 403
            actor = _machine_actor(cur, project_id, thash)
            _audit_machine(
                cur,
                project_id=project_id,
                action="machine_upsert",
                secret_key=key,
                secret_id=out["id"],
                actor_email=actor,
            )
            cur.execute(
                "SELECT * FROM private.machine_get_row(%s::uuid, %s, %s)",
                (str(project_id), thash, key),
            )
            row = cur.fetchone() or {}
            conn.commit()

        item = _meta_item(row, value=value)
        item["ok"] = True
        return jsonify(item), 200

    @app.delete("/eso/v1/projects/<uuid:project_id>/secrets/<path:key>")
    def eso_delete_secret(project_id, key):
        """Soft-delete a secret by key (write role). Moves it to trash.

        Audited as ``deleted``.

        Args:
            project_id: UUID of the project.
            key: Secret key to delete.

        Returns:
            flask.Response: ``{"ok": true, "id": ..., "key": ...}`` on success;
                404 if not found; 401/403 on auth errors.

        Example:
            DELETE /eso/v1/projects/<project_id>/secrets/API_KEY
            Authorization: Bearer <write-token>
        """
        thash = bearer_hash()
        if not thash:
            return jsonify({"error": "unauthorized"}), 401
        key = (key or "").strip()
        if not key:
            return jsonify({"error": "key required"}), 400

        with db.connect() as conn, conn.cursor() as cur:
            role, err = _require_write_role(cur, project_id, thash)
            if err:
                return err
            cur.execute(
                "SELECT * FROM private.machine_get_row(%s::uuid, %s, %s)",
                (str(project_id), thash, key),
            )
            existing = cur.fetchone()
            if not existing:
                return jsonify({"error": "not found"}), 404

            cur.execute(
                "SELECT private.machine_delete(%s::uuid, %s, %s) AS id",
                (str(project_id), thash, key),
            )
            out = cur.fetchone()
            if not out or not out["id"]:
                return jsonify({"error": "forbidden"}), 403
            actor = _machine_actor(cur, project_id, thash)
            _audit_machine(
                cur,
                project_id=project_id,
                action="deleted",
                secret_key=key,
                secret_id=out["id"],
                actor_email=actor,
            )
            conn.commit()

        return jsonify({"ok": True, "id": str(out["id"]), "key": key}), 200

    @app.get("/health")
    def health():
        """Report application and database connectivity health.

        Args:
            None

        Returns:
            flask.Response: JSON ``{"ok": true}`` on success, or
                ``{"ok": false}`` with status 503 if the DB check fails.

        Example:
            GET /health
        """
        try:
            with db.connect() as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
            return jsonify({"ok": True})
        except Exception:
            log.exception("health check failed")
            return jsonify({"ok": False}), 503
