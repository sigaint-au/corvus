"""Unified machine/CLI secret API + health (ESO, ss_…, and pat_…).

Base path: ``/eso/v1/projects/<project_ref>/secrets``.

Auth (``Authorization: Bearer …``):

- **Machine token** ``ss_…`` — project-scoped; ``project_ref`` must be that
  project's UUID. Uses ``private.machine_*`` SECURITY DEFINER helpers.
- **Personal access token** ``pat_…`` — user RLS via :func:`db.as_user`;
  ``project_ref`` may be a UUID or a unique project name the user can see.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from uuid import UUID

from flask import jsonify, request

import audit
import config
import crypto
import db
import pats
from crypto import sha256_hex
from secret_ops import _upsert_secret

log = logging.getLogger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def bearer_raw() -> str | None:
    """Return the raw Bearer token string, or None if missing/invalid header.

    Args:
        None (reads ``Authorization`` from the current request).

    Returns:
        Token string after ``Bearer ``, or None.

    Example:
        >>> # Authorization: Bearer ss_abc
        >>> bearer_raw()
        'ss_abc'
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    raw = auth[7:].strip()
    return raw or None


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
    raw = bearer_raw()
    return sha256_hex(raw) if raw else None


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


def _parse_auth():
    """Parse Bearer auth into ``("machine", thash)`` or ``("pat", user_id)``.

    Args:
        None (reads Authorization header).

    Returns:
        Tuple ``(kind, identity)`` where kind is ``"machine"`` or ``"pat"``,
        or ``(None, None)`` when unauthorized.

    Example:
        >>> kind, ident = _parse_auth()
        >>> kind in (None, "machine", "pat")
        True
    """
    raw = bearer_raw()
    if not raw:
        return None, None
    if raw.startswith(pats.PREFIX):
        uid = pats.resolve(raw)
        return ("pat", uid) if uid else (None, None)
    return "machine", sha256_hex(raw)


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


def _audit(
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
        actor_email: Actor label (machine label or user email for PAT).

    Returns:
        None.

    Example:
        >>> _audit(cur, project_id=pid, action="revealed",
        ...        secret_key="API_KEY", secret_id=sid, actor_email=actor)
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


def _require_machine_write(cur, project_id, thash) -> tuple[str | None, tuple | None]:
    """Check machine token has write role.

    Args:
        cur: Open DB cursor.
        project_id: Project UUID.
        thash: SHA-256 of the Bearer token.

    Returns:
        ``(role, None)`` when authorized for write, or
        ``(None, (jsonify(...), status))`` error response when not.

    Example:
        >>> role, err = _require_machine_write(cur, pid, thash)
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


def _resolve_project_ref(cur, project_ref: str, *, kind: str, thash: str | None) -> str | None:
    """Resolve path project_ref to a project UUID for the authenticated caller.

    Args:
        cur: Open DB cursor (machine: app role; PAT: already as_user).
        project_ref: UUID string or (PAT only) unique project name.
        kind: ``"machine"`` or ``"pat"``.
        thash: Machine token hash when kind is machine; ignored for PAT.

    Returns:
        Project UUID string, or None if not found / not authorized.

    Example:
        >>> pid = _resolve_project_ref(cur, "ios-app", kind="pat", thash=None)
    """
    ref = (project_ref or "").strip()
    if not ref:
        return None
    if kind == "machine":
        if not _UUID_RE.match(ref):
            return None
        cur.execute(
            "SELECT private.auth_machine(%s::uuid, %s) AS ok",
            (ref, thash),
        )
        auth = cur.fetchone()
        return ref if auth and auth.get("ok") else None

    # PAT / user RLS
    if _UUID_RE.match(ref):
        try:
            UUID(ref)
        except ValueError:
            return None
        cur.execute("SELECT id FROM api.projects WHERE id = %s::uuid", (ref,))
        row = cur.fetchone()
        return str(row["id"]) if row else None
    cur.execute(
        """
        SELECT id FROM api.projects
         WHERE name = %s
         ORDER BY created_at
         LIMIT 2
        """,
        (ref,),
    )
    rows = cur.fetchall() or []
    if len(rows) == 1:
        return str(rows[0]["id"])
    return None


def _pat_can_write(cur, project_id) -> bool:
    """Return True if the current RLS user may write the project.

    Args:
        cur: Open as_user cursor.
        project_id: Project UUID.

    Returns:
        Whether ``api.can_write_project`` is true.

    Example:
        >>> _pat_can_write(cur, pid)
        True
    """
    cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
    row = cur.fetchone() or {}
    return bool(row.get("w"))


def _pat_email(cur, user_id: str) -> str:
    """Load user email for audit labels (best-effort).

    Args:
        cur: Open cursor (admin or as_user).
        user_id: User UUID.

    Returns:
        Email string or empty string.

    Example:
        >>> _pat_email(cur, uid)
        'alice@example.com'
    """
    try:
        cur.execute(
            "SELECT email FROM private.users WHERE id = %s::uuid",
            (user_id,),
        )
        row = cur.fetchone() or {}
        return (row.get("email") or "").strip()
    except Exception:
        return ""


def _meta_list_query() -> tuple[bool, str | None]:
    """Parse list query flags for meta vs bulk-values mode.

    Args:
        None (reads request.args).

    Returns:
        ``(meta, q)`` where meta True means metadata-only list.

    Example:
        >>> meta, q = _meta_list_query()
    """
    meta = (
        request.args.get("meta") in ("1", "true", "yes")
        or request.args.get("format") == "meta"
        or request.args.get("include_values") in ("0", "false", "no")
    )
    q = (request.args.get("q") or "").strip() or None
    return meta, q


def register(app):
    """Register unified secret API (machine + PAT) and health routes.

    Args:
        app: Flask application instance to attach routes to.

    Returns:
        None

    Example:
        >>> from routes.eso import register
        >>> register(app)
    """

    @app.get("/eso/v1/projects")
    def eso_list_projects():
        """List projects visible to a PAT (not available for machine tokens).

        Args:
            None (optional query ``q`` / ``name`` filters by project or team name).

        Returns:
            flask.Response: ``{"items":[{id,name,team_id,team_name},…]}`` or
                401/400 JSON.

        Example:
            GET /eso/v1/projects?q=ios
            Authorization: Bearer pat_…
        """
        kind, ident = _parse_auth()
        if kind is None:
            return jsonify({"error": "unauthorized"}), 401
        if kind != "pat":
            return jsonify(
                {"error": "project list requires a personal access token (pat_…)"}
            ), 400
        q = (request.args.get("q") or request.args.get("name") or "").strip() or None
        with db.as_user(ident) as conn, conn.cursor() as cur:
            if q:
                cur.execute(
                    """
                    SELECT p.id, p.name, p.team_id, t.name AS team_name
                      FROM api.projects p
                      JOIN api.teams t ON t.id = p.team_id
                     WHERE p.name ILIKE %s OR t.name ILIKE %s
                     ORDER BY t.name, p.name
                     LIMIT 50
                    """,
                    (f"%{q}%", f"%{q}%"),
                )
            else:
                cur.execute(
                    """
                    SELECT p.id, p.name, p.team_id, t.name AS team_name
                      FROM api.projects p
                      JOIN api.teams t ON t.id = p.team_id
                     ORDER BY t.name, p.name
                     LIMIT 200
                    """
                )
            rows = cur.fetchall() or []
        return jsonify(
            {
                "items": [
                    {
                        "id": str(r["id"]),
                        "name": r["name"],
                        "team_id": str(r["team_id"]),
                        "team_name": r.get("team_name") or "",
                    }
                    for r in rows
                ]
            }
        )

    @app.get("/eso/v1/projects/<project_ref>/secrets/<path:key>")
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
        kind, ident = _parse_auth()
        if kind is None:
            return jsonify({"error": "unauthorized"}), 401
        key = (key or "").strip()

        if kind == "machine":
            thash = ident
            if not _UUID_RE.match((project_ref or "").strip()):
                return jsonify({"error": "unauthorized"}), 401
            with db.connect() as conn, conn.cursor() as cur:
                pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=thash)
                if not pid:
                    return jsonify({"error": "unauthorized"}), 401
                cur.execute(
                    "SELECT * FROM private.machine_get_row(%s::uuid, %s, %s)",
                    (pid, thash, key),
                )
                row = cur.fetchone()
                if row and row.get("value_enc"):
                    plaintext = crypto.decrypt(row["value_enc"])
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
                SELECT id, key, value_enc, note, kind, expires_at, created_at, updated_at
                  FROM api.secrets
                 WHERE project_id = %s AND key = %s AND deleted_at IS NULL
                """,
                (pid, key),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "not found"}), 404
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
                            "message": (
                                "You do not have permission to reveal this secret"
                            ),
                            "key": row["key"],
                        }
                    ),
                    403,
                )
            cur.execute(
                "SELECT api.can_reveal_secret(%s) AS ok", (str(row["id"]),)
            )
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
                                else "Reveal requires approval; "
                                "request access first"
                            ),
                            "key": row["key"],
                            "pending": bool(pending),
                        }
                    ),
                    403,
                )
            value = crypto.decrypt(row["value_enc"])
            _audit(
                cur,
                project_id=pid,
                action="revealed",
                secret_key=row["key"],
                secret_id=row["id"],
            )
            conn.commit()
        return jsonify(_meta_item(row, value=value))

    @app.post("/eso/v1/projects/<project_ref>/secrets/<path:key>/access-request")
    def eso_request_secret_access(project_ref, key):
        """Request approval to reveal a secret (PAT only).

        Body JSON optional: ``{"reason": "..."}``.

        Machine tokens are exempt from approval and should not use this.
        """
        kind, ident = _parse_auth()
        if kind is None:
            return jsonify({"error": "unauthorized"}), 401
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
            cur.execute(
                "SELECT api.can_reveal_secret(%s) AS ok", (str(row["id"]),)
            )
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

    @app.get("/eso/v1/projects/<project_ref>/access-requests")
    def eso_list_access_requests(project_ref):
        """List secret access requests for a project (PAT).

        Admins see all; others see their own. Query ``status=pending`` optional.
        """
        kind, ident = _parse_auth()
        if kind is None:
            return jsonify({"error": "unauthorized"}), 401
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

    @app.post("/eso/v1/projects/<project_ref>/access-requests/<req_id>/approve")
    def eso_approve_access_request(project_ref, req_id):
        """Approve a pending access request (project admin / team owner, PAT)."""
        kind, ident = _parse_auth()
        if kind is None:
            return jsonify({"error": "unauthorized"}), 401
        if kind != "pat":
            return jsonify({"error": "PAT required"}), 403
        body = request.get_json(silent=True) or {}
        try:
            if body.get("minutes") is not None:
                minutes = int(body["minutes"])
            elif body.get("hours") is not None:
                minutes = int(body["hours"]) * 60
            else:
                minutes = config.REVEAL_ACCESS_GRANT_MINUTES
        except (TypeError, ValueError):
            minutes = config.REVEAL_ACCESS_GRANT_MINUTES
        if minutes not in config.REVEAL_ACCESS_GRANT_CHOICES:
            minutes = config.REVEAL_ACCESS_GRANT_MINUTES
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

    @app.post("/eso/v1/projects/<project_ref>/access-requests/<req_id>/deny")
    def eso_deny_access_request(project_ref, req_id):
        """Deny a pending access request (project admin / team owner, PAT)."""
        kind, ident = _parse_auth()
        if kind is None:
            return jsonify({"error": "unauthorized"}), 401
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

    @app.get("/eso/v1/projects/<project_ref>/secrets")
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
        kind, ident = _parse_auth()
        if kind is None:
            return jsonify({"error": "unauthorized"}), 401
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
                cur.execute(
                    "SELECT * FROM private.machine_list_enc(%s::uuid, %s)",
                    (pid, thash),
                )
                rows = cur.fetchall() or []
                data = {r["key"]: crypto.decrypt(r["value_enc"]) for r in rows}
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
                where = "project_id = %s AND deleted_at IS NULL"
                params: list = [pid]
                if q:
                    where += " AND (key ILIKE %s OR note ILIKE %s)"
                    like = f"%{q}%"
                    params.extend([like, like])
                cur.execute(
                    f"""
                    SELECT id, key, note, kind, expires_at, created_at, updated_at
                      FROM api.secrets
                     WHERE {where}
                     ORDER BY key
                    """,
                    params,
                )
                rows = cur.fetchall() or []
                detail = f"cli/meta n={len(rows)}"
                if q:
                    detail += f" q={q[:80]}"
                _audit(cur, project_id=pid, action="exported", secret_key=detail)
                conn.commit()
                return jsonify({"items": [_meta_item(r) for r in rows]})
            cur.execute(
                """
                SELECT key, value_enc FROM api.secrets
                 WHERE project_id = %s AND deleted_at IS NULL
                """,
                (pid,),
            )
            rows = cur.fetchall() or []
            data = {}
            for r in rows:
                try:
                    data[r["key"]] = crypto.decrypt(r["value_enc"])
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

    def _upsert_body(project_ref, key: str, body: dict):
        """Shared create/update logic for POST and PUT (machine or PAT).

        Args:
            project_ref: Project UUID or name (PAT).
            key: Secret key to upsert.
            body: JSON body with value (required), optional note/kind/expires_*.

        Returns:
            Flask ``(response, status)`` tuple.
        """
        kind, ident = _parse_auth()
        if kind is None:
            return jsonify({"error": "unauthorized"}), 401

        key = (key or "").strip()
        value = body.get("value")
        note = body.get("note")
        if note is None:
            note = ""
        else:
            note = str(note).strip()
        kind_s = (body.get("kind") or "plain").strip().lower()
        if kind_s not in config.SECRET_KINDS:
            return jsonify(
                {"error": f"kind must be one of: {', '.join(config.SECRET_KINDS)}"}
            ), 400
        if not key or value is None:
            return jsonify({"error": "key and value required"}), 400

        expires_at, set_expires, exp_err = _parse_expires_from_body(body)
        if exp_err:
            return jsonify({"error": exp_err}), 400

        if kind == "machine":
            thash = ident
            with db.connect() as conn, conn.cursor() as cur:
                pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=thash)
                if not pid:
                    return jsonify({"error": "unauthorized"}), 401
                role, err = _require_machine_write(cur, pid, thash)
                if err:
                    return err
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
                        crypto.encrypt(str(value)),
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
            item = _meta_item(row, value=str(value))
            item["ok"] = True
            return jsonify(item), 200

        exp = expires_at if set_expires else None
        with db.as_user(ident) as conn, conn.cursor() as cur:
            pid = _resolve_project_ref(cur, project_ref, kind=kind, thash=None)
            if not pid:
                return jsonify({"error": "not found"}), 404
            if not _pat_can_write(cur, pid):
                return jsonify({"error": "forbidden"}), 403
            try:
                sid, _ = _upsert_secret(
                    cur, pid, key, str(value), note=note, expires_at=exp, kind=kind_s
                )
            except Exception as e:
                log.exception("pat upsert failed")
                return jsonify({"error": str(e) or "forbidden"}), 403
            if not sid:
                return jsonify({"error": "forbidden"}), 403
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
            row = cur.fetchone() or {"id": sid, "key": key}
            conn.commit()
        item = _meta_item(row, value=str(value))
        item["ok"] = True
        return jsonify(item), 200

    @app.post("/eso/v1/projects/<project_ref>/secrets")
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

    @app.put("/eso/v1/projects/<project_ref>/secrets/<path:key>")
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

    @app.patch("/eso/v1/projects/<project_ref>/secrets/<path:key>")
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
                role, err = _require_machine_write(cur, pid, thash)
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

    @app.delete("/eso/v1/projects/<project_ref>/secrets/<path:key>")
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
                role, err = _require_machine_write(cur, pid, thash)
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
