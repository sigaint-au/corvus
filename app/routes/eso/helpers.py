"""Shared machine/PAT API helpers (auth, audit, resolve, upsert body)."""

from __future__ import annotations

import logging
from datetime import (
    datetime,
    timedelta,
    timezone,
)

from flask import (
    jsonify,
    request,
)
from werkzeug.exceptions import HTTPException

import audit
import crypto
from core import cache, config, db
from lib.auth_tokens import classify_token
from lib.datetime_utils import iso_utc
from lib.validate import is_uuid
from secret_svc.commands import upsert_secret_command

from .http import bearer_raw

log = logging.getLogger(__name__)


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
        "folder_id": str(row["folder_id"]) if row.get("folder_id") else None,
        "folder_path": row.get("folder_path") or None,
        "note": row.get("note") or "",
        "kind": row.get("kind") or "plain",
        "expires_at": iso_utc(row.get("expires_at")),
        "created_at": iso_utc(row.get("created_at")),
        "updated_at": iso_utc(row.get("updated_at")),
        "last_accessed_at": iso_utc(row.get("last_accessed_at")),
        "last_accessed_by": row.get("last_accessed_by_email") or row.get("last_accessed_by") or "",
    }
    for field in ("rotation_interval_days", "rotation_owner"):
        if field in row:
            out[field] = row.get(field)
    for field in ("rotation_next_at", "rotated_at"):
        if field in row:
            out[field] = iso_utc(row.get(field))
    meta = row.get("metadata")
    if meta is None and row.get("meta") is not None:
        meta = row.get("meta")
    if isinstance(meta, dict):
        out["metadata"] = meta
    elif meta is not None:
        out["metadata"] = meta
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
    return classify_token(bearer_raw())


_ESO_RATE_LIMIT = 100
_ESO_RATE_WINDOW = 60


def _require_auth():
    """Parse Bearer auth and enforce the machine-token rate limit.

    Returns:
        ``((kind, ident), None)`` when authorized, or ``(None, error_tuple)``
        where error_tuple is ``(jsonify(...), status)``. Machine tokens are
        throttled per token hash (sliding window via Redis; fails open when
        Redis is unavailable). PATs are not throttled here — session/DB-backed
        controls already apply.
    """
    kind, ident = _parse_auth()
    if kind is None:
        return None, (jsonify({"error": "unauthorized"}), 401)
    if kind == "machine" and cache.rate_limited(
        f"corvus:rl:{ident}", limit=_ESO_RATE_LIMIT, window=_ESO_RATE_WINDOW
    ):
        return None, (jsonify({"error": "rate limited"}), 429)
    return (kind, ident), None


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
        days_value = body.get("expires_days")
        if days_value is None:
            return None, False, "expires_days must be an integer"
        try:
            days = int(days_value)
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
        >>> _, err = _require_machine_write(cur, pid, thash)
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
    if role != "service-write":
        return None, (jsonify({"error": "token does not have write access"}), 403)
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
        if not is_uuid(ref):
            return None
        cur.execute(
            "SELECT private.auth_machine(%s::uuid, %s) AS ok",
            (ref, thash),
        )
        auth = cur.fetchone()
        return ref if auth and auth.get("ok") else None

    # PAT / user RLS
    if is_uuid(ref):
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


def _upsert_body(project_ref, key: str, body: dict):
    """Shared create/update logic for POST and PUT (machine or PAT).

    Args:
        project_ref: Project UUID or name (PAT).
        key: Secret key to upsert.
        body: JSON body with value (required), optional note/kind/expires_*.

    Returns:
        Flask ``(response, status)`` tuple.
    """
    auth, err = _require_auth()
    if err:
        return err
    kind, ident = auth

    key = (key or "").strip()
    value = body.get("value")
    note = body.get("note")
    if note is None:
        note = ""
    else:
        note = str(note).strip()
    kind_s = (body.get("kind") or "plain").strip().lower()
    if kind_s not in config.SECRET_KINDS:
        return jsonify({"error": f"kind must be one of: {', '.join(config.SECRET_KINDS)}"}), 400
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
            _, err = _require_machine_write(cur, pid, thash)
            if err:
                return err
            value_enc, enc_provider = crypto.encrypt_for_project(str(pid), str(value))
            cur.execute(
                """
                SELECT private.machine_upsert_enc(
                  %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s
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
                    enc_provider,
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
            sid, _was_new = upsert_secret_command(
                cur,
                project_id=pid,
                key=key,
                value=str(value),
                note=note,
                expires_at=exp,
                kind=kind_s,
                audit_action="machine_upsert",
                actor_email=ident,
            )
        except HTTPException as e:
            return jsonify({"error": str(e)}), e.code
        cur.execute(
            """
            SELECT id, key, note, kind, expires_at,
                   rotation_interval_days, rotation_owner, rotation_next_at, rotated_at,
                   created_at, updated_at
              FROM api.secrets WHERE id = %s
            """,
            (str(sid),),
        )
        row = cur.fetchone() or {"id": sid, "key": key}
        conn.commit()
    item = _meta_item(row, value=str(value))
    item["ok"] = True
    return jsonify(item), 200
