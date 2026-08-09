"""Secret DB helpers shared by project route modules."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import config
import crypto
import paging
from secret_kinds import secret_due_status


def _load_secrets_page(cur, project_id, page, q):
    """Count + page live secrets for a project. Returns (rows, pager).

    Args:
        cur: Open DB cursor (authenticated project context).
        project_id: UUID of the project whose secrets to list.
        page: 1-based page number for paging.page_window.
        q: Optional search string matched against key and note (ILIKE).

    Returns:
        Tuple of (rows, pager) where rows are secret dicts with due and
        is_pinned annotations, and pager is the paging window dict.

    Example:
        >>> # rows, pager = _load_secrets_page(cur, project_id, 1, "")
        >>> # isinstance(rows, list) and "limit" in pager
    """
    where = "project_id = %s AND deleted_at IS NULL"
    params = [str(project_id)]
    if q:
        where += " AND (key ILIKE %s OR note ILIKE %s)"
        like = f"%{q}%"
        params.extend([like, like])
    cur.execute(f"SELECT count(*) AS n FROM api.secrets WHERE {where}", params)
    total = int((cur.fetchone() or {}).get("n") or 0)
    pager = paging.page_window(total, page)
    pager.update(
        endpoint="project_detail",
        project_id=project_id,
        tab="secrets",
        q=q,
    )
    cur.execute(
        f"""
        SELECT id, key, note, kind, created_at, updated_at, expires_at, acl_mode
        FROM api.secrets
        WHERE {where}
        ORDER BY key
        LIMIT %s OFFSET %s
        """,
        (*params, pager["limit"], pager["offset"]),
    )
    rows = cur.fetchall()
    # Mark favorites for this page (single query)
    ids = [str(r["id"]) for r in rows]
    pinned = set()
    if ids:
        cur.execute(
            """
            SELECT secret_id FROM api.secret_pins
            WHERE user_id = api.current_user_id()
              AND secret_id = ANY(%s::uuid[])
            """,
            (ids,),
        )
        pinned = {str(x["secret_id"]) for x in (cur.fetchall() or [])}
    for r in rows:
        r["due"] = secret_due_status(r)
        r["is_pinned"] = str(r["id"]) in pinned
        mode = (r.get("acl_mode") or "inherit").strip() or "inherit"
        r["acl_mode"] = mode
        r["acl_restricted"] = mode != "inherit"
    return rows, pager


def _parse_acl_mode(form_or_value) -> str:
    """Parse secret ACL mode; default inherit."""
    if isinstance(form_or_value, dict) or (
        hasattr(form_or_value, "get") and not isinstance(form_or_value, (str, bytes))
    ):
        raw = form_or_value.get("acl_mode")
    else:
        raw = form_or_value
    mode = (raw or "inherit").strip().lower()
    if mode not in config.SECRET_ACL_MODES:
        return "inherit"
    return mode


def _parse_expires_at(form, *, allow_clear: bool = True):
    """Return expires_at datetime or None from form (capped at MAX_EXPIRY_DAYS).

    Empty / clear_expires → None (no expiry).

    Args:
        form: Mapping of form fields (e.g. request.form) with optional
            expires_at and clear_expires keys.
        allow_clear: If True, clear_expires truthy values force None.

    Returns:
        A timezone-aware datetime for the expiry, or None when cleared/empty.

    Raises:
        ValueError: If expires_at is not parseable ISO/date, or exceeds
            config.MAX_EXPIRY_DAYS from now.

    Example:
        >>> _parse_expires_at({"expires_at": ""}) is None
        True
    """
    if allow_clear and form.get("clear_expires") in ("1", "true", "on", "yes"):
        return None
    raw = (form.get("expires_at") or "").strip()
    if not raw:
        return None
    try:
        expires_at = datetime.fromisoformat(raw)
    except ValueError:
        raise ValueError("expires_at must be YYYY-MM-DD or ISO datetime")
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    cap = datetime.now(timezone.utc) + timedelta(days=config.MAX_EXPIRY_DAYS)
    if expires_at > cap:
        raise ValueError(f"expires_at must be within {config.MAX_EXPIRY_DAYS} days")
    return expires_at


def _upsert_secret(
    cur,
    project_id,
    key,
    value_or_enc,
    note="",
    expires_at=None,
    kind="plain",
    *,
    already_enc=False,
    touch_meta=True,
    acl_mode="inherit",
    set_acl_mode=False,
):
    """Insert/update one secret; returns (id, was_new).

    Args:
        cur: Open DB cursor for the project-scoped connection.
        project_id: UUID of the project that owns the secret.
        key: Secret key name (unique among live secrets in the project).
        value_or_enc: Plaintext value, or ciphertext if already_enc is True.
        note: Optional note stored with the secret.
        expires_at: Optional expiry datetime, or None for no expiry.
        kind: Secret kind string (normalized via normalize_kind).
        already_enc: If True, value_or_enc is stored as-is without encrypting.
        touch_meta: If True, also update note and expires_at on conflict;
            if False, preserve existing note when the new note is empty and
            do not set expires_at.
        acl_mode: Per-secret access mode (see config.SECRET_ACL_MODES).
        set_acl_mode: When True, write acl_mode on insert/update.

    Returns:
        Tuple (secret_id, was_new) where was_new is True when no live row
        existed for (project_id, key) before the upsert.

    Example:
        >>> # sid, created = _upsert_secret(cur, pid, "API_KEY", "secret")
        >>> # created in (True, False)
    """
    from secret_kinds import normalize_kind

    kind = normalize_kind(kind)
    mode = _parse_acl_mode(acl_mode)
    enc = value_or_enc if already_enc else crypto.encrypt(str(value_or_enc))
    cur.execute(
        """
        SELECT id FROM api.secrets
        WHERE project_id = %s AND key = %s AND deleted_at IS NULL
        """,
        (str(project_id), key),
    )
    existing = cur.fetchone()
    if touch_meta:
        if set_acl_mode:
            cur.execute(
                """
                INSERT INTO api.secrets
                  (project_id, key, value_enc, note, expires_at, kind, acl_mode)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
                  SET value_enc = EXCLUDED.value_enc,
                      note = EXCLUDED.note,
                      expires_at = EXCLUDED.expires_at,
                      kind = EXCLUDED.kind,
                      acl_mode = EXCLUDED.acl_mode
                RETURNING id
                """,
                (str(project_id), key, enc, note or "", expires_at, kind, mode),
            )
        else:
            cur.execute(
                """
                INSERT INTO api.secrets
                  (project_id, key, value_enc, note, expires_at, kind)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
                  SET value_enc = EXCLUDED.value_enc,
                      note = EXCLUDED.note,
                      expires_at = EXCLUDED.expires_at,
                      kind = EXCLUDED.kind
                RETURNING id
                """,
                (str(project_id), key, enc, note or "", expires_at, kind),
            )
    else:
        cur.execute(
            """
            INSERT INTO api.secrets (project_id, key, value_enc, note, kind)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
              SET value_enc = EXCLUDED.value_enc,
                  note = CASE WHEN EXCLUDED.note = '' THEN api.secrets.note
                              ELSE EXCLUDED.note END,
                  kind = EXCLUDED.kind
            RETURNING id
            """,
            (str(project_id), key, enc, note or "", kind),
        )
    row = cur.fetchone()
    return (row["id"] if row else None), (existing is None)


def compose_secret_value(kind: str, form) -> str:
    """Build plaintext value from advanced form fields for the given kind.

    Args:
        kind: Secret kind (database, certificate, ssh, kv, or plain).
        form: Form-like mapping (and getlist for kv) with kind-specific fields
            such as db_host, cert_pem, ssh_key, kv_keys, or plain_value.

    Returns:
        Composed plaintext secret string suitable for encryption/storage.

    Example:
        >>> compose_secret_value("plain", {"plain_value": "hello"})
        'hello'
    """
    from secret_kinds import normalize_kind

    kind = normalize_kind(kind)
    if kind == "database":
        scheme = (form.get("db_scheme") or "postgresql").strip()
        host = (form.get("db_host") or "").strip()
        port = (form.get("db_port") or "").strip()
        user = (form.get("db_user") or "").strip()
        password = form.get("db_password") or ""
        dbname = (form.get("db_name") or "").strip()
        auth = ""
        if user:
            from urllib.parse import quote

            auth = quote(user, safe="")
            if password:
                auth += ":" + quote(password, safe="")
            auth += "@"
        hostpart = host or "localhost"
        if port:
            hostpart += f":{port}"
        path = f"/{dbname}" if dbname else ""
        return f"{scheme}://{auth}{hostpart}{path}"
    if kind == "certificate":
        cert = (form.get("cert_pem") or "").strip()
        key = (form.get("cert_key") or "").strip()
        parts = [p for p in (cert, key) if p]
        return "\n\n".join(parts)
    if kind == "ssh":
        return (form.get("ssh_key") or "").strip()
    if kind == "kv":
        keys = form.getlist("kv_keys")
        values = form.getlist("kv_values")
        lines = []
        if keys:
            for i, k in enumerate(keys):
                k = (k or "").strip()
                if not k:
                    continue
                v = values[i] if i < len(values) else ""
                lines.append(f"{k}={v}")
        if lines:
            return "\n".join(lines)
        return (form.get("kv_block") or "").strip()
    return form.get("plain_value") or form.get("value") or ""
