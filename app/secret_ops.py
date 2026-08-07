"""Secret DB helpers shared by project route modules."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import config
import crypto
import paging
from secret_kinds import secret_due_status


def _load_secrets_page(cur, project_id, page, q):
    """Count + page live secrets for a project. Returns (rows, pager)."""
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
        SELECT id, key, note, created_at, updated_at, expires_at
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
    return rows, pager


def _parse_expires_at(form, *, allow_clear: bool = True):
    """
    Return expires_at datetime or None from form (capped at MAX_EXPIRY_DAYS).
    Empty / clear_expires → None (no expiry).
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
    *,
    already_enc=False,
    touch_meta=True,
):
    """Insert/update one secret; returns (id, was_new)."""
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
        cur.execute(
            """
            INSERT INTO api.secrets
              (project_id, key, value_enc, note, expires_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
              SET value_enc = EXCLUDED.value_enc,
                  note = EXCLUDED.note,
                  expires_at = EXCLUDED.expires_at
            RETURNING id
            """,
            (str(project_id), key, enc, note or "", expires_at),
        )
    else:
        cur.execute(
            """
            INSERT INTO api.secrets (project_id, key, value_enc, note)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
              SET value_enc = EXCLUDED.value_enc,
                  note = CASE WHEN EXCLUDED.note = '' THEN api.secrets.note
                              ELSE EXCLUDED.note END
            RETURNING id
            """,
            (str(project_id), key, enc, note or ""),
        )
    row = cur.fetchone()
    return (row["id"] if row else None), (existing is None)



def compose_secret_value(kind: str, form) -> tuple[str, str]:
    """Build (value, kind_label) from advanced form fields."""
    kind = (kind or "plain").strip().lower()
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
        return f"{scheme}://{auth}{hostpart}{path}", "database"
    if kind == "certificate":
        cert = (form.get("cert_pem") or "").strip()
        key = (form.get("cert_key") or "").strip()
        parts = [p for p in (cert, key) if p]
        return "\n\n".join(parts), "certificate"
    if kind == "ssh":
        return (form.get("ssh_key") or "").strip(), "ssh"
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
            return "\n".join(lines), "kv"
        # Back-compat: single textarea paste
        return (form.get("kv_block") or "").strip(), "kv"
    return form.get("plain_value") or "", "plain"
