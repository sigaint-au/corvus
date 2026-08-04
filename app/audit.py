"""Secret access / mutation audit logging."""

from flask import session

# Actions written to api.secret_audit.action
ACTIONS = ("created", "updated", "revealed", "deleted", "restored", "purged")


def log_secret(
    cur,
    *,
    project_id,
    action: str,
    secret_key: str = "",
    secret_id=None,
    user_id=None,
    actor_email: str | None = None,
):
    """Insert an audit row using an open cursor (same transaction as the action)."""
    if action not in ACTIONS:
        raise ValueError(f"invalid audit action: {action}")
    uid = user_id if user_id is not None else session.get("user_id")
    email = actor_email if actor_email is not None else (session.get("email") or "")
    cur.execute(
        """
        INSERT INTO api.secret_audit
          (project_id, secret_id, secret_key, user_id, actor_email, action)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            str(project_id),
            str(secret_id) if secret_id else None,
            secret_key or "",
            str(uid) if uid else None,
            email,
            action,
        ),
    )


def _search_clause(q: str):
    """Return (sql_fragment, params) for optional audit search."""
    q = (q or "").strip()
    if not q:
        return "", []
    like = f"%{q}%"
    return (
        """
        AND (
          a.secret_key ILIKE %s
          OR a.action ILIKE %s
          OR a.actor_email ILIKE %s
          OR COALESCE(u.name, '') ILIKE %s
        )
        """,
        [like, like, like, like],
    )


def count_for_project(cur, project_id, q: str = "") -> int:
    extra, params = _search_clause(q)
    cur.execute(
        f"""
        SELECT count(*) AS n
        FROM api.secret_audit a
        LEFT JOIN api.user_directory u ON u.id = a.user_id
        WHERE a.project_id = %s
        {extra}
        """,
        (str(project_id), *params),
    )
    row = cur.fetchone() or {}
    return int(row.get("n") or 0)


def list_for_project(cur, project_id, limit=25, offset=0, q: str = ""):
    extra, params = _search_clause(q)
    cur.execute(
        f"""
        SELECT a.id, a.secret_id, a.secret_key, a.action, a.created_at,
               a.actor_email, a.user_id,
               COALESCE(u.name, '') AS actor_name
        FROM api.secret_audit a
        LEFT JOIN api.user_directory u ON u.id = a.user_id
        WHERE a.project_id = %s
        {extra}
        ORDER BY a.created_at DESC
        LIMIT %s OFFSET %s
        """,
        (str(project_id), *params, limit, offset),
    )
    return cur.fetchall()
