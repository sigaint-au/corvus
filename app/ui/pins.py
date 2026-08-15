"""Per-user secret pins (favorites) and recently accessed."""

from core.config import SIDEBAR_PINS_LIMIT, SIDEBAR_RECENT_LIMIT


def touch_recent(cur, user_id, secret_id):
    """Record or refresh a secret in the user's recently accessed list.

    Upserts ``api.secret_recent`` so ``accessed_at`` is ``now()``.

    Args:
        cur: Open DB cursor (user RLS connection).
        user_id: UUID of the user who accessed the secret.
        secret_id: UUID of the secret that was viewed/revealed.

    Returns:
        None.

    Example:
        >>> with db.as_user(uid) as conn, conn.cursor() as cur:
        ...     touch_recent(cur, uid, secret_id)
    """
    # Isolate RLS failures so they cannot abort the caller's transaction
    # (view/reveal still need to audit after this upsert).
    cur.execute("SAVEPOINT touch_recent")
    try:
        cur.execute(
            """
            INSERT INTO api.secret_recent (user_id, secret_id, accessed_at)
            VALUES (%s, %s, now())
            ON CONFLICT (user_id, secret_id) DO UPDATE SET accessed_at = now()
            """,
            (str(user_id), str(secret_id)),
        )
        cur.execute("RELEASE SAVEPOINT touch_recent")
    except Exception:
        cur.execute("ROLLBACK TO SAVEPOINT touch_recent")
        raise


def is_pinned(cur, user_id, secret_id) -> bool:
    """Return whether the user has pinned the given secret.

    Args:
        cur: Open DB cursor.
        user_id: UUID of the user.
        secret_id: UUID of the secret.

    Returns:
        True if a pin row exists; False otherwise.

    Example:
        >>> if is_pinned(cur, uid, sid):
        ...     # show "unpin" control
        ...     pass
    """
    cur.execute(
        """
        SELECT 1 FROM api.secret_pins
        WHERE user_id = %s AND secret_id = %s
        """,
        (str(user_id), str(secret_id)),
    )
    return cur.fetchone() is not None


def pin(cur, user_id, secret_id):
    """Pin a secret for the user (idempotent).

    Args:
        cur: Open DB cursor.
        user_id: UUID of the user.
        secret_id: UUID of the secret to pin.

    Returns:
        None. Existing pins are left unchanged (``ON CONFLICT DO NOTHING``).

    Example:
        >>> pin(cur, uid, secret_id)
    """
    cur.execute(
        """
        INSERT INTO api.secret_pins (user_id, secret_id)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING
        """,
        (str(user_id), str(secret_id)),
    )


def unpin(cur, user_id, secret_id):
    """Remove a pin for the user and secret.

    Args:
        cur: Open DB cursor.
        user_id: UUID of the user.
        secret_id: UUID of the secret to unpin.

    Returns:
        None.

    Example:
        >>> unpin(cur, uid, secret_id)
    """
    cur.execute(
        """
        DELETE FROM api.secret_pins
        WHERE user_id = %s AND secret_id = %s
        """,
        (str(user_id), str(secret_id)),
    )


def _secret_rows(cur, sql, params):
    """Execute a SELECT and return all rows (or empty list).

    Args:
        cur: Open DB cursor.
        sql: SQL query string that returns secret summary columns.
        params: Bind parameters for ``sql``.

    Returns:
        List of row dicts, or ``[]`` if the query returns no rows.

    Example:
        >>> rows = _secret_rows(cur, "SELECT id FROM api.secrets WHERE ...", (pid,))
    """
    cur.execute(sql, params)
    return cur.fetchall() or []


def list_pins(cur, user_id, limit=SIDEBAR_PINS_LIMIT):
    """List the user's pinned secrets for the sidebar (newest pin first).

    Args:
        cur: Open DB cursor with RLS as the user.
        user_id: UUID of the user.
        limit: Max rows. Defaults to ``SIDEBAR_PINS_LIMIT`` (8).

    Returns:
        List of dicts with ``id``, ``key``, ``project_id``, ``project_name``,
        ``team_name`` for live (non-deleted) secrets.

    Example:
        >>> pins = list_pins(cur, session["user_id"])
        >>> for p in pins:
        ...     print(p["key"], p["project_name"])
    """
    return _secret_rows(
        cur,
        """
        SELECT s.id, s.key, s.project_id, p.name AS project_name, t.name AS team_name
        FROM api.secret_pins pin
        JOIN api.secrets s ON s.id = pin.secret_id AND s.deleted_at IS NULL
        JOIN api.projects p ON p.id = s.project_id
        JOIN api.teams t ON t.id = p.team_id
        WHERE pin.user_id = %s
        ORDER BY pin.created_at DESC
        LIMIT %s
        """,
        (str(user_id), limit),
    )


def list_recent(cur, user_id, limit=SIDEBAR_RECENT_LIMIT):
    """List recently accessed secrets for the sidebar.

    Args:
        cur: Open DB cursor with RLS as the user.
        user_id: UUID of the user.
        limit: Max rows. Defaults to ``SIDEBAR_RECENT_LIMIT`` (8).

    Returns:
        List of dicts with ``id``, ``key``, ``project_id``, ``project_name``,
        ``team_name``, ``accessed_at`` for live secrets, newest first.

    Example:
        >>> recent = list_recent(cur, session["user_id"])
    """
    return _secret_rows(
        cur,
        """
        SELECT s.id, s.key, s.project_id, p.name AS project_name, t.name AS team_name,
               r.accessed_at
        FROM api.secret_recent r
        JOIN api.secrets s ON s.id = r.secret_id AND s.deleted_at IS NULL
        JOIN api.projects p ON p.id = s.project_id
        JOIN api.teams t ON t.id = p.team_id
        WHERE r.user_id = %s
        ORDER BY r.accessed_at DESC
        LIMIT %s
        """,
        (str(user_id), limit),
    )
