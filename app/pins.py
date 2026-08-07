"""Per-user secret pins (favorites) and recently accessed."""

from config import SIDEBAR_PINS_LIMIT, SIDEBAR_RECENT_LIMIT


def touch_recent(cur, user_id, secret_id):
    cur.execute(
        """
        INSERT INTO api.secret_recent (user_id, secret_id, accessed_at)
        VALUES (%s, %s, now())
        ON CONFLICT (user_id, secret_id) DO UPDATE SET accessed_at = now()
        """,
        (str(user_id), str(secret_id)),
    )


def is_pinned(cur, user_id, secret_id) -> bool:
    cur.execute(
        """
        SELECT 1 FROM api.secret_pins
        WHERE user_id = %s AND secret_id = %s
        """,
        (str(user_id), str(secret_id)),
    )
    return cur.fetchone() is not None


def pin(cur, user_id, secret_id):
    cur.execute(
        """
        INSERT INTO api.secret_pins (user_id, secret_id)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING
        """,
        (str(user_id), str(secret_id)),
    )


def unpin(cur, user_id, secret_id):
    cur.execute(
        """
        DELETE FROM api.secret_pins
        WHERE user_id = %s AND secret_id = %s
        """,
        (str(user_id), str(secret_id)),
    )


def _secret_rows(cur, sql, params):
    cur.execute(sql, params)
    return cur.fetchall() or []


def list_pins(cur, user_id, limit=SIDEBAR_PINS_LIMIT):
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
