"""Database connections and JWT helpers for RLS.

Uses ``psycopg_pool.ConnectionPool`` for admin connections (reduces per-request
overhead). User-context connections (``as_user``) remain direct because each
checkout needs ``SET ROLE`` + JWT claims that must be reset on return.
"""

import json
import time

import jwt
import psycopg
from psycopg.rows import dict_row

from core.config import DATABASE_ADMIN_URL, DATABASE_URL, JWT_SECRET

# ── Connection pools (admin only; user connections stay direct) ──────────
_admin_pool = None
_admin_pool_opened = False

try:
    from psycopg_pool import ConnectionPool

    if DATABASE_ADMIN_URL:
        _admin_pool = ConnectionPool(
            DATABASE_ADMIN_URL,
            min_size=1,
            max_size=5,
            kwargs={"row_factory": dict_row},
            open=False,
        )
except ImportError:
    pass


def _ensure_admin_pool():
    """Lazily open the admin pool on first use (avoids connecting at import)."""
    global _admin_pool_opened
    if _admin_pool is not None and not _admin_pool_opened:
        _admin_pool.open()
        _admin_pool_opened = True
    return _admin_pool


def close_pools():
    """Close all connection pools (call on app shutdown).

    Example:
        >>> close_pools()
    """
    global _admin_pool, _admin_pool_opened
    if _admin_pool is not None:
        _admin_pool.close()
        _admin_pool = None
        _admin_pool_opened = False


def connect(autocommit=False):
    """Open a connection as the app ``authenticator`` role (``DATABASE_URL``).

    Rows are returned as dicts. Use for PostgREST-style access; prefer
    :func:`as_user` when RLS must run as a specific user.

    Args:
        autocommit: If True, each statement commits immediately. Defaults to
            False (transactional).

    Returns:
        A ``psycopg.Connection`` with ``dict_row`` factory.

    Example:
        >>> with connect() as conn, conn.cursor() as cur:
        ...     cur.execute("SELECT 1 AS n")
        ...     cur.fetchone()
        {'n': 1}
    """
    return psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=autocommit)


def connect_admin(autocommit=True):
    """Open a superuser connection for schema upgrades and private schema work.

    Uses ``DATABASE_ADMIN_URL``. When ``psycopg_pool`` is installed, reuses
    a pooled connection (reduces per-request overhead). Required for settings,
    lockout, PATs, and anything that must bypass RLS or touch ``private.*``.

    Args:
        autocommit: If True (default), each statement commits immediately.

    Returns:
        A ``psycopg.Connection`` (or pooled connection) with ``dict_row`` factory.

    Example:
        >>> with connect_admin() as conn, conn.cursor() as cur:
        ...     cur.execute("SELECT current_user")
        ...     cur.fetchone()
        {'current_user': 'postgres'}
    """
    pool = _ensure_admin_pool()
    if pool is not None:
        conn = pool.connection()
        conn.autocommit = autocommit
        return conn
    return psycopg.connect(DATABASE_ADMIN_URL, row_factory=dict_row, autocommit=autocommit)


def as_user(user_id: str):
    """Open a connection with JWT claims set so RLS matches PostgREST.

    Sets role to ``authenticated`` and ``request.jwt.claims`` with ``sub``
    equal to ``user_id``, so ``api.current_user_id()`` and policies apply.

    Args:
        user_id: UUID string of the logged-in user (session ``user_id``).

    Returns:
        An open ``psycopg.Connection`` configured for that user's RLS context.
        Caller must close it (use as a context manager).

    Example:
        >>> with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        ...     cur.execute("SELECT * FROM api.teams")
        ...     teams = cur.fetchall()
    """
    conn = connect()
    claims = {"sub": str(user_id), "role": "authenticated"}
    with conn.cursor() as cur:
        cur.execute("SET ROLE authenticated")
        cur.execute(
            "SELECT set_config('request.jwt.claims', %s, false)",
            (json.dumps(claims),),
        )
    return conn


def team(cur, team_id):
    """Load a team row by id under the current cursor's RLS context.

    Args:
        cur: Open DB cursor (user RLS).
        team_id: Team UUID.

    Returns:
        Team row dict (all columns) or None when the team is not visible.
    """
    cur.execute("SELECT * FROM api.teams WHERE id = %s", (str(team_id),))
    return cur.fetchone()


def make_jwt(user_id: str, hours=1) -> str:
    """Create an HS256 JWT for PostgREST / API clients.

    Short default TTL so a disabled/revoked user loses API access within
    at most one hour (a stateless JWT cannot be revoked server-side).

    Args:
        user_id: UUID string placed in the ``sub`` claim.
        hours: Token lifetime in hours. Defaults to 1.

    Returns:
        Encoded JWT string (``HS256`` with ``JWT_SECRET``).

    Example:
        >>> token = make_jwt("a1b2c3d4-...", hours=1)
        >>> isinstance(token, str) and len(token) > 20
        True
    """
    return jwt.encode(
        {
            "sub": str(user_id),
            "role": "authenticated",
            "exp": int(time.time()) + hours * 3600,
        },
        JWT_SECRET,
        algorithm="HS256",
    )
