"""Database connections and JWT helpers for RLS."""
import json
import time

import jwt
import psycopg
from psycopg.rows import dict_row

from config import DATABASE_ADMIN_URL, DATABASE_URL, JWT_SECRET


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

    Uses ``DATABASE_ADMIN_URL``. Required for settings, lockout, PATs, and
    anything that must bypass RLS or touch ``private.*``.

    Args:
        autocommit: If True (default), each statement commits immediately.

    Returns:
        A ``psycopg.Connection`` with ``dict_row`` factory.

    Example:
        >>> with connect_admin() as conn, conn.cursor() as cur:
        ...     cur.execute("SELECT current_user")
        ...     cur.fetchone()
        {'current_user': 'postgres'}  # or configured admin role
    """
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


def make_jwt(user_id: str, hours=24) -> str:
    """Create an HS256 JWT for PostgREST / API clients.

    Args:
        user_id: UUID string placed in the ``sub`` claim.
        hours: Token lifetime in hours. Defaults to 24.

    Returns:
        Encoded JWT string (``HS256`` with ``JWT_SECRET``).

    Example:
        >>> token = make_jwt("a1b2c3d4-...", hours=1)
        >>> # Authorization: Bearer <token> against PostgREST
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
