"""DB-backed login failure lockout (shared across workers)."""
import logging

import db

log = logging.getLogger(__name__)

MAX_ATTEMPTS = 5
WINDOW = "5 minutes"


def is_locked(email: str) -> bool:
    """Return whether ``email`` is temporarily locked out of login.

    Counts rows in ``private.login_failures`` within the last ``WINDOW``
    (5 minutes). Locked when count >= ``MAX_ATTEMPTS`` (5). On DB errors,
    fails open (returns False) so login is not blocked by infrastructure issues.

    Args:
        email: Login email (normalized to lowercase). Empty string never locks.

    Returns:
        True if the account should be refused login; False otherwise.

    Example:
        >>> if is_locked("user@example.com"):
        ...     flash("Too many failed attempts; try again later")
    """
    email = (email or "").strip().lower()
    if not email:
        return False
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT count(*) AS n FROM private.login_failures
                WHERE email = %s AND created_at > now() - %s::interval
                """,
                (email, WINDOW),
            )
            n = int((cur.fetchone() or {}).get("n") or 0)
            return n >= MAX_ATTEMPTS
    except Exception as e:
        log.warning("lockout check failed: %s", e)
        return False


def record_failure(email: str):
    """Record a failed login attempt for lockout accounting.

    Args:
        email: Login email that failed authentication. Empty values are ignored.

    Returns:
        None. Inserts a row into ``private.login_failures`` (best-effort).

    Example:
        >>> record_failure("user@example.com")
        >>> is_locked("user@example.com")  # after MAX_ATTEMPTS failures
        True
    """
    email = (email or "").strip().lower()
    if not email:
        return
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO private.login_failures (email) VALUES (%s)",
                (email,),
            )
    except Exception as e:
        log.warning("lockout record failed: %s", e)


def clear_failures(email: str):
    """Clear all login failure records for ``email`` after a successful login.

    Args:
        email: Login email that just authenticated successfully.

    Returns:
        None. Deletes matching rows from ``private.login_failures`` (best-effort).

    Example:
        >>> clear_failures("user@example.com")
        >>> is_locked("user@example.com")
        False
    """
    email = (email or "").strip().lower()
    if not email:
        return
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM private.login_failures WHERE email = %s",
                (email,),
            )
    except Exception as e:
        log.warning("lockout clear failed: %s", e)
