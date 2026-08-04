"""DB-backed login failure lockout (shared across workers)."""
import logging

import db

log = logging.getLogger(__name__)

MAX_ATTEMPTS = 5
WINDOW = "5 minutes"


def is_locked(email: str) -> bool:
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
