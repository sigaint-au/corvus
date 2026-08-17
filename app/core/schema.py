"""Schema bootstrap: apply pending migrations, then promote the bootstrap admin.

Fresh volumes are created by ``docker-entrypoint-initdb.d`` (via
``db/migrations/0001_init.sql``). This module applies any remaining migrations
(``0002_rls_authz_hardening.sql``, …) at startup under a session advisory lock,
then promotes the configured bootstrap admin email (env-driven, not a
migration).
"""

from __future__ import annotations

import logging

from core.config import DATABASE_ADMIN_URL, bootstrap_admin_email
from core import db
from core import migrations

log = logging.getLogger(__name__)

# Session-level advisory lock key for ensure_schema (arbitrary stable int4 pair).
_ENSURE_LOCK_K1 = 834201
_ENSURE_LOCK_K2 = 1


def ensure_schema():
    """Apply pending SQL migrations for this database volume.

    Reads ``db/migrations/*.sql`` and applies any not yet recorded in
    ``private.schema_migrations``, serialized by a session advisory lock so
    concurrent workers cannot race. Requires a superuser DSN via
    ``DATABASE_ADMIN_URL``. After migrations succeed, promotes the bootstrap
    admin email.

    Args:
        None.

    Returns:
        None. Logs success; re-raises on failure after logging.

    Raises:
        RuntimeError: If ``DATABASE_ADMIN_URL`` is not set.
        Exception: Any database error while applying migrations (re-raised).

    Example:
        >>> # ensure_schema()  # call once at app startup
        >>> # schema ensure complete (logged)
    """
    if not DATABASE_ADMIN_URL:
        # Do not fall back to the app/authenticator role — policy DDL would fail
        # and hide misconfiguration. Compose sets DATABASE_ADMIN_URL explicitly.
        raise RuntimeError(
            "DATABASE_ADMIN_URL is not set; schema migrations require a superuser DSN"
        )

    try:
        with db.connect_admin(autocommit=True) as conn, conn.cursor() as cur:
            # Serialize workers so concurrent migrations cannot race across
            # gunicorn processes.
            cur.execute(
                "SELECT pg_advisory_lock(%s, %s)",
                (_ENSURE_LOCK_K1, _ENSURE_LOCK_K2),
            )
            try:
                migrations.apply_pending(cur)
                # Bootstrap: only explicit GLOBAL_ADMIN_EMAIL / BOOTSTRAP_ADMIN_EMAIL
                # (never auto-promote the first registrant — race / takeover risk)
                boot = bootstrap_admin_email()
                if boot:
                    cur.execute(
                        "UPDATE private.users SET is_global_admin = true WHERE email = %s",
                        (boot,),
                    )
            finally:
                cur.execute(
                    "SELECT pg_advisory_unlock(%s, %s)",
                    (_ENSURE_LOCK_K1, _ENSURE_LOCK_K2),
                )
        log.info("schema ensure complete")
    except Exception:
        log.exception("ensure_schema failed")
        raise
