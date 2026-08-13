"""Audit maintenance (purge old rows, table counts)."""

from __future__ import annotations


def purge_old_audit(cur, retention_days: int) -> dict:
    """Delete audit and login-failure rows older than retention_days.

    Args:
        cur: Database cursor used to run DELETE statements.
        retention_days: Keep this many days of history; if <= 0, skip purge.

    Returns:
        Dict with counts deleted for secret_audit, org_audit, and
        login_failures, plus skipped=True when retention_days <= 0.

    Example:
        >>> result = purge_old_audit(cur, retention_days=90)
        >>> result["skipped"]
        False
    """
    if retention_days <= 0:
        return {
            "secret_audit": 0,
            "org_audit": 0,
            "login_failures": 0,
            "skipped": True,
        }
    days = str(int(retention_days))
    cur.execute(
        """
        WITH d AS (
          DELETE FROM api.secret_audit
          WHERE created_at < now() - (%s || ' days')::interval
          RETURNING 1
        )
        SELECT count(*)::int AS n FROM d
        """,
        (days,),
    )
    n_secret = int((cur.fetchone() or {}).get("n") or 0)
    cur.execute(
        """
        WITH d AS (
          DELETE FROM api.org_audit
          WHERE created_at < now() - (%s || ' days')::interval
          RETURNING 1
        )
        SELECT count(*)::int AS n FROM d
        """,
        (days,),
    )
    n_org = int((cur.fetchone() or {}).get("n") or 0)
    n_login = 0
    try:
        cur.execute(
            """
            WITH d AS (
              DELETE FROM private.login_failures
              WHERE created_at < now() - (%s || ' days')::interval
              RETURNING 1
            )
            SELECT count(*)::int AS n FROM d
            """,
            (days,),
        )
        n_login = int((cur.fetchone() or {}).get("n") or 0)
    except Exception:
        # Table may be missing on very old DBs; audit purge still succeeds
        pass
    return {
        "secret_audit": n_secret,
        "org_audit": n_org,
        "login_failures": n_login,
        "skipped": False,
    }


def audit_counts(cur) -> dict:
    """Return row counts and time span for secret and org audit tables.

    Args:
        cur: Database cursor used to run the COUNT and MIN/MAX queries.

    Returns:
        Dict with secret_audit and org_audit counts, plus oldest and newest
        created_at across both tables (or None if empty).

    Example:
        >>> stats = audit_counts(cur)
        >>> "secret_audit" in stats and "org_audit" in stats
        True
    """
    cur.execute("SELECT count(*)::int AS n FROM api.secret_audit")
    n_secret = int((cur.fetchone() or {}).get("n") or 0)
    cur.execute("SELECT count(*)::int AS n FROM api.org_audit")
    n_org = int((cur.fetchone() or {}).get("n") or 0)
    cur.execute(
        """
        SELECT min(created_at) AS oldest, max(created_at) AS newest
        FROM (
          SELECT created_at FROM api.secret_audit
          UNION ALL
          SELECT created_at FROM api.org_audit
        ) x
        """
    )
    span = cur.fetchone() or {}
    return {
        "secret_audit": n_secret,
        "org_audit": n_org,
        "oldest": span.get("oldest"),
        "newest": span.get("newest"),
    }
