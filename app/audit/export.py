"""Audit export queries (secret and org)."""

from __future__ import annotations

from .dates import _parse_day


def export_secret_audit(
    cur,
    *,
    since: str = "",
    until: str = "",
    limit: int = 50000,
):
    """Export secret_audit rows for a date range (compliance/export use).

    Args:
        cur: Database cursor used to run the SELECT.
        since: Inclusive start date as YYYY-MM-DD (UTC start of day).
        until: Inclusive end date as YYYY-MM-DD (UTC end of day).
        limit: Maximum number of rows to return (default 50000).

    Returns:
        List of secret_audit row mappings with project/team names joined.

    Example:
        >>> rows = export_secret_audit(cur, since="2026-01-01", until="2026-01-31")
        >>> len(rows) <= 50000
        True
    """
    parts = [" WHERE 1=1 "]
    params: list = []
    since_dt = _parse_day(since, end=False)
    if since_dt:
        parts.append(" AND a.created_at >= %s ")
        params.append(since_dt)
    until_dt = _parse_day(until, end=True)
    if until_dt:
        parts.append(" AND a.created_at <= %s ")
        params.append(until_dt)
    where = "".join(parts)
    cur.execute(
        f"""
        SELECT a.id::text, a.created_at, a.action, a.secret_key, a.actor_email,
               a.project_id::text, p.name AS project_name,
               t.name AS team_name, a.user_id::text,
               a.ip_address, a.user_agent
        FROM api.secret_audit a
        LEFT JOIN api.projects p ON p.id = a.project_id
        LEFT JOIN api.teams t ON t.id = p.team_id
        {where}
        ORDER BY a.created_at DESC
        LIMIT %s
        """,
        (*params, limit),
    )
    return cur.fetchall() or []


def export_org_audit(
    cur,
    *,
    since: str = "",
    until: str = "",
    limit: int = 50000,
):
    """Export org_audit rows for a date range (compliance/export use).

    Args:
        cur: Database cursor used to run the SELECT.
        since: Inclusive start date as YYYY-MM-DD (UTC start of day).
        until: Inclusive end date as YYYY-MM-DD (UTC end of day).
        limit: Maximum number of rows to return (default 50000).

    Returns:
        List of org_audit row mappings with team/project names joined.

    Example:
        >>> rows = export_org_audit(cur, since="2026-01-01", limit=1000)
        >>> isinstance(rows, list)
        True
    """
    parts = [" WHERE 1=1 "]
    params: list = []
    since_dt = _parse_day(since, end=False)
    if since_dt:
        parts.append(" AND a.created_at >= %s ")
        params.append(since_dt)
    until_dt = _parse_day(until, end=True)
    if until_dt:
        parts.append(" AND a.created_at <= %s ")
        params.append(until_dt)
    where = "".join(parts)
    cur.execute(
        f"""
        SELECT a.id::text, a.created_at, a.action, a.detail, a.actor_email,
               a.team_id::text, t.name AS team_name,
               a.project_id::text, p.name AS project_name,
               a.user_id::text, a.ip_address, a.user_agent
        FROM api.org_audit a
        LEFT JOIN api.teams t ON t.id = a.team_id
        LEFT JOIN api.projects p ON p.id = a.project_id
        {where}
        ORDER BY a.created_at DESC
        LIMIT %s
        """,
        (*params, limit),
    )
    return cur.fetchall() or []
