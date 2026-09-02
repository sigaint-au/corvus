"""Read-side audit queries (org and secret listing/counting)."""

from __future__ import annotations

from .constants import ACTIONS, describe_event
from .dates import _parse_day, format_when


def list_org_for_team(cur, team_id, limit=40):
    """List recent org audit rows for a single team.

    Args:
        cur: Database cursor used to run the SELECT.
        team_id: UUID of the team whose audit rows to return.
        limit: Maximum number of rows to return (default 40).

    Returns:
        Sequence of org_audit row mappings ordered by created_at descending.

    Example:
        >>> rows = list_org_for_team(cur, team_id, limit=20)
        >>> rows[0]["action"]
        'member_add'
    """
    cur.execute(
        """
        SELECT id, team_id, project_id, action, detail, actor_email, created_at,
               ip_address, user_agent
        FROM api.org_audit
        WHERE team_id = %s
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (str(team_id), limit),
    )
    return cur.fetchall()


def _org_audit_where(
    *,
    actions: tuple[str, ...] | None = None,
    q: str = "",
    actor: str = "",
    since: str = "",
    until: str = "",
) -> tuple[str, list]:
    """Build the shared WHERE clause + params for org_audit list/count queries.

    Used by both :func:`list_org_audit` and :func:`count_org_audit` so the
    filter logic lives in one place. Returns a full ``WHERE ...`` fragment
    (starting with ``WHERE 1=1``) and the bound parameter list.
    """
    parts = [" WHERE 1=1 "]
    params: list = []
    if actions:
        parts.append(" AND a.action = ANY(%s) ")
        params.append(list(actions))
    q = (q or "").strip()
    if q:
        like = f"%{q}%"
        parts.append(
            """
            AND (
              a.action ILIKE %s OR a.detail ILIKE %s OR a.actor_email ILIKE %s
              OR t.name ILIKE %s OR p.name ILIKE %s
            )
            """
        )
        params.extend([like, like, like, like, like])
    actor = (actor or "").strip()
    if actor:
        parts.append(" AND a.actor_email ILIKE %s ")
        params.append(f"%{actor}%")
    since_dt = _parse_day(since, end=False)
    if since_dt:
        parts.append(" AND a.created_at >= %s ")
        params.append(since_dt)
    until_dt = _parse_day(until, end=True)
    if until_dt:
        parts.append(" AND a.created_at <= %s ")
        params.append(until_dt)
    return "".join(parts), params


def list_org_audit(
    cur,
    *,
    actions: tuple[str, ...] | None = None,
    q: str = "",
    actor: str = "",
    since: str = "",
    until: str = "",
    limit: int = 100,
    offset: int = 0,
):
    """List org_audit rows with optional filters and display fields.

    Admin connection recommended for full visibility.

    Args:
        cur: Database cursor used to run the SELECT.
        actions: Optional tuple of action names to restrict results to.
        q: Free-text search across action, detail, actor, team, and project.
        actor: Substring filter on actor_email (case-insensitive).
        since: Inclusive start date as YYYY-MM-DD (UTC start of day).
        until: Inclusive end date as YYYY-MM-DD (UTC end of day).
        limit: Maximum number of rows to return (default 100).
        offset: Number of rows to skip for pagination (default 0).

    Returns:
        List of org_audit row mappings including team_name, project_name,
        and when_display (formatted created_at).

    Example:
        >>> rows = list_org_audit(cur, actions=(ORG_MEMBER_ADD,), limit=10)
        >>> "when_display" in rows[0]
        True
    """
    where, params = _org_audit_where(
        actions=actions, q=q, actor=actor, since=since, until=until
    )
    cur.execute(
        f"""
        SELECT a.id, a.team_id, a.project_id, a.action, a.detail,
               a.actor_email, a.user_id, a.created_at,
               a.ip_address, a.user_agent,
               t.name AS team_name, p.name AS project_name
        FROM api.org_audit a
        LEFT JOIN api.teams t ON t.id = a.team_id
        LEFT JOIN api.projects p ON p.id = a.project_id
        {where}
        ORDER BY a.created_at DESC
        LIMIT %s OFFSET %s
        """,
        (*params, limit, offset),
    )
    rows = cur.fetchall() or []
    for r in rows:
        r["when_display"] = format_when(r.get("created_at"))
    return rows


def count_org_audit(
    cur,
    *,
    actions: tuple[str, ...] | None = None,
    q: str = "",
    actor: str = "",
    since: str = "",
    until: str = "",
) -> int:
    """Count org_audit rows matching the same filters as list_org_audit.

    Args:
        cur: Database cursor used to run the COUNT query.
        actions: Optional tuple of action names to restrict the count to.
        q: Free-text search across action, detail, actor, team, and project.
        actor: Substring filter on actor_email (case-insensitive).
        since: Inclusive start date as YYYY-MM-DD (UTC start of day).
        until: Inclusive end date as YYYY-MM-DD (UTC end of day).

    Returns:
        Integer count of matching org_audit rows.

    Example:
        >>> n = count_org_audit(cur, actor="admin@example.com")
        >>> isinstance(n, int)
        True
    """
    where, params = _org_audit_where(
        actions=actions, q=q, actor=actor, since=since, until=until
    )
    cur.execute(
        f"""
        SELECT count(*) AS n
        FROM api.org_audit a
        LEFT JOIN api.teams t ON t.id = a.team_id
        LEFT JOIN api.projects p ON p.id = a.project_id
        {where}
        """,
        params,
    )
    return int((cur.fetchone() or {}).get("n") or 0)


def _filter_clause(
    q: str = "",
    actor: str = "",
    action: str = "",
    since: str = "",
    until: str = "",
    ip: str = "",
    hide_reveals: bool = False,
):
    """Build SQL fragment and params for secret audit list filters.

    Args:
        q: Free-text ILIKE filter on secret_key, action, and actor_email.
        actor: Substring filter on actor_email (case-insensitive).
        action: Exact action filter; only applied if action is in ACTIONS.
        since: Inclusive start date as YYYY-MM-DD (UTC start of day).
        until: Inclusive end date as YYYY-MM-DD (UTC end of day).
        ip: Substring filter on ip_address (case-insensitive).
        hide_reveals: When True, exclude 'revealed' rows (noise filter).

    Returns:
        Tuple of (sql_fragment, params) where sql_fragment is AND-clauses
        to append after WHERE, and params is the bound parameter list.

    Example:
        >>> clause, params = _filter_clause(action="created", actor="alice")
        >>> "a.action" in clause and len(params) >= 1
        True
    """
    parts = []
    params = []
    q = (q or "").strip()
    if q:
        like = f"%{q}%"
        parts.append(
            """
            AND (
              a.secret_key ILIKE %s
              OR a.action ILIKE %s
              OR a.actor_email ILIKE %s
            )
            """
        )
        params.extend([like, like, like])
    actor = (actor or "").strip()
    if actor:
        parts.append(" AND a.actor_email ILIKE %s ")
        params.append(f"%{actor}%")
    action = (action or "").strip()
    if action and action in ACTIONS:
        parts.append(" AND a.action = %s ")
        params.append(action)
    ip = (ip or "").strip()
    if ip:
        parts.append(" AND a.ip_address ILIKE %s ")
        params.append(f"%{ip}%")
    if hide_reveals:
        parts.append(" AND a.action <> 'revealed' ")
    since_dt = _parse_day(since, end=False)
    if since_dt:
        parts.append(" AND a.created_at >= %s ")
        params.append(since_dt)
    until_dt = _parse_day(until, end=True)
    if until_dt:
        parts.append(" AND a.created_at <= %s ")
        params.append(until_dt)
    return "".join(parts), params


def count_for_project(
    cur,
    project_id,
    q: str = "",
    actor: str = "",
    action: str = "",
    since: str = "",
    until: str = "",
    ip: str = "",
    hide_reveals: bool = False,
) -> int:
    """Count secret_audit rows for a project with optional filters.

    Args:
        cur: Database cursor used to run the COUNT query.
        project_id: UUID of the project to count audit rows for.
        q: Free-text filter on secret_key, action, and actor_email.
        actor: Substring filter on actor_email (case-insensitive).
        action: Exact action filter if it is a known ACTIONS value.
        since: Inclusive start date as YYYY-MM-DD (UTC start of day).
        until: Inclusive end date as YYYY-MM-DD (UTC end of day).
        ip: Substring filter on ip_address (case-insensitive).
        hide_reveals: When True, exclude 'revealed' rows (noise filter).

    Returns:
        Integer count of matching secret_audit rows for the project.

    Example:
        >>> n = count_for_project(cur, project_id, action="revealed")
        >>> n >= 0
        True
    """
    extra, params = _filter_clause(
        q=q, actor=actor, action=action, since=since, until=until,
        ip=ip, hide_reveals=hide_reveals,
    )
    cur.execute(
        f"""
        SELECT count(*) AS n
        FROM api.secret_audit a
        WHERE a.project_id = %s
        {extra}
        """,
        (str(project_id), *params),
    )
    row = cur.fetchone() or {}
    return int(row.get("n") or 0)


def list_for_project(
    cur,
    project_id,
    limit=25,
    offset=0,
    q: str = "",
    actor: str = "",
    action: str = "",
    since: str = "",
    until: str = "",
    ip: str = "",
    hide_reveals: bool = False,
):
    """List secret_audit rows for a project with filters and display fields.

    Args:
        cur: Database cursor used to run the SELECT.
        project_id: UUID of the project whose audit rows to return.
        limit: Maximum number of rows to return (default 25).
        offset: Number of rows to skip for pagination (default 0).
        q: Free-text filter on secret_key, action, and actor_email.
        actor: Substring filter on actor_email (case-insensitive).
        action: Exact action filter if it is a known ACTIONS value.
        since: Inclusive start date as YYYY-MM-DD (UTC start of day).
        until: Inclusive end date as YYYY-MM-DD (UTC end of day).
        ip: Substring filter on ip_address (case-insensitive).
        hide_reveals: When True, exclude 'revealed' rows (noise filter).

    Returns:
        List of secret_audit row mappings with summary (from describe_event)
        and when_display (from format_when) added.

    Example:
        >>> rows = list_for_project(cur, project_id, limit=10)
        >>> "summary" in rows[0] and "when_display" in rows[0]
        True
    """
    extra, params = _filter_clause(
        q=q, actor=actor, action=action, since=since, until=until,
        ip=ip, hide_reveals=hide_reveals,
    )
    cur.execute(
        f"""
        SELECT a.id, a.secret_id, a.secret_key, a.action, a.created_at,
               a.actor_email, a.user_id,
               a.ip_address, a.user_agent,
               a.actor_email AS actor_name
        FROM api.secret_audit a
        WHERE a.project_id = %s
        {extra}
        ORDER BY a.created_at DESC
        LIMIT %s OFFSET %s
        """,
        (str(project_id), *params, limit, offset),
    )
    rows = cur.fetchall()
    for r in rows:
        r["summary"] = describe_event(r)
        r["when_display"] = format_when(r.get("created_at"))
    return rows
