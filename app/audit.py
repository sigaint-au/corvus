"""Secret and org (membership/settings) audit logging."""

from datetime import datetime, time, timezone

from flask import session

# Actions written to api.secret_audit.action (must match DB CHECK + private.audit_secret)
ACTIONS = (
    "created",
    "updated",
    "revealed",
    "deleted",
    "restored",
    "purged",
    "machine_upsert",
    "exported",
    "access_requested",
    "access_approved",
    "access_denied",
)

# Common org_audit.action values (free text; these are conventions)
ORG_MEMBER_ADD = "member_add"
ORG_MEMBER_REMOVE = "member_remove"
ORG_MEMBER_ROLE = "member_role"
ORG_OWNERSHIP = "ownership_transfer"
ORG_INVITE_CREATE = "invite_create"
ORG_INVITE_REVOKE = "invite_revoke"
ORG_JOIN_REQUEST = "join_request"
ORG_JOIN_APPROVE = "join_approve"
ORG_JOIN_REJECT = "join_reject"
ORG_LDAP_MAP_ADD = "ldap_map_add"
ORG_LDAP_MAP_DELETE = "ldap_map_delete"
ORG_OIDC_MAP_ADD = "oidc_map_add"
ORG_OIDC_MAP_DELETE = "oidc_map_delete"
ORG_TEAM_SETTINGS = "team_settings"
ORG_PROJECT_MEMBER_ADD = "project_member_add"
ORG_PROJECT_MEMBER_REMOVE = "project_member_remove"
ORG_PROJECT_MEMBER_ROLE = "project_member_role"

_ACTION_VERB = {
    "created": "created",
    "updated": "updated",
    "revealed": "revealed",
    "deleted": "deleted",
    "restored": "restored",
    "purged": "permanently deleted",
    "machine_upsert": "upserted via machine token",
    "exported": "exported secrets",
    "access_requested": "requested access to",
    "access_approved": "approved access to",
    "access_denied": "denied access to",
}

# Special per-action sentence shapes for describe_event.
_EVENT_FORMATS = {
    "exported": lambda who, verb, key: f"{who} {verb}" + (f" ({key})" if key else ""),
    "machine_upsert": lambda who, verb, key: (
        f"{who} {verb} “{key}”" if key else f"{who} {verb} a secret"
    ),
}


def log_secret(
    cur,
    *,
    project_id,
    action: str,
    secret_key: str = "",
    secret_id=None,
    actor_email: str | None = None,
):
    """Insert a secret audit row via private.audit_secret.

    Actor user_id is taken from JWT claims inside the DB function (as_user
    connections). Optional actor_email is only used when there is no JWT user
    (e.g. machine paths).

    Args:
        cur: Database cursor used to execute the audit insert.
        project_id: UUID of the project the secret belongs to.
        action: Audit action name; must be one of ACTIONS.
        secret_key: Human-readable secret key/name (default empty).
        secret_id: Optional UUID of the secret row.
        actor_email: Optional actor email override; defaults to session email.

    Returns:
        None. The audit row is written via a side-effect SQL call.

    Example:
        >>> log_secret(cur, project_id=pid, action="created", secret_key="API_KEY")
    """
    if action not in ACTIONS:
        raise ValueError(f"invalid audit action: {action}")
    # p_user_id is ignored by private.audit_secret; pass NULL for clarity.
    email = actor_email if actor_email is not None else (session.get("email") or "")
    cur.execute(
        """
        SELECT private.audit_secret(
          %s::uuid, %s::uuid, %s, %s, NULL::uuid, %s
        )
        """,
        (
            str(project_id),
            str(secret_id) if secret_id else None,
            secret_key or "",
            action,
            email or "",
        ),
    )


def log_org(
    cur,
    *,
    action: str,
    detail: str = "",
    team_id=None,
    project_id=None,
    actor_email: str | None = None,
):
    """Insert a membership/settings audit row via private.audit_org.

    Args:
        cur: Database cursor used to execute the audit insert.
        action: Org audit action string (e.g. ORG_MEMBER_ADD); required.
        detail: Free-text detail about the change (default empty).
        team_id: Optional team UUID related to the event.
        project_id: Optional project UUID related to the event.
        actor_email: Optional actor email override; defaults to session email.

    Returns:
        None. The audit row is written via a side-effect SQL call.

    Example:
        >>> log_org(cur, action=ORG_MEMBER_ADD, detail="user@ex.com as member", team_id=tid)
    """
    if not action:
        raise ValueError("org audit action required")
    email = actor_email if actor_email is not None else (session.get("email") or "")
    cur.execute(
        """
        SELECT private.audit_org(
          %s::uuid, %s::uuid, %s, %s, %s
        )
        """,
        (
            str(team_id) if team_id else None,
            str(project_id) if project_id else None,
            action,
            detail or "",
            email or "",
        ),
    )


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
        SELECT id, team_id, project_id, action, detail, actor_email, created_at
        FROM api.org_audit
        WHERE team_id = %s
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (str(team_id), limit),
    )
    return cur.fetchall()


# Org actions that represent access / role changes (for access reviews)
ROLE_CHANGE_ACTIONS = (
    ORG_MEMBER_ADD,
    ORG_MEMBER_REMOVE,
    ORG_MEMBER_ROLE,
    ORG_OWNERSHIP,
    ORG_INVITE_CREATE,
    ORG_INVITE_REVOKE,
    ORG_JOIN_APPROVE,
    ORG_JOIN_REJECT,
    ORG_LDAP_MAP_ADD,
    ORG_LDAP_MAP_DELETE,
    ORG_OIDC_MAP_ADD,
    ORG_OIDC_MAP_DELETE,
    ORG_PROJECT_MEMBER_ADD,
    ORG_PROJECT_MEMBER_REMOVE,
    ORG_PROJECT_MEMBER_ROLE,
)


def access_review_rows(cur) -> list[dict]:
    """Build a membership matrix for SOC2-style access reviews.

    One row per explicit grant: global admin, team role, or project role.
    Uses admin connection (caller must bypass RLS).

    Args:
        cur: Database cursor (admin connection recommended to bypass RLS).

    Returns:
        List of dicts, each describing one access grant with keys such as
        user_id, email, name, is_global_admin, disabled, scope, team,
        team_role, project, project_role, and access_via.

    Example:
        >>> matrix = access_review_rows(cur)
        >>> matrix[0]["scope"]
        'global'
    """
    rows: list[dict] = []
    cur.execute(
        """
        SELECT id::text AS user_id, email, name, is_global_admin,
               disabled_at IS NOT NULL AS disabled
        FROM private.users
        WHERE is_global_admin
        ORDER BY email
        """
    )
    for r in cur.fetchall() or []:
        rows.append(
            {
                "user_id": r["user_id"],
                "email": r["email"],
                "name": r["name"] or "",
                "is_global_admin": True,
                "disabled": bool(r["disabled"]),
                "scope": "global",
                "team": "",
                "team_role": "",
                "project": "",
                "project_role": "",
                "access_via": "global_admin",
            }
        )
    cur.execute(
        """
         SELECT u.id::text AS user_id, u.email, u.name, u.is_global_admin,
                u.disabled_at IS NOT NULL AS disabled,
                t.name AS team_name,
                r.name AS team_role
         FROM rbac.bindings b
         JOIN rbac.roles r ON r.id = b.role_id
         JOIN private.users u ON u.id = b.subject_id
         JOIN api.teams t ON t.id = b.scope_id
         WHERE b.subject_kind = 'User' AND b.scope_kind = 'team'
           AND r.name IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')
         ORDER BY u.email, t.name
        """
    )
    for r in cur.fetchall() or []:
        rows.append(
            {
                "user_id": r["user_id"],
                "email": r["email"],
                "name": r["name"] or "",
                "is_global_admin": bool(r["is_global_admin"]),
                "disabled": bool(r["disabled"]),
                "scope": "team",
                "team": r["team_name"] or "",
                "team_role": r["team_role"] or "",
                "project": "",
                "project_role": "",
                "access_via": f"team:{r['team_role']}",
            }
        )
    cur.execute(
        """
         SELECT u.id::text AS user_id, u.email, u.name, u.is_global_admin,
                u.disabled_at IS NOT NULL AS disabled,
                t.name AS team_name, p.name AS project_name,
                r.name AS project_role
         FROM rbac.bindings b
         JOIN rbac.roles r ON r.id = b.role_id
         JOIN private.users u ON u.id = b.subject_id
         JOIN api.projects p ON p.id = b.scope_id
         JOIN api.teams t ON t.id = p.team_id
         WHERE b.subject_kind = 'User' AND b.scope_kind = 'project'
           AND r.name IN ('project-admin', 'project-write', 'project-reveal', 'project-read')
         ORDER BY u.email, t.name, p.name
        """
    )
    for r in cur.fetchall() or []:
        rows.append(
            {
                "user_id": r["user_id"],
                "email": r["email"],
                "name": r["name"] or "",
                "is_global_admin": bool(r["is_global_admin"]),
                "disabled": bool(r["disabled"]),
                "scope": "project",
                "team": r["team_name"] or "",
                "team_role": "",
                "project": r["project_name"] or "",
                "project_role": r["project_role"] or "",
                "access_via": f"project:{r['project_role']}",
            }
        )
    return rows


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
    where = "".join(parts)
    cur.execute(
        f"""
        SELECT a.id, a.team_id, a.project_id, a.action, a.detail,
               a.actor_email, a.user_id, a.created_at,
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
    where = "".join(parts)
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
               t.name AS team_name, a.user_id::text
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
               a.user_id::text
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


def _parse_day(s: str, *, end: bool = False):
    """Parse YYYY-MM-DD to a UTC datetime at start or end of day.

    Args:
        s: Date string; first 10 characters are parsed as YYYY-MM-DD.
        end: If True, return 23:59:59.999999 UTC; else 00:00:00 UTC.

    Returns:
        Timezone-aware UTC datetime, or None if s is empty/invalid.

    Example:
        >>> _parse_day("2026-08-08", end=False).hour
        0
        >>> _parse_day("bad") is None
        True
    """
    s = (s or "").strip()
    if not s:
        return None
    try:
        d = datetime.strptime(s[:10], "%Y-%m-%d").date()
    except ValueError:
        return None
    t = time(23, 59, 59, 999999) if end else time(0, 0, 0)
    return datetime.combine(d, t, tzinfo=timezone.utc)


def _filter_clause(
    q: str = "",
    actor: str = "",
    action: str = "",
    since: str = "",
    until: str = "",
):
    """Build SQL fragment and params for secret audit list filters.

    Args:
        q: Free-text ILIKE filter on secret_key, action, and actor_email.
        actor: Substring filter on actor_email (case-insensitive).
        action: Exact action filter; only applied if action is in ACTIONS.
        since: Inclusive start date as YYYY-MM-DD (UTC start of day).
        until: Inclusive end date as YYYY-MM-DD (UTC end of day).

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
    since_dt = _parse_day(since, end=False)
    if since_dt:
        parts.append(" AND a.created_at >= %s ")
        params.append(since_dt)
    until_dt = _parse_day(until, end=True)
    if until_dt:
        parts.append(" AND a.created_at <= %s ")
        params.append(until_dt)
    return "".join(parts), params


def describe_event(row) -> str:
    """Build a human-readable who/what line for a secret audit row.

    Args:
        row: Mapping with optional keys actor_email, action, and secret_key.

    Returns:
        Sentence describing the actor and action, e.g.
        'alice@ex.com created “API_KEY”'.

    Example:
        >>> describe_event({"actor_email": "a@x.com", "action": "created", "secret_key": "K"})
        'a@x.com created “K”'
    """
    who = (row.get("actor_email") or "").strip() or "Someone"
    action = row.get("action") or ""
    key = (row.get("secret_key") or "").strip()
    verb = _ACTION_VERB.get(action, action or "acted on")
    formatter = _EVENT_FORMATS.get(action)
    if formatter:
        return formatter(who, verb, key)
    return f"{who} {verb} " + (f"“{key}”" if key else "a secret")


def _as_utc_dt(dt):
    """Coerce a datetime or ISO string to timezone-aware UTC (delegates to lib)."""
    from lib.datetime_utils import coerce_utc

    return coerce_utc(dt)


def format_when(dt) -> str:
    """Format a timestamp as a compact absolute UTC display string.

    Args:
        dt: Datetime, ISO string, or None to format.

    Returns:
        String like '2026-08-08 12:00 UTC', '—' for None, or str(dt)
        if unparseable.

    Example:
        >>> format_when(None)
        '—'
    """
    d = _as_utc_dt(dt)
    if d is None:
        return "—" if dt is None else str(dt)
    return d.strftime("%Y-%m-%d %H:%M UTC")


def format_expires(dt, *, prefix: bool = True) -> str:
    """Format an expiry time as a human-friendly relative string.

    Args:
        dt: Expiry datetime or ISO string; empty result if missing/invalid.
        prefix: If True, prefix with 'expires'/'expired'; if False, omit
            the leading word for future dates far out, still include it
            for past relative forms as implemented.

    Returns:
        Human-friendly expiry string such as
        'expires in 3 days (10 Aug 2026)', or empty string if dt is invalid.

    Example:
        >>> format_expires(None)
        ''
    """
    d = _as_utc_dt(dt)
    if d is None:
        return ""
    now = datetime.now(timezone.utc)
    sec = int((d - now).total_seconds())
    abs_when = d.strftime("%d %b %Y")
    if sec < 0:
        past = -sec
        if past < 60:
            rel = "just now"
        elif past < 3600:
            n = max(1, past // 60)
            rel = f"{n} minute{'s' if n != 1 else ''} ago"
        elif past < 86400:
            n = max(1, past // 3600)
            rel = f"{n} hour{'s' if n != 1 else ''} ago"
        elif past < 86400 * 30:
            n = max(1, past // 86400)
            rel = f"{n} day{'s' if n != 1 else ''} ago"
        else:
            return f"expired {abs_when}" if prefix else abs_when
        body = f"{rel} ({abs_when})"
        return f"expired {body}" if prefix else f"expired {body}"
    if sec < 60:
        rel = "in under a minute"
    elif sec < 3600:
        n = max(1, sec // 60)
        rel = f"in {n} minute{'s' if n != 1 else ''}"
    elif sec < 86400:
        n = max(1, sec // 3600)
        rel = f"in {n} hour{'s' if n != 1 else ''}"
    elif sec < 86400 * 30:
        n = max(1, sec // 86400)
        rel = f"in {n} day{'s' if n != 1 else ''}"
    elif sec < 86400 * 365:
        n = max(1, sec // (86400 * 30))
        rel = f"in {n} month{'s' if n != 1 else ''}"
    else:
        return f"expires {abs_when}" if prefix else abs_when
    body = f"{rel} ({abs_when})"
    return f"expires {body}" if prefix else body


def format_time_ago(dt) -> str:
    """Format a timestamp as relative time for Updated columns.

    Args:
        dt: Datetime or ISO string representing a past (or slightly future) time.

    Returns:
        Relative string such as '3 hours ago', 'just now', absolute format
        for future/clock-skew, or '—' for None.

    Example:
        >>> format_time_ago(None)
        '—'
    """
    d = _as_utc_dt(dt)
    if d is None:
        return "—" if dt is None else str(dt)
    now = datetime.now(timezone.utc)
    sec = int((now - d).total_seconds())
    if sec < 0:
        # Clock skew / future stamp — fall back to absolute
        return format_when(d)
    if sec < 45:
        return "just now"
    if sec < 90:
        return "1 minute ago"
    if sec < 3600:
        n = sec // 60
        return f"{n} minutes ago"
    if sec < 5400:
        return "1 hour ago"
    if sec < 86400:
        n = sec // 3600
        return f"{n} hours ago"
    if sec < 86400 * 2:
        return "1 day ago"
    if sec < 86400 * 30:
        n = sec // 86400
        return f"{n} days ago"
    if sec < 86400 * 45:
        return "1 month ago"
    if sec < 86400 * 365:
        n = sec // (86400 * 30)
        return f"{n} months ago"
    if sec < 86400 * 365 * 2:
        return "1 year ago"
    n = sec // (86400 * 365)
    return f"{n} years ago"


def count_for_project(
    cur,
    project_id,
    q: str = "",
    actor: str = "",
    action: str = "",
    since: str = "",
    until: str = "",
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

    Returns:
        Integer count of matching secret_audit rows for the project.

    Example:
        >>> n = count_for_project(cur, project_id, action="revealed")
        >>> n >= 0
        True
    """
    extra, params = _filter_clause(q=q, actor=actor, action=action, since=since, until=until)
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

    Returns:
        List of secret_audit row mappings with summary (from describe_event)
        and when_display (from format_when) added.

    Example:
        >>> rows = list_for_project(cur, project_id, limit=10)
        >>> "summary" in rows[0] and "when_display" in rows[0]
        True
    """
    extra, params = _filter_clause(q=q, actor=actor, action=action, since=since, until=until)
    cur.execute(
        f"""
        SELECT a.id, a.secret_id, a.secret_key, a.action, a.created_at,
               a.actor_email, a.user_id,
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
