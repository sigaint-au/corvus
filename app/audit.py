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
    """Insert an audit row via SECURITY DEFINER private.audit_secret (no direct INSERT).

    Actor user_id is taken from JWT claims inside the DB function (as_user connections).
    Optional actor_email is only used when there is no JWT user (e.g. machine paths).
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
    """Membership / settings / access-control audit via private.audit_org."""
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


def _parse_day(s: str, *, end: bool = False):
    """Parse YYYY-MM-DD to UTC datetime (start or end of day)."""
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
    """Return (sql_fragment, params) for audit list filters."""
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
    """Human-readable who/what line for an audit row."""
    who = (row.get("actor_email") or "").strip() or "Someone"
    action = row.get("action") or ""
    key = (row.get("secret_key") or "").strip()
    verb = _ACTION_VERB.get(action, action or "acted on")
    if action == "exported":
        detail = f" ({key})" if key else ""
        return f"{who} {verb}{detail}"
    if action == "machine_upsert":
        target = f" “{key}”" if key else " a secret"
        return f"{who} {verb}{target}"
    if key:
        return f"{who} {verb} “{key}”"
    return f"{who} {verb} a secret"


def _as_utc_dt(dt):
    """Coerce datetime/ISO string to timezone-aware UTC, or None."""
    if dt is None:
        return None
    if isinstance(dt, str):
        s = dt.strip()
        if not s:
            return None
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_when(dt) -> str:
    """Compact absolute timestamp for display."""
    d = _as_utc_dt(dt)
    if d is None:
        return "—" if dt is None else str(dt)
    return d.strftime("%Y-%m-%d %H:%M UTC")


def format_time_ago(dt) -> str:
    """Relative time for Updated columns, e.g. '3 hours ago'."""
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
