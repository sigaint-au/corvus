"""Secret and org (membership/settings) audit logging."""

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


def _search_clause(q: str):
    """Return (sql_fragment, params) for optional audit search."""
    q = (q or "").strip()
    if not q:
        return "", []
    like = f"%{q}%"
    return (
        """
        AND (
          a.secret_key ILIKE %s
          OR a.action ILIKE %s
          OR a.actor_email ILIKE %s
        )
        """,
        [like, like, like],
    )


def count_for_project(cur, project_id, q: str = "") -> int:
    extra, params = _search_clause(q)
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


def list_for_project(cur, project_id, limit=25, offset=0, q: str = ""):
    extra, params = _search_clause(q)
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
    return cur.fetchall()
