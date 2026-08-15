"""Global search and access-request inbox routes."""

from __future__ import annotations

from flask import (
    render_template,
    request,
    session,
)
from auth import authz
from core import config
from core import db
from ui import paging
from secret_svc.secret_kinds import secret_due_status


@authz.login_required
def global_search():
    """Search teams, projects, and secrets the user can access.

    Overview mode (default): capped previews per section with totals and
    "view all" links. Scoped mode ``?scope=teams|projects|secrets`` returns
    a paginated single-section result set.

    Example:
        GET /search?q=database
        GET /search?q=prod&scope=secrets&kind=database&page=2
    """
    q = (request.args.get("q") or "").strip()
    scope = (request.args.get("scope") or "").strip().lower() or None
    if scope not in ("teams", "projects", "secrets", None):
        scope = None
    page = paging.page_arg()
    kind = (request.args.get("kind") or "").strip() or None
    if kind and kind not in config.SECRET_KINDS:
        kind = None
    due = (request.args.get("due") or "").strip() or None
    if due not in ("overdue", "soon", "none", None):
        due = None

    teams, projects, secrets = [], [], []
    teams_total = projects_total = secrets_total = 0
    preview = {
        "teams": 25,
        "projects": 40,
        "secrets": 50,
    }
    search_pager = None

    if q:
        like = f"%{q}%"
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            if scope in (None, "teams"):
                cur.execute(
                    "SELECT count(*) AS n FROM api.teams WHERE name ILIKE %s",
                    (like,),
                )
                teams_total = int((cur.fetchone() or {}).get("n") or 0)
                if scope == "teams":
                    search_pager = paging.page_window(teams_total, page)
                    search_pager.update(
                        endpoint="global_search", q=q, scope="teams"
                    )
                    cur.execute(
                        """
                        SELECT id, name FROM api.teams
                        WHERE name ILIKE %s
                        ORDER BY name
                        LIMIT %s OFFSET %s
                        """,
                        (like, search_pager["limit"], search_pager["offset"]),
                    )
                    teams = cur.fetchall() or []
                else:
                    cur.execute(
                        """
                        SELECT id, name FROM api.teams
                        WHERE name ILIKE %s
                        ORDER BY name
                        LIMIT %s
                        """,
                        (like, preview["teams"]),
                    )
                    teams = cur.fetchall() or []

            if scope in (None, "projects"):
                cur.execute(
                    """
                    SELECT count(*) AS n FROM api.projects p
                    WHERE p.name ILIKE %s
                    """,
                    (like,),
                )
                projects_total = int((cur.fetchone() or {}).get("n") or 0)
                if scope == "projects":
                    search_pager = paging.page_window(projects_total, page)
                    search_pager.update(
                        endpoint="global_search", q=q, scope="projects"
                    )
                    cur.execute(
                        """
                        SELECT p.id, p.name, p.description,
                               t.name AS team_name, t.id AS team_id
                        FROM api.projects p
                        JOIN api.teams t ON t.id = p.team_id
                        WHERE p.name ILIKE %s
                        ORDER BY t.name, p.name
                        LIMIT %s OFFSET %s
                        """,
                        (like, search_pager["limit"], search_pager["offset"]),
                    )
                    projects = cur.fetchall() or []
                else:
                    cur.execute(
                        """
                        SELECT p.id, p.name, t.name AS team_name, t.id AS team_id
                        FROM api.projects p
                        JOIN api.teams t ON t.id = p.team_id
                        WHERE p.name ILIKE %s
                        ORDER BY t.name, p.name
                        LIMIT %s
                        """,
                        (like, preview["projects"]),
                    )
                    projects = cur.fetchall() or []

            if scope in (None, "secrets"):
                sec_where = """
                  s.deleted_at IS NULL
                  AND (
                    s.key ILIKE %s OR s.note ILIKE %s OR p.name ILIKE %s
                    OR EXISTS (
                      SELECT 1 FROM api.secret_meta m
                      WHERE m.secret_id = s.id
                        AND (m.key ILIKE %s OR m.value ILIKE %s)
                    )
                  )
                """
                sec_params = [like, like, like, like, like]
                if kind:
                    sec_where += " AND s.kind = %s"
                    sec_params.append(kind)
                if due == "overdue":
                    sec_where += (
                        " AND s.expires_at IS NOT NULL AND s.expires_at < now()"
                    )
                elif due == "soon":
                    sec_where += """
                      AND s.expires_at IS NOT NULL
                      AND s.expires_at >= now()
                      AND s.expires_at < now() + interval '14 days'
                    """
                elif due == "none":
                    sec_where += " AND s.expires_at IS NULL"
                cur.execute(
                    f"""
                    SELECT count(*) AS n
                    FROM api.secrets s
                    JOIN api.projects p ON p.id = s.project_id
                    WHERE {sec_where}
                    """,
                    sec_params,
                )
                secrets_total = int((cur.fetchone() or {}).get("n") or 0)
                if scope == "secrets":
                    search_pager = paging.page_window(secrets_total, page)
                    search_pager.update(
                        endpoint="global_search",
                        q=q,
                        scope="secrets",
                        kind=kind,
                        due=due,
                    )
                    lim, off = search_pager["limit"], search_pager["offset"]
                else:
                    lim, off = preview["secrets"], 0
                cur.execute(
                    f"""
                    SELECT s.id, s.key, s.note, s.kind, s.project_id, s.expires_at,
                           p.name AS project_name, t.name AS team_name
                    FROM api.secrets s
                    JOIN api.projects p ON p.id = s.project_id
                    JOIN api.teams t ON t.id = p.team_id
                    WHERE {sec_where}
                    ORDER BY t.name, p.name, s.key
                    LIMIT %s OFFSET %s
                    """,
                    (*sec_params, lim, off),
                )
                secrets = cur.fetchall() or []
                for s in secrets:
                    s["due"] = secret_due_status(s)

    return render_template(
        "search.html",
        search_q=q,
        scope=scope,
        teams=teams,
        projects=projects,
        secrets=secrets,
        teams_total=teams_total,
        projects_total=projects_total,
        secrets_total=secrets_total,
        preview=preview,
        search_pager=search_pager,
        filter_kind=kind,
        filter_due=due,
        secret_kinds=config.SECRET_KINDS,
    )


@authz.login_required
def access_requests_inbox():
    """List pending secret reveal requests the current user can approve.

    Returns:
        Rendered inbox of pending access requests across projects.

    Example:
        GET /access-requests
    """
    rows = []
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM private.pending_access_requests_for_admin()")
        rows = cur.fetchall() or []
    return render_template(
        "access_requests.html",
        requests=rows,
        grant_minutes=config.REVEAL_ACCESS_GRANT_MINUTES,
        grant_choices=config.REVEAL_ACCESS_GRANT_CHOICES,
    )
