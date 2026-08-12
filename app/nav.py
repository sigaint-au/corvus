"""Sidebar navigation context and team selection helpers."""
import re
from urllib.parse import parse_qs, urlsplit

from flask import session, url_for

import authz
from config import (
    CLIPBOARD_CLEAR_SECONDS,
    MAX_EXPIRY_DAYS,
    REVEAL_AUTO_HIDE_SECONDS,
)
import db
import pins
from settings_svc import branding, classification, team_classification


def nav_teams(user_id: str):
    """List teams visible to the user for the sidebar team switcher.

    Global admins see all teams; others see only teams they belong to.

    Args:
        user_id: UUID of the current user.

    Returns:
        List of team dicts with ``id``, ``name``, and classification columns,
        ordered by name.

    Example:
        >>> teams = nav_teams(session["user_id"])
        >>> for t in teams:
        ...     print(t["name"])
    """
    with db.as_user(user_id) as conn, conn.cursor() as cur:
        if session.get("is_global_admin"):
            cur.execute(
                """
                SELECT t.id, t.name,
                       t.classification_enabled, t.classification_text,
                       t.classification_color, t.classification_fg
                FROM api.teams t ORDER BY t.name
                """
            )
        else:
            # RLS + is_team_member includes direct members and group-based team roles
            cur.execute(
                """
                SELECT t.id, t.name,
                       t.classification_enabled, t.classification_text,
                       t.classification_color, t.classification_fg
                FROM api.teams t
                ORDER BY t.name
                """
            )
        return cur.fetchall()


def active_team_id(teams):
    """Resolve the active team for the session, or clear it if none.

    Uses ``session["team_id"]`` when still a member of that team; otherwise
    picks the first team and stores it. Clears session key if ``teams`` is empty.

    Args:
        teams: Iterable of team dicts with an ``id`` key (from :func:`nav_teams`).

    Returns:
        Active team UUID string, or None if the user has no teams.

    Example:
        >>> tid = active_team_id(teams)
        >>> session["team_id"]  # may be updated
    """
    ids = {str(t["id"]) for t in teams}
    tid = session.get("team_id")
    if tid in ids:
        return tid
    if teams:
        tid = str(teams[0]["id"])
        session["team_id"] = tid
        return tid
    session.pop("team_id", None)
    return None


def ensure_active_team(user_id: str | None = None) -> str | None:
    """Return the active team id, ensuring ``session["team_id"]`` is set.

    List views must call this (not bare ``session.get("team_id")``): the
    sidebar context processor runs *after* the view, so the first visit
    otherwise shows an empty list while the switcher already looks selected.

    Args:
        user_id: User UUID; defaults to ``session["user_id"]``.

    Returns:
        Team UUID string, or None if the user has no teams.
    """
    uid = user_id or session.get("user_id")
    if not uid:
        return None
    try:
        teams = nav_teams(uid)
    except Exception:
        teams = []
    return active_team_id(teams)


_PROJECT_PATH_RE = re.compile(
    r"^/projects/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/.*)?$"
)
_TEAM_PATH_RE = re.compile(
    r"^/teams/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/.*)?$"
)


def _project_team_id(project_id: str) -> str | None:
    """Return team_id for a project (admin connection; no RLS)."""
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT team_id FROM api.projects WHERE id = %s::uuid",
                (project_id,),
            )
            row = cur.fetchone() or {}
            tid = row.get("team_id")
            return str(tid) if tid else None
    except Exception:
        return None


def redirect_after_team_switch(nxt: str | None, team_id: str | None) -> str:
    """Pick a safe redirect after the sidebar team switcher changes team.

    Team-scoped lists (``/secrets``, ``/projects``, …) stay put so content
    reloads for the new team. Project- or team-bound URLs that belong to a
    *different* team are rewritten so the user is not left staring at the
    previous team's project (which looked like "switch does nothing").

    Args:
        nxt: Form ``next`` or referrer path (may include query string).
        team_id: Newly selected team UUID, or None.

    Returns:
        Relative URL path (+ optional query) to redirect to.
    """
    fallback = url_for("projects_list")
    nxt = authz.safe_redirect_target(nxt, fallback)
    if not team_id:
        return nxt

    parts = urlsplit(nxt)
    path = parts.path or ""
    qs = parts.query or ""

    # Team-scoped index pages: keep (session team drives content).
    if path in ("/secrets", "/trash", "/machines", "/projects") or path.startswith(
        "/search"
    ):
        return nxt

    m = _PROJECT_PATH_RE.match(path)
    if m:
        pid = m.group(1)
        rest = m.group(2) or ""
        pteam = _project_team_id(pid)
        if pteam and pteam == str(team_id):
            return nxt
        # Wrong team — land on a list that respects the new session team.
        tab = (parse_qs(qs).get("tab") or [""])[0].strip().lower()
        secrets_like = (
            rest.startswith("/secrets")
            or tab in ("", "secrets")
            or "secret" in rest
        )
        if secrets_like:
            return url_for("secrets_list")
        if tab == "tokens" or "token" in rest:
            return url_for("machines_list")
        return url_for("projects_list")

    m = _TEAM_PATH_RE.match(path)
    if m:
        path_tid = m.group(1)
        if path_tid.lower() != str(team_id).lower():
            return url_for("team_detail", team_id=team_id)
        return nxt

    return nxt


def inject_nav():
    """Flask context processor: template globals for chrome and sidebar.

    Always provides branding, classification banner, clipboard/reveal settings,
    and CSRF token. When logged in and not an HTMX partial request, also loads
    teams, pins, and recent secrets (and may override banner from active team).

    Args:
        None (reads Flask ``session`` and request via helpers).

    Returns:
        Dict of template variables (``app_name``, ``nav_teams``, ``nav_pins``,
        ``csrf_token``, etc.).

    Example:
        >>> # In app factory:
        >>> app.context_processor(inject_nav)
        >>> # Templates use {{ nav_teams }}, {{ classification }}, ...
    """
    banner = classification()
    brand = branding()
    base = {
        "app_name": brand["app_name"],
        "brand_name": brand["brand_name"],
        "brand_tagline": brand["brand_tagline"],
        "classification": banner,
        "is_global_admin": bool(session.get("is_global_admin")),
        "nav_teams": [],
        "nav_team_id": session.get("team_id"),
        "nav_team_name": None,
        "nav_pins": [],
        "nav_recent": [],
        "nav_access_pending": 0,
        "clipboard_clear_seconds": CLIPBOARD_CLEAR_SECONDS,
        "reveal_auto_hide_seconds": REVEAL_AUTO_HIDE_SECONDS,
        "max_expiry_days": MAX_EXPIRY_DAYS,
        "csrf_token": authz.csrf_token(),
    }
    if not session.get("user_id"):
        return base
    # Prefer session flag set at login; only hit DB if missing (legacy sessions).
    if "is_global_admin" not in session:
        session["is_global_admin"] = authz.is_global_admin(session["user_id"])
    base["is_global_admin"] = bool(session.get("is_global_admin"))
    # HTMX partials don't render the sidebar — skip the teams query.
    if authz.htmx():
        return base
    try:
        teams = nav_teams(session["user_id"])
    except Exception:
        teams = []
    base["nav_teams"] = teams
    tid = active_team_id(teams)
    base["nav_team_id"] = tid
    name = None
    active = None
    for t in teams:
        try:
            if str(t["id"]) == tid:
                name = t.get("name") if hasattr(t, "get") else t["name"]
                active = t
                break
        except (KeyError, TypeError):
            continue
    base["nav_team_name"] = name
    # Pending reveal access requests the user can approve (project admin / team owner)
    try:
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT count(*) AS n
                FROM api.secret_access_requests r
                WHERE r.status = 'pending'
                  AND api.can_admin_project(r.project_id)
                """
            )
            base["nav_access_pending"] = int((cur.fetchone() or {}).get("n") or 0)
    except Exception:
        base["nav_access_pending"] = 0
    # Team-level classification: NULL enabled = use server banner; True/False = override
    if active is not None:
        if active is not None and active.get("classification_enabled") is not None:
            # Normalize the team override once, in settings_svc (color fallback etc.)
            base["classification"] = team_classification(active)
    try:
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            base["nav_pins"] = pins.list_pins(cur, session["user_id"])
            base["nav_recent"] = pins.list_recent(cur, session["user_id"])
    except Exception:
        pass
    return base
