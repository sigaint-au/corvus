"""Sidebar navigation context and team selection helpers."""
from flask import session

import authz
from config import (
    CLIPBOARD_CLEAR_SECONDS,
    MAX_EXPIRY_DAYS,
    REVEAL_AUTO_HIDE_SECONDS,
)
import db
import pins
from settings_svc import branding, classification


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
            cur.execute(
                """
                SELECT t.id, t.name,
                       t.classification_enabled, t.classification_text,
                       t.classification_color, t.classification_fg
                FROM api.teams t
                JOIN api.team_members tm ON tm.team_id = t.id
                WHERE tm.user_id = %s
                ORDER BY t.name
                """,
                (user_id,),
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
        try:
            en = active.get("classification_enabled")
            if en is not None:
                from config import HEX

                text = (active.get("classification_text") or "").strip()
                color = (active.get("classification_color") or "").strip() or "#677381"
                fg = (active.get("classification_fg") or "").strip() or "#ffffff"
                if not HEX.match(color):
                    color = "#677381"
                if not HEX.match(fg):
                    fg = "#ffffff"
                # en is True → show if text present; False → hide (even if server banner on)
                base["classification"] = {
                    "enabled": bool(en) and bool(text),
                    "text": text if en else "",
                    "color": color,
                    "fg": fg,
                }
        except (KeyError, TypeError, AttributeError):
            pass
    try:
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            base["nav_pins"] = pins.list_pins(cur, session["user_id"])
            base["nav_recent"] = pins.list_recent(cur, session["user_id"])
    except Exception:
        pass
    return base
