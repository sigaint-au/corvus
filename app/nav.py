"""Sidebar navigation context and team selection helpers."""
from flask import session

import authz
from config import APP_NAME, CLIPBOARD_CLEAR_SECONDS, MAX_EXPIRY_DAYS
import db
import pins
from settings_svc import classification


def nav_teams(user_id: str):
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
    """Session team if still a member, else first team."""
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
    banner = classification()
    base = {
        "app_name": APP_NAME,
        "classification": banner,
        "is_global_admin": bool(session.get("is_global_admin")),
        "nav_teams": [],
        "nav_team_id": session.get("team_id"),
        "nav_team_name": None,
        "nav_pins": [],
        "nav_recent": [],
        "clipboard_clear_seconds": CLIPBOARD_CLEAR_SECONDS,
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
