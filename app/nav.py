"""Sidebar navigation context and team selection helpers."""
from flask import session

import authz
from config import APP_NAME
import db
from settings_svc import classification


def nav_teams(user_id: str):
    with db.as_user(user_id) as conn, conn.cursor() as cur:
        if session.get("is_global_admin"):
            cur.execute("SELECT t.id, t.name FROM api.teams t ORDER BY t.name")
        else:
            cur.execute(
                """
                SELECT t.id, t.name
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
        "nav_team_id": None,
    }
    if not session.get("user_id"):
        return base
    if session.get("user_id"):
        session["is_global_admin"] = authz.is_global_admin(session["user_id"])
        base["is_global_admin"] = session["is_global_admin"]
    try:
        teams = nav_teams(session["user_id"])
    except Exception:
        teams = []
    base["nav_teams"] = teams
    base["nav_team_id"] = active_team_id(teams)
    return base
