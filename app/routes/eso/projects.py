"""ESO project listing route."""

from __future__ import annotations

from flask import (
    jsonify,
    request,
)
from core import db
from .helpers import _require_auth


def eso_list_projects():
    """List projects visible to a PAT (not available for machine tokens).

    Args:
        None (optional query ``q`` / ``name`` filters by project or team name).

    Returns:
        flask.Response: ``{"items":[{id,name,team_id,team_name},…]}`` or
            401/400 JSON.

    Example:
        GET /eso/v1/projects?q=ios
        Authorization: Bearer pat_…
    """
    auth, err = _require_auth()
    if err:
        return err
    kind, ident = auth
    if kind != "pat":
        return jsonify(
            {"error": "project list requires a personal access token (pat_…)"}
        ), 400
    q = (request.args.get("q") or request.args.get("name") or "").strip() or None
    with db.as_user(ident) as conn, conn.cursor() as cur:
        if q:
            cur.execute(
                """
                SELECT p.id, p.name, p.team_id, t.name AS team_name
                  FROM api.projects p
                  JOIN api.teams t ON t.id = p.team_id
                 WHERE p.name ILIKE %s OR t.name ILIKE %s
                 ORDER BY t.name, p.name
                 LIMIT 50
                """,
                (f"%{q}%", f"%{q}%"),
            )
        else:
            cur.execute(
                """
                SELECT p.id, p.name, p.team_id, t.name AS team_name
                  FROM api.projects p
                  JOIN api.teams t ON t.id = p.team_id
                 ORDER BY t.name, p.name
                 LIMIT 200
                """
            )
        rows = cur.fetchall() or []
    return jsonify(
        {
            "items": [
                {
                    "id": str(r["id"]),
                    "name": r["name"],
                    "team_id": str(r["team_id"]),
                    "team_name": r.get("team_name") or "",
                }
                for r in rows
            ]
        }
    )
