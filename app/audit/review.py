"""Access-review matrix queries (SOC2-style membership)."""

from __future__ import annotations


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
           AND 'team' = ANY (r.scopes)
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
           AND 'project' = ANY (r.scopes)
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
