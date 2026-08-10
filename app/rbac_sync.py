"""RBAC binding helpers (k8s model).

Membership UIs (team Members, project Access) write ``rbac.bindings`` directly.
``backfill_all_legacy_to_bindings`` is a one-shot migration for existing
``team_members`` / ``project_members`` / ``project_group_roles`` rows.
Legacy tables are NOT written to going forward (pure RBAC model).
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

# Legacy role name → built-in rbac.roles name
TEAM_ROLE_TO_RBAC = {
    "owner": "team-owner",
    "admin": "team-admin",
    "member": "team-member",
    "viewer": "team-viewer",
}
PROJECT_ROLE_TO_RBAC = {
    "admin": "project-admin",
    "write": "project-write",
    "read": "project-read",
}
RBAC_TO_PROJECT_ROLE = {v: k for k, v in PROJECT_ROLE_TO_RBAC.items()}
RBAC_TO_TEAM_ROLE = {v: k for k, v in TEAM_ROLE_TO_RBAC.items()}
PROJECT_ROLE_NAMES = tuple(PROJECT_ROLE_TO_RBAC.values())
TEAM_ROLE_NAMES = tuple(TEAM_ROLE_TO_RBAC.values())


def _role_id(cur, name: str):
    cur.execute("SELECT id FROM rbac.roles WHERE name = %s", (name,))
    row = cur.fetchone()
    return str(row["id"]) if row else None


def sync_group_team_binding(cur, *, group_id, team_id, team_role: str | None, created_by=None):
    """Upsert or clear Group→team binding from groups.team_role."""
    cur.execute(
        """
        DELETE FROM rbac.bindings
        WHERE subject_kind = 'Group' AND subject_id = %s::uuid
          AND scope_kind = 'team' AND scope_id = %s::uuid
          AND role_id IN (
            SELECT id FROM rbac.roles
            WHERE name IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')
          )
        """,
        (str(group_id), str(team_id)),
    )
    if not team_role:
        return
    rname = TEAM_ROLE_TO_RBAC.get(team_role)
    if not rname:
        return
    rid = _role_id(cur, rname)
    if not rid:
        log.warning("missing built-in role %s", rname)
        return
    cur.execute(
        """
        INSERT INTO rbac.bindings
          (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
        VALUES (%s::uuid, 'Group', %s::uuid, 'team', %s::uuid, %s::uuid)
        """,
        (rid, str(group_id), str(team_id), str(created_by) if created_by else None),
    )


def sync_group_project_binding(
    cur, *, group_id, project_id, role: str | None, created_by=None
):
    """Upsert or clear Group→project binding from project_group_roles."""
    cur.execute(
        """
        DELETE FROM rbac.bindings
        WHERE subject_kind = 'Group' AND subject_id = %s::uuid
          AND scope_kind = 'project' AND scope_id = %s::uuid
          AND role_id IN (
            SELECT id FROM rbac.roles
            WHERE name IN ('project-admin', 'project-write', 'project-read')
          )
        """,
        (str(group_id), str(project_id)),
    )
    if not role:
        return
    rname = PROJECT_ROLE_TO_RBAC.get(role)
    if not rname:
        return
    rid = _role_id(cur, rname)
    if not rid:
        log.warning("missing built-in role %s", rname)
        return
    cur.execute(
        """
        INSERT INTO rbac.bindings
          (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
        VALUES (%s::uuid, 'Group', %s::uuid, 'project', %s::uuid, %s::uuid)
        """,
        (rid, str(group_id), str(project_id), str(created_by) if created_by else None),
    )


def sync_user_team_binding(cur, *, user_id, team_id, role: str | None, created_by=None):
    """Upsert User→team binding from team_members.role."""
    cur.execute(
        """
        DELETE FROM rbac.bindings
        WHERE subject_kind = 'User' AND subject_id = %s::uuid
          AND scope_kind = 'team' AND scope_id = %s::uuid
          AND role_id IN (
            SELECT id FROM rbac.roles
            WHERE name IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')
          )
        """,
        (str(user_id), str(team_id)),
    )
    if not role:
        return
    rname = TEAM_ROLE_TO_RBAC.get(role)
    if not rname:
        return
    rid = _role_id(cur, rname)
    if not rid:
        return
    cur.execute(
        """
        INSERT INTO rbac.bindings
          (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
        VALUES (%s::uuid, 'User', %s::uuid, 'team', %s::uuid, %s::uuid)
        """,
        (rid, str(user_id), str(team_id), str(created_by) if created_by else None),
    )


def sync_user_project_binding(
    cur, *, user_id, project_id, role: str | None, created_by=None
):
    """Upsert User→project binding (role: admin|write|read or None to clear)."""
    cur.execute(
        """
        DELETE FROM rbac.bindings
        WHERE subject_kind = 'User' AND subject_id = %s::uuid
          AND scope_kind = 'project' AND scope_id = %s::uuid
          AND role_id IN (
            SELECT id FROM rbac.roles
            WHERE name IN ('project-admin', 'project-write', 'project-read')
          )
        """,
        (str(user_id), str(project_id)),
    )
    if not role:
        return
    rname = PROJECT_ROLE_TO_RBAC.get(role) or (
        role if role in PROJECT_ROLE_NAMES else None
    )
    if not rname:
        return
    rid = _role_id(cur, rname)
    if not rid:
        return
    cur.execute(
        """
        INSERT INTO rbac.bindings
          (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
        VALUES (%s::uuid, 'User', %s::uuid, 'project', %s::uuid, %s::uuid)
        """,
        (rid, str(user_id), str(project_id), str(created_by) if created_by else None),
    )


def list_scope_bindings(cur, scope_kind: str, scope_id) -> list:
    """List bindings at a scope (with group_name; emails filled by caller)."""
    cur.execute(
        """
        SELECT b.id, b.subject_kind, b.subject_id, b.scope_kind, b.scope_id,
               b.created_at, r.name AS role_name, r.built_in,
               g.name AS group_name
        FROM rbac.bindings b
        JOIN rbac.roles r ON r.id = b.role_id
        LEFT JOIN api.groups g
          ON b.subject_kind = 'Group' AND g.id = b.subject_id
        WHERE b.scope_kind = %s AND b.scope_id = %s::uuid
        ORDER BY b.created_at DESC
        LIMIT 200
        """,
        (scope_kind, str(scope_id)),
    )
    return list(cur.fetchall() or [])


def enrich_binding_emails(bindings: list) -> list:
    """Attach subject_email for User subjects via admin DSN."""
    if not bindings:
        return bindings
    user_ids = [
        str(b["subject_id"])
        for b in bindings
        if b.get("subject_kind") == "User" and b.get("subject_id")
    ]
    email_map: dict[str, str] = {}
    if user_ids:
        try:
            import db

            with db.connect_admin() as aconn, aconn.cursor() as acur:
                acur.execute(
                    """
                    SELECT id, email FROM private.users
                    WHERE id = ANY(%s::uuid[])
                    """,
                    (user_ids,),
                )
                for row in acur.fetchall() or []:
                    email_map[str(row["id"])] = row["email"]
        except Exception:
            log.debug("enrich_binding_emails failed", exc_info=True)
    for b in bindings:
        if b.get("subject_kind") == "User":
            b["subject_email"] = email_map.get(str(b.get("subject_id")))
        else:
            b["subject_email"] = None
        # Friendly short role for project-* / team-*
        rn = b.get("role_name") or ""
        b["role_short"] = RBAC_TO_PROJECT_ROLE.get(rn) or RBAC_TO_TEAM_ROLE.get(rn) or rn
    return bindings


def backfill_all_legacy_to_bindings(cur) -> dict:
    """One-shot: copy team_members, project_members, group roles into bindings.

    Does not touch secrets (Permissions tab writes secret-scope bindings; secret_acl dropped).
    Safe to re-run (deletes then re-inserts per subject/scope role family).
    """
    stats = {"team_members": 0, "project_members": 0, "group_team": 0, "group_project": 0}
    cur.execute(
        "SELECT team_id, user_id, role FROM api.team_members"
    )
    for row in cur.fetchall() or []:
        sync_user_team_binding(
            cur,
            user_id=row["user_id"],
            team_id=row["team_id"],
            role=row["role"],
        )
        stats["team_members"] += 1
    cur.execute(
        "SELECT project_id, user_id, role FROM api.project_members"
    )
    for row in cur.fetchall() or []:
        sync_user_project_binding(
            cur,
            user_id=row["user_id"],
            project_id=row["project_id"],
            role=row["role"],
        )
        stats["project_members"] += 1
    cur.execute(
        "SELECT id, team_id, team_role FROM api.groups WHERE team_role IS NOT NULL"
    )
    for row in cur.fetchall() or []:
        sync_group_team_binding(
            cur,
            group_id=row["id"],
            team_id=row["team_id"],
            team_role=row["team_role"],
        )
        stats["group_team"] += 1
    cur.execute(
        "SELECT project_id, group_id, role FROM api.project_group_roles"
    )
    for row in cur.fetchall() or []:
        sync_group_project_binding(
            cur,
            group_id=row["group_id"],
            project_id=row["project_id"],
            role=row["role"],
        )
        stats["group_project"] += 1
    return stats
