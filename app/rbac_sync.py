"""Sync legacy membership / group role UI into rbac.bindings (k8s model)."""

from __future__ import annotations

import logging

import config

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
    """Upsert User→project binding from project_members.role."""
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
    rname = PROJECT_ROLE_TO_RBAC.get(role)
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
