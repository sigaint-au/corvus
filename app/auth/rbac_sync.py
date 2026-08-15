"""RBAC binding helpers (k8s model).

Membership UIs and directory synchronization write ``rbac.bindings`` directly.
Roles are the built-in ``rbac.roles`` names (``team-member``, ``project-admin``,
``secret-reveal``, ...); callers never translate a short role vocabulary.
"""

from __future__ import annotations

import logging

from core.config import (
    RBAC_CLUSTER_ROLE_DROPDOWN,
    RBAC_PROJECT_ROLE_DROPDOWN,
    RBAC_PROJECT_ROLE_NAMES,
    RBAC_SECRET_ROLE_DROPDOWN,
    RBAC_SERVICE_ROLE_DROPDOWN,
    RBAC_TEAM_ROLE_DROPDOWN,
    RBAC_TEAM_ROLE_NAMES,
)

log = logging.getLogger(__name__)

TEAM_ROLE_NAMES = RBAC_TEAM_ROLE_NAMES
PROJECT_ROLE_NAMES = RBAC_PROJECT_ROLE_NAMES


# steep dropdowns → friendly label for list badges / tooltips
ROLE_LABELS = dict(
    RBAC_TEAM_ROLE_DROPDOWN
    + RBAC_PROJECT_ROLE_DROPDOWN
    + RBAC_SECRET_ROLE_DROPDOWN
    + RBAC_CLUSTER_ROLE_DROPDOWN
    + RBAC_SERVICE_ROLE_DROPDOWN
)


def rbac_role_label(role_name: str) -> str:
    """Return the friendly label for an ``rbac.roles`` name (fallback: name)."""
    return ROLE_LABELS.get(role_name, role_name or "")


def role_id(cur, name: str):
    """Return the UUID string for an ``rbac.roles`` name, or None."""
    cur.execute("SELECT id FROM rbac.roles WHERE name = %s", (name,))
    row = cur.fetchone()
    return str(row["id"]) if row else None


def count_team_owner_bindings(cur, team_id) -> int:
    """Count team-owner bindings (User or Group) at team scope."""
    cur.execute(
        """
        SELECT count(*) AS n
        FROM rbac.bindings b
        JOIN rbac.roles r ON r.id = b.role_id
        WHERE b.scope_kind = 'team' AND b.scope_id = %s::uuid
          AND r.name = 'team-owner'
        """,
        (str(team_id),),
    )
    return int((cur.fetchone() or {}).get("n") or 0)


def ensure_not_last_team_owner(
    cur, team_id, *, subject_kind: str, subject_id, new_role: str | None
) -> None:
    """Raise if removing/demoting the last team-owner binding at this scope.

    ``new_role`` is an ``rbac.roles`` name (e.g. ``"team-owner"``) or ``None``
    / ``""`` to clear the binding.
    """
    cur.execute(
        """
        SELECT r.name AS role_name
        FROM rbac.bindings b
        JOIN rbac.roles r ON r.id = b.role_id
        WHERE b.subject_kind = %s AND b.subject_id = %s::uuid
          AND b.scope_kind = 'team' AND b.scope_id = %s::uuid
          AND r.name IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')
        LIMIT 1
        """,
        (subject_kind, str(subject_id), str(team_id)),
    )
    row = cur.fetchone()
    if not row or row.get("role_name") != "team-owner":
        return
    if new_role == "team-owner":
        return
    if count_team_owner_bindings(cur, team_id) <= 1:
        raise ValueError(
            "cannot remove the last team owner; transfer ownership first"
        )


def group_team_roles_map(cur, team_id) -> dict[str, str]:
    """Map group_id → rbac team role name (e.g. ``team-admin``) from bindings."""
    cur.execute(
        """
        SELECT b.subject_id::text AS gid, r.name AS role_name
        FROM rbac.bindings b
        JOIN rbac.roles r ON r.id = b.role_id
        WHERE b.scope_kind = 'team' AND b.scope_id = %s::uuid
          AND b.subject_kind = 'Group'
          AND r.name IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')
        """,
        (str(team_id),),
    )
    out: dict[str, str] = {}
    for row in cur.fetchall() or []:
        out[str(row["gid"])] = row["role_name"]
    return out


def sync_group_team_binding(cur, *, group_id, team_id, team_role: str | None, created_by=None):
    """Upsert or clear Group→team binding. ``team_role`` is an rbac role name.

    Args:
        cur: Open DB cursor (authenticated, under RLS).
        group_id: UUID of the group to bind.
        team_id: UUID of the team scope.
        team_role: RBAC role name (e.g. ``team-member``) or None to remove.
        created_by: UUID of the acting user (audit).

    Example:
        sync_group_team_binding(cur, group_id=gid, team_id=tid,
                                team_role="team-viewer", created_by=actor_id)
    """
    ensure_not_last_team_owner(
        cur,
        team_id,
        subject_kind="Group",
        subject_id=group_id,
        new_role=team_role,
    )
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
    if team_role not in TEAM_ROLE_NAMES:
        return
    rid = role_id(cur, team_role)
    if not rid:
        log.warning("missing built-in role %s", team_role)
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
    """Upsert or clear a Group→project RBAC binding. ``role`` is an rbac name.

    Args:
        cur: Open DB cursor (authenticated, under RLS).
        group_id: UUID of the group to bind.
        project_id: UUID of the project scope.
        role: RBAC role name (e.g. ``project-write``) or None to remove.
        created_by: UUID of the acting user (audit).

    Example:
        sync_group_project_binding(cur, group_id=gid, project_id=pid,
                                   role="project-admin", created_by=actor_id)
    """
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
    if role not in PROJECT_ROLE_NAMES:
        return
    rid = role_id(cur, role)
    if not rid:
        log.warning("missing built-in role %s", role)
        return
    cur.execute(
        """
        INSERT INTO rbac.bindings
          (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
        VALUES (%s::uuid, 'Group', %s::uuid, 'project', %s::uuid, %s::uuid)
        """,
        (rid, str(group_id), str(project_id), str(created_by) if created_by else None),
    )


def sync_user_team_binding(
    cur, *, user_id, team_id, role: str | None, created_by=None, source="manual"
):
    """Upsert User→team binding. ``role`` is an rbac role name or None to clear.

    Args:
        cur: Open DB cursor (authenticated, under RLS).
        user_id: UUID of the user to bind.
        team_id: UUID of the team scope.
        role: RBAC role name (e.g. ``team-member``) or None to remove binding.
        created_by: UUID of the acting user (audit).
        source: ``manual``, ``ldap``, or ``oidc``.

    Example:
        sync_user_team_binding(cur, user_id=uid, team_id=tid, role="team-admin",
                               created_by=actor_id)
    """
    ensure_not_last_team_owner(
        cur,
        team_id,
        subject_kind="User",
        subject_id=user_id,
        new_role=role,
    )
    cur.execute(
        """
        DELETE FROM rbac.bindings
        WHERE subject_kind = 'User' AND subject_id = %s::uuid
          AND scope_kind = 'team' AND scope_id = %s::uuid
          AND source = %s
          AND role_id IN (
            SELECT id FROM rbac.roles
            WHERE name IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')
          )
        """,
        (str(user_id), str(team_id), source),
    )
    if role not in TEAM_ROLE_NAMES:
        return
    rid = role_id(cur, role)
    if not rid:
        return
    cur.execute(
        """
        INSERT INTO rbac.bindings
          (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by, source)
        VALUES (%s::uuid, 'User', %s::uuid, 'team', %s::uuid, %s::uuid, %s)
        """,
        (rid, str(user_id), str(team_id), str(created_by) if created_by else None, source),
    )


def sync_user_project_binding(
    cur, *, user_id, project_id, role: str | None, created_by=None
):
    """Upsert User→project binding. ``role`` is an rbac role name or None.

    Args:
        cur: Open DB cursor (authenticated, under RLS).
        user_id: UUID of the user to bind.
        project_id: UUID of the project scope.
        role: RBAC role name (e.g. ``project-write``) or None to remove.
        created_by: UUID of the acting user (audit).

    Example:
        sync_user_project_binding(cur, user_id=uid, project_id=pid,
                                   role="project-read", created_by=actor_id)
    """
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
    if role not in PROJECT_ROLE_NAMES:
        return
    rid = role_id(cur, role)
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
                b.created_at, b.source, r.name AS role_name, r.built_in,
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
    """Attach subject_email for User subjects via admin DSN and the friendly
    role label (title-bearing badge) for the role_name."""
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
            from core import db

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
        b["role_short"] = rbac_role_label(b.get("role_name") or "")
    return bindings
