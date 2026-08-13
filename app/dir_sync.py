"""Shared LDAP/OIDC group → role and team membership sync."""

from __future__ import annotations

# Directory team maps store rbac.roles names (team-owner/admin/member/viewer);
# rank by RBAC role name so the highest wins.
TEAM_RBAC_RANK = {
    "team-owner": 4,
    "team-admin": 3,
    "team-member": 2,
    "team-viewer": 1,
}


def apply_global_admin_maps(cur, uid, groups, role_maps, group_key: str) -> None:
    """Set ``is_global_admin`` from directory role maps that match the user's groups.

    If ``role_maps`` is empty, leaves the flag unchanged. When maps exist, any
    map with ``role == "global_admin"`` and a matching group promotes the user;
    otherwise demotes them.

    Args:
        cur: Open admin DB cursor.
        uid: User UUID being synced.
        groups: Iterable of group tokens from LDAP/OIDC for this user.
        role_maps: Rows with at least ``role`` and the column named by ``group_key``.
        group_key: Column name on each map row (``"ldap_group"`` or ``"oidc_group"``).

    Returns:
        None. Updates ``private.users.is_global_admin`` in place.

    Example:
        >>> apply_global_admin_maps(
        ...     cur, uid, ["cn=admins,ou=groups"], role_maps, "ldap_group"
        ... )
    """
    from ldap_auth import group_matches

    if not role_maps:
        return
    is_admin = any(
        m["role"] == "global_admin" and group_matches(m[group_key], groups)
        for m in role_maps
    )
    cur.execute(
        "UPDATE private.users SET is_global_admin = %s WHERE id = %s",
        (is_admin, str(uid)),
    )


def apply_team_membership_maps(
    cur,
    uid,
    groups,
    tmaps,
    *,
    group_key: str,
    source: str,
) -> None:
    """Sync directory-managed team bindings from LDAP/OIDC maps.

    Builds desired team roles from matching maps (highest RBAC role rank wins),
    removes stale directory bindings, and never overwrites manual bindings.

    Args:
        cur: Open admin DB cursor.
        uid: User UUID being synced.
        groups: Iterable of group tokens for this user.
        tmaps: Team map rows with ``team_id``, ``role``, and ``group_key`` column.
        group_key: Map column for the group name (``ldap_group`` / ``oidc_group``).
        source: Membership source tag to write (``"ldap"`` or ``"oidc"``).

    Returns:
        None.

    Example:
        >>> apply_team_membership_maps(
        ...     cur, uid, groups, tmaps, group_key="oidc_group", source="oidc"
        ... )
    """
    from ldap_auth import group_matches

    desired: dict[str, str] = {}
    for m in tmaps:
        if not group_matches(m[group_key], groups):
            continue
        tid = str(m["team_id"])
        rname = m["role"]
        if rname not in TEAM_RBAC_RANK:
            continue
        if (
            tid not in desired
            or TEAM_RBAC_RANK.get(rname, 0) > TEAM_RBAC_RANK.get(desired[tid], 0)
        ):
            desired[tid] = rname

    import rbac_sync

    cur.execute(
        """
        SELECT b.scope_id
        FROM rbac.bindings b
        JOIN rbac.roles r ON r.id = b.role_id
        WHERE b.subject_kind = 'User' AND b.subject_id = %s::uuid
          AND b.scope_kind = 'team' AND b.source = %s
          AND r.name IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')
        """,
        (str(uid), source),
    )
    for row in cur.fetchall() or []:
        tid = str(row["scope_id"])
        if tid not in desired:
            rbac_sync.sync_user_team_binding(
                cur, user_id=uid, team_id=tid, role=None, source=source
            )
    for tid, role in desired.items():
        cur.execute(
            """
            SELECT 1
            FROM rbac.bindings b
            JOIN rbac.roles r ON r.id = b.role_id
            WHERE b.subject_kind = 'User' AND b.subject_id = %s::uuid
              AND b.scope_kind = 'team' AND b.scope_id = %s::uuid
              AND b.source = 'manual'
              AND r.name IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')
            LIMIT 1
            """,
            (str(uid), tid),
        )
        if cur.fetchone():
            continue
        rbac_sync.sync_user_team_binding(
            cur, user_id=uid, team_id=tid, role=role, source=source
        )


def apply_group_membership_maps(
    cur,
    uid,
    groups,
    *,
    source: str,
) -> None:
    """Sync ``api.group_members`` for groups mapped to directory tokens.

    Matches ``api.groups`` rows with ``source`` ldap|oidc and non-null
    ``external_key`` against the user's directory groups. Directory-sourced
    memberships are added/removed; ``source='manual'`` rows are never removed.

    Args:
        cur: Open admin DB cursor.
        uid: User UUID being synced.
        groups: Iterable of group tokens from LDAP/OIDC for this user.
        source: ``"ldap"`` or ``"oidc"`` (must match ``api.groups.source``).

    Returns:
        None.
    """
    from ldap_auth import group_matches

    cur.execute(
        """
        SELECT id, external_key FROM api.groups
        WHERE source = %s AND external_key IS NOT NULL AND btrim(external_key) <> ''
        """,
        (source,),
    )
    mapped = cur.fetchall() or []
    desired_ids: list[str] = []
    for row in mapped:
        if group_matches(row["external_key"], groups):
            desired_ids.append(str(row["id"]))

    # Drop stale directory memberships for this source
    cur.execute(
        """
        DELETE FROM api.group_members gm
        USING api.groups g
        WHERE gm.group_id = g.id
          AND gm.user_id = %s
          AND gm.source = %s
          AND g.source = %s
          AND NOT (gm.group_id = ANY(%s::uuid[]))
        """,
        (str(uid), source, source, desired_ids or []),
    )
    for gid in desired_ids:
        cur.execute(
            """
            SELECT source FROM api.group_members
            WHERE group_id = %s AND user_id = %s
            """,
            (gid, str(uid)),
        )
        existing = cur.fetchone()
        if existing and existing.get("source") == "manual":
            continue
        if existing:
            cur.execute(
                """
                UPDATE api.group_members SET source = %s
                WHERE group_id = %s AND user_id = %s
                """,
                (source, gid, str(uid)),
            )
        else:
            cur.execute(
                """
                INSERT INTO api.group_members (group_id, user_id, source)
                VALUES (%s, %s, %s)
                """,
                (gid, str(uid), source),
            )


def fetch_user_row(cur, uid) -> dict:
    """Load a user row after directory sync for session/login fields.

    Args:
        cur: Open DB cursor.
        uid: User UUID.

    Returns:
        Dict with ``id``, ``email``, ``name``, ``is_global_admin``, or whatever
        ``fetchone`` returns (may be None if missing).

    Example:
        >>> row = fetch_user_row(cur, uid)
        >>> session["email"] = row["email"]
    """
    cur.execute(
        "SELECT id, email, name, is_global_admin FROM private.users WHERE id = %s",
        (str(uid),),
    )
    return cur.fetchone()
