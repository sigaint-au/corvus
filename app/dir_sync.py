"""Shared LDAP/OIDC group → role and team membership sync."""

from __future__ import annotations

from config import ROLE_RANK
def apply_global_admin_maps(cur, uid, groups, role_maps, group_key: str) -> None:
    """If role maps exist, set is_global_admin from group matches."""
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
    """Sync team_members rows with source=ldap|oidc from directory maps."""
    from ldap_auth import group_matches

    desired: dict[str, str] = {}
    for m in tmaps:
        if not group_matches(m[group_key], groups):
            continue
        tid = str(m["team_id"])
        role = m["role"]
        if tid not in desired or ROLE_RANK.get(role, 0) > ROLE_RANK.get(desired[tid], 0):
            desired[tid] = role

    cur.execute(
        f"""
        DELETE FROM api.team_members
        WHERE user_id = %s AND source = %s
          AND NOT (team_id = ANY(%s::uuid[]))
        """,
        (str(uid), source, list(desired.keys()) or []),
    )
    for tid, role in desired.items():
        cur.execute(
            """
            SELECT role, source FROM api.team_members
            WHERE team_id = %s AND user_id = %s
            """,
            (tid, str(uid)),
        )
        existing = cur.fetchone()
        if existing and existing.get("source") == "manual":
            continue
        if existing:
            cur.execute(
                """
                UPDATE api.team_members SET role = %s, source = %s
                WHERE team_id = %s AND user_id = %s
                """,
                (role, source, tid, str(uid)),
            )
        else:
            cur.execute(
                """
                INSERT INTO api.team_members (team_id, user_id, role, source)
                VALUES (%s, %s, %s, %s)
                """,
                (tid, str(uid), role, source),
            )


def fetch_user_row(cur, uid) -> dict:
    cur.execute(
        "SELECT id, email, name, is_global_admin FROM private.users WHERE id = %s",
        (str(uid),),
    )
    return cur.fetchone()
