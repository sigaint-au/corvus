"""Team LDAP/OIDC directory-map routes."""

from __future__ import annotations

from flask import (
    flash,
    redirect,
    request,
    session,
    url_for,
)
import audit
from auth import authz
from core import config
from core import db


@authz.login_required
def add_team_ldap_map(team_id):
    """Add or update an LDAP group to team role mapping.

    Args:
        team_id: UUID of the team to map.

    Returns:
        Redirect to the team settings tab.

    Example:
        POST /teams/<team_id>/ldap-maps with ldap_group and role form fields
    """
    ldap_group = (request.form.get("ldap_group") or "").strip()
    role = request.form.get("role", "team-member")
    team_role_names = config.RBAC_TEAM_ROLE_NAMES
    if role not in team_role_names:
        role = "team-member"
    if not ldap_group:
        flash("LDAP group required", "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                """
                INSERT INTO api.team_ldap_maps (team_id, ldap_group, role)
                VALUES (%s, %s, %s)
                ON CONFLICT (team_id, ldap_group) DO UPDATE SET role = EXCLUDED.role
                """,
                (str(team_id), ldap_group, role),
            )
            audit.log_org(
                cur,
                team_id=team_id,
                action=audit.ORG_LDAP_MAP_ADD,
                detail=f"{ldap_group} → {role}",
            )
            conn.commit()
            flash("LDAP group mapping saved — applies on next LDAP login", "ok")
        except Exception as e:
            flash("Could not update the directory mapping. Try again.", "error")
    return redirect(url_for("team_detail", team_id=team_id, tab="settings"))


@authz.login_required
def delete_team_ldap_map(team_id, map_id):
    """Delete an LDAP group mapping for a team.

    Args:
        team_id: UUID of the team.
        map_id: UUID of the LDAP map row to delete.

    Returns:
        Redirect to the team settings tab.

    Example:
        POST /teams/<team_id>/ldap-maps/<map_id>/delete
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM api.team_ldap_maps WHERE id = %s AND team_id = %s",
            (str(map_id), str(team_id)),
        )
        if cur.rowcount:
            audit.log_org(
                cur,
                team_id=team_id,
                action=audit.ORG_LDAP_MAP_DELETE,
                detail=str(map_id),
            )
        conn.commit()
    return redirect(url_for("team_detail", team_id=team_id, tab="settings"))


@authz.login_required
def add_team_oidc_map(team_id):
    """Add or update an OIDC group to team role mapping.

    Args:
        team_id: UUID of the team to map.

    Returns:
        Redirect to the team settings tab.

    Example:
        POST /teams/<team_id>/oidc-maps with oidc_group and role form fields
    """
    oidc_group = (request.form.get("oidc_group") or "").strip()
    role = request.form.get("role", "team-member")
    team_role_names = config.RBAC_TEAM_ROLE_NAMES
    if role not in team_role_names:
        role = "team-member"
    if not oidc_group:
        flash("OIDC group required", "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                """
                INSERT INTO api.team_oidc_maps (team_id, oidc_group, role)
                VALUES (%s, %s, %s)
                ON CONFLICT (team_id, oidc_group) DO UPDATE SET role = EXCLUDED.role
                """,
                (str(team_id), oidc_group, role),
            )
            audit.log_org(
                cur,
                team_id=team_id,
                action=audit.ORG_OIDC_MAP_ADD,
                detail=f"{oidc_group} → {role}",
            )
            conn.commit()
            flash("OIDC group mapping saved — applies on next SSO login", "ok")
        except Exception as e:
            flash("Could not update the directory mapping. Try again.", "error")
    return redirect(url_for("team_detail", team_id=team_id, tab="settings"))


@authz.login_required
def delete_team_oidc_map(team_id, map_id):
    """Delete an OIDC group mapping for a team.

    Args:
        team_id: UUID of the team.
        map_id: UUID of the OIDC map row to delete.

    Returns:
        Redirect to the team settings tab.

    Example:
        POST /teams/<team_id>/oidc-maps/<map_id>/delete
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM api.team_oidc_maps WHERE id = %s AND team_id = %s",
            (str(map_id), str(team_id)),
        )
        if cur.rowcount:
            audit.log_org(
                cur,
                team_id=team_id,
                action=audit.ORG_OIDC_MAP_DELETE,
                detail=str(map_id),
            )
        conn.commit()
    return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
