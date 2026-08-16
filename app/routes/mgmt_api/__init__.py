"""Management API package (PAT/session CLI management routes)."""

from __future__ import annotations

from .helpers import (
    _require_pat,
    _require_global_admin,
    _row,
    _resolve_team,
    _resolve_project,
)
from .teams import (
    mgmt_list_teams,
    mgmt_create_team,
    mgmt_get_team,
    mgmt_delete_team,
    mgmt_list_team_members,
    mgmt_add_team_binding,
    mgmt_remove_team_binding,
    mgmt_transfer_team,
)
from .projects import (
    mgmt_create_project,
    mgmt_get_project,
    mgmt_delete_project,
    mgmt_list_project_members,
    mgmt_add_project_binding,
    mgmt_remove_project_binding,
)
from .trash import (
    mgmt_list_trash,
    mgmt_restore_trash,
    mgmt_purge_trash,
)
from .tokens import (
    mgmt_list_tokens,
    mgmt_create_token,
    mgmt_delete_token,
)
from .history import (
    mgmt_secret_history,
    mgmt_project_audit,
)
from .admin import (
    mgmt_admin_users,
    mgmt_admin_audit,
)


def register(app):
    """Register the authenticated management API routes."""
    base = "/api/v1/manage"
    app.get(f"{base}/teams")(mgmt_list_teams)
    app.post(f"{base}/teams")(mgmt_create_team)
    app.get(f"{base}/teams/<team_ref>")(mgmt_get_team)
    app.delete(f"{base}/teams/<team_ref>")(mgmt_delete_team)
    app.get(f"{base}/teams/<team_ref>/members")(mgmt_list_team_members)
    app.post(f"{base}/teams/<team_ref>/members")(mgmt_add_team_binding)
    app.delete(f"{base}/teams/<team_ref>/members/<member_ref>")(mgmt_remove_team_binding)
    app.post(f"{base}/teams/<team_ref>/transfer")(mgmt_transfer_team)
    app.post(f"{base}/teams/<team_ref>/projects")(mgmt_create_project)
    app.get(f"{base}/projects/<project_ref>")(mgmt_get_project)
    app.delete(f"{base}/projects/<project_ref>")(mgmt_delete_project)
    app.get(f"{base}/projects/<project_ref>/members")(mgmt_list_project_members)
    app.post(f"{base}/projects/<project_ref>/members")(mgmt_add_project_binding)
    app.delete(f"{base}/projects/<project_ref>/members/<member_ref>")(mgmt_remove_project_binding)
    app.get(f"{base}/projects/<project_ref>/trash")(mgmt_list_trash)
    app.post(f"{base}/projects/<project_ref>/trash/<secret_id>/restore")(mgmt_restore_trash)
    app.delete(f"{base}/projects/<project_ref>/trash/<secret_id>")(mgmt_purge_trash)
    app.get(f"{base}/projects/<project_ref>/tokens")(mgmt_list_tokens)
    app.post(f"{base}/projects/<project_ref>/tokens")(mgmt_create_token)
    app.delete(f"{base}/projects/<project_ref>/tokens/<token_id>")(mgmt_delete_token)
    app.get(f"{base}/projects/<project_ref>/secrets/<path:key>/history")(mgmt_secret_history)
    app.get(f"{base}/projects/<project_ref>/audit")(mgmt_project_audit)
    app.get(f"{base}/admin/users")(mgmt_admin_users)
    app.get(f"{base}/admin/audit")(mgmt_admin_audit)
