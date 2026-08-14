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
    app.get("/eso/v1/teams")(mgmt_list_teams)
    app.post("/eso/v1/teams")(mgmt_create_team)
    app.get("/eso/v1/teams/<team_ref>")(mgmt_get_team)
    app.delete("/eso/v1/teams/<team_ref>")(mgmt_delete_team)
    app.get("/eso/v1/teams/<team_ref>/members")(mgmt_list_team_members)
    app.post("/eso/v1/teams/<team_ref>/members")(mgmt_add_team_binding)
    app.delete("/eso/v1/teams/<team_ref>/members/<member_ref>")(mgmt_remove_team_binding)
    app.post("/eso/v1/teams/<team_ref>/transfer")(mgmt_transfer_team)
    app.post("/eso/v1/teams/<team_ref>/projects")(mgmt_create_project)
    app.get("/eso/v1/projects/<project_ref>")(mgmt_get_project)
    app.delete("/eso/v1/projects/<project_ref>")(mgmt_delete_project)
    app.get("/eso/v1/projects/<project_ref>/members")(mgmt_list_project_members)
    app.post("/eso/v1/projects/<project_ref>/members")(mgmt_add_project_binding)
    app.delete("/eso/v1/projects/<project_ref>/members/<member_ref>")(mgmt_remove_project_binding)
    app.get("/eso/v1/projects/<project_ref>/trash")(mgmt_list_trash)
    app.post("/eso/v1/projects/<project_ref>/trash/<secret_id>/restore")(mgmt_restore_trash)
    app.delete("/eso/v1/projects/<project_ref>/trash/<secret_id>")(mgmt_purge_trash)
    app.get("/eso/v1/projects/<project_ref>/tokens")(mgmt_list_tokens)
    app.post("/eso/v1/projects/<project_ref>/tokens")(mgmt_create_token)
    app.delete("/eso/v1/projects/<project_ref>/tokens/<token_id>")(mgmt_delete_token)
    app.get("/eso/v1/projects/<project_ref>/secrets/<path:key>/history")(mgmt_secret_history)
    app.get("/eso/v1/projects/<project_ref>/audit")(mgmt_project_audit)
    app.get("/eso/v1/admin/users")(mgmt_admin_users)
    app.get("/eso/v1/admin/audit")(mgmt_admin_audit)
