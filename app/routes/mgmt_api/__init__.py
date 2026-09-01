"""Management API package (PAT/session CLI management routes)."""

from __future__ import annotations

from .access import (
    mgmt_add_secret_binding,
    mgmt_delete_secret_binding,
    mgmt_update_secret_access,
)
from .admin import (
    mgmt_admin_audit,
    mgmt_admin_demote_user,
    mgmt_admin_disable_user,
    mgmt_admin_enable_user,
    mgmt_admin_promote_user,
    mgmt_admin_reset_2fa,
    mgmt_admin_reset_password,
    mgmt_admin_users,
)
from .export import mgmt_export_project
from .folders import (
    mgmt_create_folder,
    mgmt_delete_folder,
    mgmt_list_folders,
)
from .groups import (
    mgmt_add_group_member,
    mgmt_create_group,
    mgmt_delete_group,
    mgmt_list_groups,
    mgmt_remove_group_member,
)
from .history import (
    mgmt_project_audit,
    mgmt_secret_history,
)
from .projects import (
    mgmt_add_project_binding,
    mgmt_create_project,
    mgmt_delete_project,
    mgmt_delete_project_meta,
    mgmt_get_project,
    mgmt_list_project_members,
    mgmt_remove_project_binding,
    mgmt_update_project_settings,
    mgmt_upsert_project_meta,
)
from .secrets import (
    mgmt_delete_secret_meta,
    mgmt_upsert_secret_meta,
)
from .teams import (
    mgmt_add_team_binding,
    mgmt_create_team,
    mgmt_delete_team,
    mgmt_delete_team_meta,
    mgmt_get_team,
    mgmt_list_team_members,
    mgmt_list_teams,
    mgmt_remove_team_binding,
    mgmt_transfer_team,
    mgmt_upsert_team_meta,
)
from .tokens import (
    mgmt_create_token,
    mgmt_delete_token,
    mgmt_list_tokens,
)
from .trash import (
    mgmt_bulk_trash,
    mgmt_list_trash,
    mgmt_purge_trash,
    mgmt_restore_trash,
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
    app.patch(f"{base}/teams/<team_ref>/meta/<meta_key>")(mgmt_upsert_team_meta)
    app.delete(f"{base}/teams/<team_ref>/meta/<meta_key>")(mgmt_delete_team_meta)
    app.get(f"{base}/teams/<team_ref>/groups")(mgmt_list_groups)
    app.post(f"{base}/teams/<team_ref>/groups")(mgmt_create_group)
    app.delete(f"{base}/teams/<team_ref>/groups/<group_ref>")(mgmt_delete_group)
    app.post(f"{base}/teams/<team_ref>/groups/<group_ref>/members")(mgmt_add_group_member)
    app.delete(f"{base}/teams/<team_ref>/groups/<group_ref>/members/<member_ref>")(
        mgmt_remove_group_member
    )
    app.post(f"{base}/teams/<team_ref>/projects")(mgmt_create_project)
    app.get(f"{base}/projects/<project_ref>")(mgmt_get_project)
    app.delete(f"{base}/projects/<project_ref>")(mgmt_delete_project)
    app.patch(f"{base}/projects/<project_ref>")(mgmt_update_project_settings)
    app.get(f"{base}/projects/<project_ref>/export")(mgmt_export_project)
    app.get(f"{base}/projects/<project_ref>/members")(mgmt_list_project_members)
    app.post(f"{base}/projects/<project_ref>/members")(mgmt_add_project_binding)
    app.delete(f"{base}/projects/<project_ref>/members/<member_ref>")(mgmt_remove_project_binding)
    app.get(f"{base}/projects/<project_ref>/trash")(mgmt_list_trash)
    app.post(f"{base}/projects/<project_ref>/trash/restore")(mgmt_bulk_trash)
    app.post(f"{base}/projects/<project_ref>/trash/<secret_id>/restore")(mgmt_restore_trash)
    app.delete(f"{base}/projects/<project_ref>/trash/<secret_id>")(mgmt_purge_trash)
    app.get(f"{base}/projects/<project_ref>/tokens")(mgmt_list_tokens)
    app.post(f"{base}/projects/<project_ref>/tokens")(mgmt_create_token)
    app.delete(f"{base}/projects/<project_ref>/tokens/<token_id>")(mgmt_delete_token)
    app.get(f"{base}/projects/<project_ref>/folders")(mgmt_list_folders)
    app.post(f"{base}/projects/<project_ref>/folders")(mgmt_create_folder)
    app.delete(f"{base}/projects/<project_ref>/folders/<uuid:folder_id>")(mgmt_delete_folder)
    app.get(f"{base}/projects/<project_ref>/secrets/<path:key>/history")(mgmt_secret_history)
    app.patch(f"{base}/projects/<project_ref>/secrets/<path:key>")(mgmt_update_secret_access)
    app.post(f"{base}/projects/<project_ref>/secrets/<path:key>/bindings")(mgmt_add_secret_binding)
    app.delete(f"{base}/projects/<project_ref>/secrets/<path:key>/bindings/<binding_id>")(
        mgmt_delete_secret_binding
    )
    app.patch(f"{base}/projects/<project_ref>/secrets/<path:key>/meta")(mgmt_upsert_secret_meta)
    app.delete(f"{base}/projects/<project_ref>/secrets/<path:key>/meta/<meta_key>")(
        mgmt_delete_secret_meta
    )
    app.get(f"{base}/projects/<project_ref>/audit")(mgmt_project_audit)
    app.patch(f"{base}/projects/<project_ref>/meta/<meta_key>")(mgmt_upsert_project_meta)
    app.delete(f"{base}/projects/<project_ref>/meta/<meta_key>")(mgmt_delete_project_meta)
    app.get(f"{base}/admin/users")(mgmt_admin_users)
    app.get(f"{base}/admin/audit")(mgmt_admin_audit)
    app.post(f"{base}/admin/users/<uuid:user_id>/disable")(mgmt_admin_disable_user)
    app.post(f"{base}/admin/users/<uuid:user_id>/enable")(mgmt_admin_enable_user)
    app.post(f"{base}/admin/users/<uuid:user_id>/promote")(mgmt_admin_promote_user)
    app.post(f"{base}/admin/users/<uuid:user_id>/demote")(mgmt_admin_demote_user)
    app.post(f"{base}/admin/users/<uuid:user_id>/reset-password")(mgmt_admin_reset_password)
    app.post(f"{base}/admin/users/<uuid:user_id>/reset-2fa")(mgmt_admin_reset_2fa)
