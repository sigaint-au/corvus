"""Team routes package (teams, members, invites, groups)."""

from __future__ import annotations

from .teams import (
    teams,
    create_team,
    team_detail,
    update_team_settings,
    delete_team,
)
from .members import (
    team_access_binding_create,
    team_access_binding_delete,
    add_team_binding,
    remove_team_binding,
    transfer_team_ownership,
)
from .invites import (
    create_team_invite,
    revoke_team_invite,
    redeem_invite,
    approve_join_request,
    reject_join_request,
)
from .dir_maps import (
    add_team_ldap_map,
    delete_team_ldap_map,
    add_team_oidc_map,
    delete_team_oidc_map,
)
from .projects import (
    create_project,
    delete_project_from_team,
    new_project_wizard,
)
from .groups import (
    team_group_detail,
    create_team_group,
    update_team_group,
    delete_team_group,
    add_group_member,
    remove_group_member,
)


def register(app):
    app.get("/teams")(teams)
    app.post("/teams")(create_team)
    app.get("/teams/<uuid:team_id>")(team_detail)
    app.post("/teams/<uuid:team_id>/access/bindings")(team_access_binding_create)
    app.post("/teams/<uuid:team_id>/access/bindings/<uuid:binding_id>/delete")(team_access_binding_delete)
    app.post("/teams/<uuid:team_id>/members")(add_team_binding)
    app.post("/teams/<uuid:team_id>/members/<uuid:user_id>/remove")(remove_team_binding)
    app.post("/teams/<uuid:team_id>/transfer")(transfer_team_ownership)
    app.post("/teams/<uuid:team_id>/invites")(create_team_invite)
    app.post("/teams/<uuid:team_id>/invites/<uuid:invite_id>/revoke")(revoke_team_invite)
    app.get("/invite/<token>")(redeem_invite)
    app.post("/teams/<uuid:team_id>/join-requests/<uuid:req_id>/approve")(approve_join_request)
    app.post("/teams/<uuid:team_id>/join-requests/<uuid:req_id>/reject")(reject_join_request)
    app.post("/teams/<uuid:team_id>/settings")(update_team_settings)
    app.post("/teams/<uuid:team_id>/ldap-maps")(add_team_ldap_map)
    app.post("/teams/<uuid:team_id>/ldap-maps/<uuid:map_id>/delete")(delete_team_ldap_map)
    app.post("/teams/<uuid:team_id>/oidc-maps")(add_team_oidc_map)
    app.post("/teams/<uuid:team_id>/oidc-maps/<uuid:map_id>/delete")(delete_team_oidc_map)
    app.post("/teams/<uuid:team_id>/projects")(create_project)
    app.get("/teams/<uuid:team_id>/projects/new")(new_project_wizard)
    app.post("/teams/<uuid:team_id>/delete")(delete_team)
    app.post("/teams/<uuid:team_id>/projects/<uuid:project_id>/delete")(delete_project_from_team)
    app.get("/teams/<uuid:team_id>/groups/<uuid:group_id>")(team_group_detail)
    app.post("/teams/<uuid:team_id>/groups")(create_team_group)
    app.post("/teams/<uuid:team_id>/groups/<uuid:group_id>")(update_team_group)
    app.post("/teams/<uuid:team_id>/groups/<uuid:group_id>/delete")(delete_team_group)
    app.post("/teams/<uuid:team_id>/groups/<uuid:group_id>/members")(add_group_member)
    app.post(
        "/teams/<uuid:team_id>/groups/<uuid:group_id>/members/<uuid:user_id>/remove"
    )(remove_group_member)
