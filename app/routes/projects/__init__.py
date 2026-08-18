"""Project routes package (search, detail, access)."""

from __future__ import annotations

from secret_svc.secret_kinds import expires_status, parse_secret_pairs, secret_due_status

from .access import (
    add_project_binding,
    add_project_group_role,
    project_access_binding_create,
    project_access_binding_delete,
    remove_project_binding,
    remove_project_group_role,
)
from .detail import (
    delete_project,
    project_crypto_action,
    project_detail,
    projects_list,
    update_project_settings,
)
from .search import (
    access_requests_inbox,
    global_search,
)

__all__ = ["register", "expires_status", "parse_secret_pairs", "secret_due_status"]


def register(app):
    """Register project listing, lifecycle, settings, and access routes."""
    app.get("/search")(global_search)
    app.get("/access-requests")(access_requests_inbox)
    app.get("/projects")(projects_list)
    app.get("/projects/<uuid:project_id>")(project_detail)
    app.post("/projects/<uuid:project_id>/delete")(delete_project)
    app.post("/projects/<uuid:project_id>/members")(add_project_binding)
    app.post("/projects/<uuid:project_id>/members/<uuid:user_id>/remove")(remove_project_binding)
    app.post("/projects/<uuid:project_id>/group-roles")(add_project_group_role)
    app.post("/projects/<uuid:project_id>/group-roles/<uuid:group_id>/remove")(remove_project_group_role)
    app.post("/projects/<uuid:project_id>/access/bindings")(project_access_binding_create)
    app.post("/projects/<uuid:project_id>/access/bindings/<uuid:binding_id>/delete")(project_access_binding_delete)
    app.post("/projects/<uuid:project_id>/settings")(update_project_settings)
    app.post("/projects/<uuid:project_id>/crypto")(project_crypto_action)
