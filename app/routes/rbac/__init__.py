"""RBAC admin UI package: Roles, Bindings, Access Review."""

from __future__ import annotations

from routes.rbac.bindings import (
    rbac_bindings,
    rbac_bindings_create,
    rbac_bindings_delete,
)
from routes.rbac.helpers import parse_rules_yaml  # noqa: F401  (package re-export)
from routes.rbac.review import rbac_access_review
from routes.rbac.roles import rbac_roles, rbac_roles_create, rbac_roles_delete


def register(app):
    """Register RBAC role, binding, and access-review routes."""
    app.get("/rbac/roles")(rbac_roles)
    app.post("/rbac/roles")(rbac_roles_create)
    app.post("/rbac/roles/<uuid:role_id>/delete")(rbac_roles_delete)
    app.get("/rbac/bindings")(rbac_bindings)
    app.post("/rbac/bindings")(rbac_bindings_create)
    app.post("/rbac/bindings/<uuid:binding_id>/delete")(rbac_bindings_delete)
    app.get("/rbac/access-review")(rbac_access_review)
