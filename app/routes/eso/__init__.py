"""ESO machine/CLI secret API package."""

from __future__ import annotations

from .http import bearer_hash, bearer_raw

from .helpers import (
    _meta_item,
    _parse_auth,
    _machine_actor,
    _audit,
    _parse_expires_from_body,
    _require_machine_write,
    _resolve_project_ref,
    _pat_can_write,
    _meta_list_query,
    _upsert_body,
)
from .projects import eso_list_projects
from .secrets import (
    eso_get_secret,
    eso_list_secrets,
)
from .access import (
    eso_request_secret_access,
    eso_list_access_requests,
    eso_approve_access_request,
    eso_deny_access_request,
)
from .write import (
    eso_upsert_secret,
    eso_put_secret,
    eso_patch_secret,
    eso_delete_secret,
)
from .health import health


def register(app):
    app.get("/eso/v1/projects")(eso_list_projects)
    app.get("/eso/v1/projects/<project_ref>/secrets/<path:key>")(eso_get_secret)
    app.post("/eso/v1/projects/<project_ref>/secrets/<path:key>/access-request")(eso_request_secret_access)
    app.get("/eso/v1/projects/<project_ref>/access-requests")(eso_list_access_requests)
    app.post("/eso/v1/projects/<project_ref>/access-requests/<req_id>/approve")(eso_approve_access_request)
    app.post("/eso/v1/projects/<project_ref>/access-requests/<req_id>/deny")(eso_deny_access_request)
    app.get("/eso/v1/projects/<project_ref>/secrets")(eso_list_secrets)
    app.post("/eso/v1/projects/<project_ref>/secrets")(eso_upsert_secret)
    app.put("/eso/v1/projects/<project_ref>/secrets/<path:key>")(eso_put_secret)
    app.patch("/eso/v1/projects/<project_ref>/secrets/<path:key>")(eso_patch_secret)
    app.delete("/eso/v1/projects/<project_ref>/secrets/<path:key>")(eso_delete_secret)
    app.get("/health")(health)
