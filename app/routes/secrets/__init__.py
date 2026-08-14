"""Secret routes package (CRUD, reveal, history, access)."""

from __future__ import annotations

from .helpers import (
    _secret_requires_approval,
    _reveal_access_state,
    _render_reveal_access_panel,
    _reveal_cell_ids,
    _reveal_toggle_html,
    _render_secret_view,
    _secrets_partial,
)
from .list import (
    secrets_list,
    shared_secrets_list,
    trash,
    restore_secret,
    purge_secret,
    bulk_trash,
)
from .crud import (
    create_secret,
    delete_secret,
    upsert_secret_meta,
    delete_secret_meta,
    update_secret_value,
    bulk_secrets,
    secret_new,
)
from .view import (
    reveal_secret,
    secret_view,
    hide_secret,
    toggle_secret_pin,
)
from .history import (
    secret_history,
    reveal_secret_version,
    hide_secret_version,
    rollback_secret,
)
from .access import (
    request_secret_access,
    approve_secret_access,
    deny_secret_access,
)
from .bindings import (
    update_secret_access,
    add_secret_access_binding,
    delete_secret_access_binding,
)


def register(app):
    app.get("/secrets")(secrets_list)
    app.get("/shared")(shared_secrets_list)
    app.get("/trash")(trash)
    app.post("/trash/secrets/<uuid:secret_id>/restore")(restore_secret)
    app.post("/trash/secrets/<uuid:secret_id>/purge")(purge_secret)
    app.post("/projects/<uuid:project_id>/secrets")(create_secret)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/delete")(delete_secret)
    app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/reveal")(reveal_secret)
    app.route(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/view",
        methods=["GET", "POST"],
    )(secret_view)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/meta")(upsert_secret_meta)
    app.post(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/meta/<path:meta_key>/delete"
    )(delete_secret_meta)
    app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/hide")(hide_secret)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/pin")(toggle_secret_pin)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/value")(update_secret_value)
    app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/history")(secret_history)
    app.get(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/versions/<uuid:version_id>/reveal"
    )(reveal_secret_version)
    app.get(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/versions/<uuid:version_id>/hide"
    )(hide_secret_version)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/access-request")(request_secret_access)
    app.post("/projects/<uuid:project_id>/access-requests/<uuid:req_id>/approve")(approve_secret_access)
    app.post("/projects/<uuid:project_id>/access-requests/<uuid:req_id>/deny")(deny_secret_access)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/rollback/<uuid:version_id>")(rollback_secret)
    app.post("/projects/<uuid:project_id>/secrets/bulk")(bulk_secrets)
    app.post("/trash/bulk")(bulk_trash)
    app.route("/projects/<uuid:project_id>/secrets/new", methods=["GET", "POST"])(secret_new)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/access")(update_secret_access)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/access/bindings")(add_secret_access_binding)
    app.post(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/access/bindings/<uuid:grant_id>/delete"
    )(delete_secret_access_binding)
