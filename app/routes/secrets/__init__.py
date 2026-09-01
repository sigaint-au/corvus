"""Secret routes package (CRUD, reveal, history, access)."""

from __future__ import annotations

from .access import (
    approve_secret_access,
    deny_secret_access,
    request_secret_access,
)
from .bindings import (
    add_secret_access_binding,
    delete_secret_access_binding,
    update_secret_access,
)
from .crud import (
    bulk_secrets,
    create_secret,
    delete_secret,
    delete_secret_meta,
    generate_ssh_key,
    secret_new,
    update_secret_value,
    upsert_secret_meta,
)
from .folders import (
    add_folder_access_binding,
    create_folder,
    delete_folder,
    delete_folder_access_binding,
    folder_view,
    update_folder_access,
)
from .history import (
    hide_secret_version,
    reveal_secret_version,
    rollback_secret,
    secret_history,
)
from .list import (
    bulk_trash,
    purge_secret,
    restore_secret,
    secrets_list,
    shared_secrets_list,
    trash,
)
from .view import (
    hide_secret,
    reveal_secret,
    secret_view,
    toggle_secret_pin,
)


def register(app):
    """Register secret listing, lifecycle, access, and reveal routes."""
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
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/meta/<path:meta_key>/delete")(
        delete_secret_meta
    )
    app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/hide")(hide_secret)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/pin")(toggle_secret_pin)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/value")(update_secret_value)
    app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/history")(secret_history)
    app.get(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/versions/<uuid:version_id>/reveal"
    )(reveal_secret_version)
    app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/versions/<uuid:version_id>/hide")(
        hide_secret_version
    )
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/access-request")(
        request_secret_access
    )
    app.post("/projects/<uuid:project_id>/access-requests/<uuid:req_id>/approve")(
        approve_secret_access
    )
    app.post("/projects/<uuid:project_id>/access-requests/<uuid:req_id>/deny")(deny_secret_access)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/rollback/<uuid:version_id>")(
        rollback_secret
    )
    app.post("/projects/<uuid:project_id>/secrets/bulk")(bulk_secrets)
    app.post("/projects/<uuid:project_id>/folders")(create_folder)
    app.get("/projects/<uuid:project_id>/folders/<uuid:folder_id>")(folder_view)
    app.post("/projects/<uuid:project_id>/folders/<uuid:folder_id>/access")(update_folder_access)
    app.post("/projects/<uuid:project_id>/folders/<uuid:folder_id>/access/bindings")(
        add_folder_access_binding
    )
    app.post(
        "/projects/<uuid:project_id>/folders/<uuid:folder_id>/access/bindings/<uuid:binding_id>/delete"
    )(delete_folder_access_binding)
    app.post("/projects/<uuid:project_id>/folders/<uuid:folder_id>/delete")(delete_folder)
    app.post("/trash/bulk")(bulk_trash)
    app.post("/projects/<uuid:project_id>/generate-ssh-key")(generate_ssh_key)
    app.route("/projects/<uuid:project_id>/secrets/new", methods=["GET", "POST"])(secret_new)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/access")(update_secret_access)
    app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/access/bindings")(
        add_secret_access_binding
    )
    app.post(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/access/bindings/<uuid:grant_id>/delete"
    )(delete_secret_access_binding)
