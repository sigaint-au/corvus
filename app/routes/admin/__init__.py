"""Global admin routes package (settings, audit, access reviews)."""

from __future__ import annotations

from .audit import (
    admin_audit,
    admin_audit_access_export,
    admin_audit_export,
)
from .settings import (
    hsm_slot_new_wizard,
    server_settings,
)


def register(app):
    """Register administration, audit, and server-settings routes."""
    app.route("/admin/audit", methods=["GET", "POST"])(admin_audit)
    app.get("/admin/audit/access/export")(admin_audit_access_export)
    app.get("/admin/audit/export")(admin_audit_export)
    app.route("/settings", methods=["GET", "POST"])(server_settings)
    app.route("/settings/encryption/hsm-slots/new", methods=["GET", "POST"])(hsm_slot_new_wizard)
