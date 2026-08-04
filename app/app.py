"""Sigaint Secret Server: Flask+HTMX UI, PostgREST JWT, OpenShift ESO webhook API."""
import logging

from flask import Flask

import config
from nav import inject_nav
from schema import ensure_schema
from routes import register_all

# Re-exports for unit tests and external imports (import app as store)
from authz import global_admin_required, htmx, is_global_admin, login_required  # noqa: F401
from authz import is_global_admin as _is_global_admin  # noqa: F401
from config import JWT_SECRET, POSTGREST_URL  # noqa: F401
from crypto import decrypt, encrypt  # noqa: F401
from db import as_user, connect, connect_admin, jwt_json, make_jwt  # noqa: F401
from ldap_auth import (  # noqa: F401
    group_matches,
    group_tokens,
    ldap_authenticate,
    ldap_cfg,
    ldap_escape,
    sync_ldap_user,
)
from ldap_auth import group_matches as _group_matches  # noqa: F401
from ldap_auth import group_tokens as _group_tokens  # noqa: F401
from ldap_auth import ldap_cfg as _ldap_cfg  # noqa: F401
from ldap_auth import ldap_escape as _ldap_escape  # noqa: F401
from ldap_auth import sync_ldap_user as _sync_ldap_user  # noqa: F401
from settings_svc import classification, get_settings, registration_enabled, set_setting  # noqa: F401
from settings_svc import get_settings as _get_settings  # noqa: F401
from settings_svc import registration_enabled as _registration_enabled  # noqa: F401
from settings_svc import set_setting as _set_setting  # noqa: F401

log = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

app.context_processor(inject_nav)
register_all(app)

_schema_ready = False


@app.before_request
def _bootstrap_schema():
    global _schema_ready
    if _schema_ready:
        return
    ensure_schema()
    _schema_ready = True


from routes.eso import bearer_hash as _bearer_hash  # noqa: F401, E402


if __name__ == "__main__":
    assert decrypt(encrypt("ping")) == "ping"
    app.run(host="0.0.0.0", port=8080, debug=True)
