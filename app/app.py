"""Sigaint Secret Server: Flask+HTMX UI, PostgREST JWT, OpenShift ESO webhook API."""
import logging
import os

from flask import Flask

import authz
import config
from nav import inject_nav
from schema import ensure_schema
from routes import register_all

log = logging.getLogger(__name__)

config.refuse_insecure_defaults()

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
)

app.context_processor(inject_nav)
register_all(app)

import audit as _audit  # noqa: E402

app.jinja_env.filters["time_ago"] = _audit.format_time_ago
app.jinja_env.filters["time_when"] = _audit.format_when


_schema_ready = False


@app.before_request
def _bootstrap_schema():
    global _schema_ready
    if _schema_ready:
        return
    # TESTING: unit tests mock the DB and do not run real schema upgrades.
    if app.config.get("TESTING"):
        _schema_ready = True
        return
    ensure_schema()  # raises on misconfig / DB failure (do not mark ready)
    _schema_ready = True


app.before_request(authz.csrf_protect)
app.before_request(authz.validate_registered_session)


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://unpkg.com 'unsafe-inline'; "
        "style-src 'self' https://unpkg.com 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )
    if os.environ.get("COOKIE_SECURE") == "1":
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


if __name__ == "__main__":
    from crypto import decrypt, encrypt

    assert decrypt(encrypt("ping")) == "ping"
    app.run(host="0.0.0.0", port=8080, debug=os.environ.get("FLASK_DEBUG") == "1")
