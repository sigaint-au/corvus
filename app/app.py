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

_schema_ready = False


@app.before_request
def _bootstrap_schema():
    global _schema_ready
    if _schema_ready:
        return
    ensure_schema()
    _schema_ready = True


app.before_request(authz.csrf_protect)


if __name__ == "__main__":
    from crypto import decrypt, encrypt

    assert decrypt(encrypt("ping")) == "ping"
    app.run(host="0.0.0.0", port=8080, debug=os.environ.get("FLASK_DEBUG") == "1")
