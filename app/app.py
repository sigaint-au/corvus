"""Sigaint Secret Server: Flask+HTMX UI, PostgREST JWT, OpenShift ESO webhook API."""
import logging

from flask import Flask

import config
from nav import inject_nav
from schema import ensure_schema
from routes import register_all

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


if __name__ == "__main__":
    from crypto import decrypt, encrypt

    assert decrypt(encrypt("ping")) == "ping"
    app.run(host="0.0.0.0", port=8080, debug=True)
