"""ESO health route."""

from __future__ import annotations

import logging
from flask import jsonify
from core import db
log = logging.getLogger(__name__)


def health():
    """Report application and database connectivity health.

    Args:
        None

    Returns:
        flask.Response: JSON ``{"ok": true}`` on success, or
            ``{"ok": false}`` with status 503 if the DB check fails.

    Example:
        GET /health
    """
    try:
        with db.connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
        return jsonify({"ok": True})
    except Exception:
        log.exception("health check failed")
        return jsonify({"ok": False}), 503
