"""JSON API helpers (PostgREST JWT)."""

import logging

from flask import jsonify, session

import authz
import config
import db

log = logging.getLogger(__name__)


def register(app):
    @app.get("/api/token")
    @authz.login_required
    def api_token():
        """Return JWT for PostgREST (Authorization: Bearer ...)."""
        return jsonify(
            {
                "access_token": db.make_jwt(session["user_id"]),
                "token_type": "bearer",
                "postgrest": config.POSTGREST_URL,
            }
        )
