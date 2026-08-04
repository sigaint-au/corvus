"""OpenShift External Secrets Operator webhook + health."""

import hashlib
import logging

from flask import jsonify, request

import crypto
import db

log = logging.getLogger(__name__)


def bearer_hash():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return hashlib.sha256(auth[7:].strip().encode()).hexdigest()


def register(app):
    @app.get("/eso/v1/projects/<uuid:project_id>/secrets/<path:key>")
    def eso_get_secret(project_id, key):
        """ESO webhook: single secret. jsonPath: $.value"""
        thash = bearer_hash()
        if not thash:
            return jsonify({"error": "unauthorized"}), 401
        with db.connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT private.machine_get_enc(%s::uuid, %s, %s) AS value_enc",
                (str(project_id), thash, key),
            )
            row = cur.fetchone()
            if row and row["value_enc"]:
                return jsonify({"value": crypto.decrypt(row["value_enc"]), "key": key})
            cur.execute(
                "SELECT private.auth_machine(%s::uuid, %s) AS ok",
                (str(project_id), thash),
            )
            if not cur.fetchone()["ok"]:
                return jsonify({"error": "unauthorized"}), 401
        return jsonify({"error": "not found"}), 404

    @app.get("/eso/v1/projects/<uuid:project_id>/secrets")
    def eso_list_secrets(project_id):
        """All secrets as {key: value} map for bulk sync."""
        thash = bearer_hash()
        if not thash:
            return jsonify({"error": "unauthorized"}), 401
        with db.connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT private.auth_machine(%s::uuid, %s) AS ok",
                (str(project_id), thash),
            )
            if not cur.fetchone()["ok"]:
                return jsonify({"error": "unauthorized"}), 401
            cur.execute(
                "SELECT * FROM private.machine_list_enc(%s::uuid, %s)",
                (str(project_id), thash),
            )
            rows = cur.fetchall()
        data = {r["key"]: crypto.decrypt(r["value_enc"]) for r in rows}
        return jsonify({"secrets": data})

    @app.get("/health")
    def health():
        try:
            with db.connect() as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 503
