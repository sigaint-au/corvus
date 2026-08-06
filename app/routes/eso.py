"""OpenShift External Secrets Operator webhook + health + machine write API."""

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
        """ESO webhook: single secret. jsonPath: $.value (any machine role)."""
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
        """All secrets as {key: value} map for bulk sync (any machine role)."""
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

    @app.post("/eso/v1/projects/<uuid:project_id>/secrets")
    def eso_upsert_secret(project_id):
        """Create/update a secret. Requires machine token role=write."""
        thash = bearer_hash()
        if not thash:
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        key = (body.get("key") or "").strip()
        value = body.get("value")
        note = (body.get("note") or "").strip()
        if not key or value is None:
            return jsonify({"error": "key and value required"}), 400
        with db.connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT private.machine_role(%s::uuid, %s) AS role",
                (str(project_id), thash),
            )
            row = cur.fetchone()
            role = row["role"] if row else None
            if role is None:
                return jsonify({"error": "unauthorized"}), 401
            if role != "write":
                return jsonify({"error": "token is read-only"}), 403
            cur.execute(
                """
                SELECT private.machine_upsert_enc(%s::uuid, %s, %s, %s, %s) AS id
                """,
                (str(project_id), thash, key, crypto.encrypt(str(value)), note),
            )
            out = cur.fetchone()
            if not out or not out["id"]:
                return jsonify({"error": "forbidden"}), 403
            cur.execute(
                """
                SELECT private.audit_secret(
                  %s::uuid, %s::uuid, %s, 'machine_upsert', NULL::uuid, %s
                )
                """,
                (str(project_id), str(out["id"]), key, "machine"),
            )
            conn.commit()
        return jsonify({"ok": True, "id": str(out["id"]), "key": key}), 200

    @app.get("/health")
    def health():
        try:
            with db.connect() as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
            return jsonify({"ok": True})
        except Exception:
            log.exception("health check failed")
            return jsonify({"ok": False}), 503
