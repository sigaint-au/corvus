"""Management API project export (PAT only)."""

from __future__ import annotations

from flask import jsonify, request

import audit
import crypto
from core import db
from secret_svc.secret_ops import fetch_project_reveal_enc_rows

from .helpers import _require_pat, _resolve_project


def mgmt_export_project(project_ref):
    """Export live project secrets as plaintext (JSON-structured for clients).

    Query: ``mode=plain|enc`` (default ``plain``). Always returns the secret
    rows the caller may reveal (ACL + approval gated). Plain mode decrypts
    values; ``enc`` returns ``value_enc`` only. Audited as ``exported``.
    """
    uid, err = _require_pat()
    if err:
        return err
    mode = (request.args.get("mode") or "plain").strip().lower()
    if mode not in ("plain", "enc"):
        mode = "plain"
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT api.can_read_project(%s) AS r", (pid,))
        if not (cur.fetchone() or {}).get("r"):
            return jsonify({"error": "not found"}), 404
        rows = fetch_project_reveal_enc_rows(cur, pid)
        audit.log_secret(
            cur,
            project_id=pid,
            action="exported",
            secret_key=f"{mode}/cli n={len(rows)}",
        )
        conn.commit()
    items = []
    for r in rows:
        item = {"key": r["key"], "note": r.get("note") or ""}
        if mode == "plain":
            item["value"] = crypto.decrypt_for_project(
                pid, r["value_enc"], r.get("crypto_provider") or "master"
            )
        else:
            item["value_enc"] = r["value_enc"]
        items.append(item)
    return jsonify({"mode": mode, "items": items})
