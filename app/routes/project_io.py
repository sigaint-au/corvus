"""Project secret import/export."""

import csv
import io
import json
import logging

from flask import Response, flash, redirect, render_template, request, session, url_for

import audit
import authz
import config
import crypto
import db
from secret_kinds import detect_secret_kind, normalize_kind, parse_secret_pairs
from secret_ops import _upsert_secret

log = logging.getLogger(__name__)

_KIND_OPTIONS = (
    ("plain", "Plain text / password"),
    ("database", "Database URL"),
    ("certificate", "Certificate (PEM)"),
    ("ssh", "SSH private key"),
    ("kv", "Key / value pairs"),
)


def _items_from_import_form():
    """Read import rows from commit form (values live in POST body, not session)."""
    keys = request.form.getlist("key")
    values = request.form.getlist("value")
    value_encs = request.form.getlist("value_enc")
    notes = request.form.getlist("note")
    kinds = request.form.getlist("kind")
    encs = request.form.getlist("enc")
    n = len(keys)
    if not n:
        return []
    # Pad shorter lists so zip doesn't silently drop rows
    def pad(lst):
        return list(lst) + [""] * (n - len(lst))

    items = []
    for key, val, venc, note, kind, enc in zip(
        keys, pad(values), pad(value_encs), pad(notes), pad(kinds), pad(encs)
    ):
        key = (key or "").strip()
        if not key:
            continue
        is_enc = (enc or "").strip() in ("1", "true", "yes")
        if is_enc:
            items.append(
                {
                    "key": key,
                    "enc": True,
                    "value_enc": venc or "",
                    "note": note or "",
                    "kind": normalize_kind(kind),
                }
            )
        else:
            items.append(
                {
                    "key": key,
                    "enc": False,
                    "value": val if val is not None else "",
                    "note": note or "",
                    "kind": normalize_kind(kind),
                }
            )
    return items


def register(app):

    @app.get("/projects/<uuid:project_id>/export")
    @authz.login_required
    def export_secrets(project_id):
        fmt = (request.args.get("format") or "env").strip().lower()
        mode = (request.args.get("mode") or "plain").strip().lower()
        if fmt not in ("env", "json", "csv"):
            fmt = "env"
        if mode not in ("plain", "enc"):
            mode = "plain"
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_read_project(%s) AS r", (str(project_id),))
            if not (cur.fetchone() or {}).get("r"):
                return "Not found", 404
            cur.execute(
                """
                SELECT key, value_enc, note FROM api.secrets
                WHERE project_id = %s AND deleted_at IS NULL
                ORDER BY key
                """,
                (str(project_id),),
            )
            rows = cur.fetchall()
            # Bulk exfil must leave an audit trail (especially plaintext)
            audit.log_secret(
                cur,
                project_id=project_id,
                action="exported",
                secret_key=f"{mode}/{fmt} n={len(rows)}",
            )
            conn.commit()
        if mode == "enc":
            payload = {
                r["key"]: {"value_enc": r["value_enc"], "note": r["note"]} for r in rows
            }
            body = json.dumps(payload, indent=2)
            return Response(
                body,
                mimetype="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="secrets-{project_id}-enc.json"'
                },
            )
        pairs = [(r["key"], crypto.decrypt(r["value_enc"])) for r in rows]
        if fmt == "json":
            body = json.dumps({k: v for k, v in pairs}, indent=2)
            mime, name = "application/json", f"secrets-{project_id}.json"
        elif fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["key", "value"])
            w.writerows(pairs)
            body = buf.getvalue()
            mime, name = "text/csv", f"secrets-{project_id}.csv"
        else:
            body = "\n".join(f"{k}={v}" for k, v in pairs) + ("\n" if pairs else "")
            mime, name = "text/plain", f"secrets-{project_id}.env"
        return Response(
            body,
            mimetype=mime,
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )


    def _read_import_payload():
        """Return (raw_text, error_message)."""
        raw = request.form.get("payload") or ""
        f = request.files.get("file")
        if f and f.filename:
            blob = f.read(config.MAX_IMPORT_BYTES + 1)
            if len(blob) > config.MAX_IMPORT_BYTES:
                return (
                    None,
                    f"Import file too large (max {config.MAX_IMPORT_BYTES // 1024} KiB)",
                )
            raw = blob.decode("utf-8", errors="replace")
        if len(raw.encode("utf-8")) > config.MAX_IMPORT_BYTES:
            return (
                None,
                f"Import payload too large (max {config.MAX_IMPORT_BYTES // 1024} KiB)",
            )
        if not raw.strip():
            return None, "Paste secrets or choose a file"
        return raw, None

    @app.post("/projects/<uuid:project_id>/import/preview")
    @authz.login_required
    def import_preview(project_id):
        back = url_for("project_detail", project_id=project_id, tab="import")
        raw, err = _read_import_payload()
        if err:
            flash(err, "error")
            return redirect(back)
        try:
            pairs = parse_secret_pairs(raw)
        except Exception as e:
            flash(f"Parse error: {e}", "error")
            return redirect(back)
        if not pairs:
            flash("No key/value pairs found", "error")
            return redirect(back)
        # Build preview rows in the response form (not the session cookie —
        # large JSON values blow past cookie size and caused "preview expired").
        pending = []
        for key, val in pairs:
            if isinstance(val, dict) and "_enc" in val:
                note = val.get("note") or ""
                pending.append(
                    {
                        "key": key,
                        "enc": True,
                        "value_enc": val["_enc"],
                        "value": "",
                        "note": note,
                        "kind": "plain",
                    }
                )
            else:
                text = "" if val is None else str(val)
                pending.append(
                    {
                        "key": key,
                        "enc": False,
                        "value": text,
                        "value_enc": "",
                        "note": "",
                        "kind": detect_secret_kind(text),
                    }
                )
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(back)
            cur.execute(
                """
                SELECT key FROM api.secrets
                WHERE project_id = %s AND deleted_at IS NULL
                """,
                (str(project_id),),
            )
            existing = {r["key"] for r in (cur.fetchall() or [])}
            cur.execute(
                """
                SELECT p.name, p.id, t.name AS team_name
                FROM api.projects p JOIN api.teams t ON t.id = p.team_id
                WHERE p.id = %s
                """,
                (str(project_id),),
            )
            project = cur.fetchone()
        if not project:
            return "Not found", 404
        creates = updates = 0
        for item in pending:
            if item["key"] in existing:
                item["action"] = "update"
                updates += 1
            else:
                item["action"] = "create"
                creates += 1
        return render_template(
            "import_preview.html",
            project=project,
            items=pending,
            n_creates=creates,
            n_updates=updates,
            kind_options=_KIND_OPTIONS,
        )

    @app.post("/projects/<uuid:project_id>/import")
    @authz.login_required
    def import_secrets(project_id):
        """Legacy direct import — prefer preview + commit."""
        return import_preview(project_id)

    @app.post("/projects/<uuid:project_id>/import/commit")
    @authz.login_required
    def import_commit(project_id):
        back = url_for("project_detail", project_id=project_id, tab="import")
        items = _items_from_import_form()
        if not items:
            flash("Nothing to import — upload again", "error")
            return redirect(back)
        n_ok = 0
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(back)
            try:
                for item in items:
                    key = item["key"]
                    if item.get("enc"):
                        sid, was_new = _upsert_secret(
                            cur,
                            project_id,
                            key,
                            item["value_enc"],
                            note=item.get("note") or "",
                            kind=item.get("kind") or "plain",
                            already_enc=True,
                            touch_meta=False,
                        )
                    else:
                        val = item.get("value") or ""
                        sid, was_new = _upsert_secret(
                            cur,
                            project_id,
                            key,
                            val,
                            note=item.get("note") or "",
                            kind=item.get("kind") or detect_secret_kind(val),
                            touch_meta=False,
                        )
                    if sid:
                        audit.log_secret(
                            cur,
                            project_id=project_id,
                            secret_id=sid,
                            secret_key=key,
                            action="created" if was_new else "updated",
                        )
                        n_ok += 1
                conn.commit()
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
                return redirect(back)
        flash(f"Imported {n_ok} secret(s)", "ok")
        return redirect(back)

    @app.post("/projects/<uuid:project_id>/export/bulk")
    @authz.login_required
    def bulk_export(project_id):
        fmt = (request.args.get("format") or request.form.get("format") or "env").strip().lower()
        if fmt not in ("env", "json", "csv"):
            fmt = "env"
        ids = request.form.getlist("secret_ids")
        if not ids:
            flash("Select at least one secret", "error")
            return redirect(
                url_for("project_detail", project_id=project_id, tab="secrets")
            )
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_read_project(%s) AS r", (str(project_id),))
            if not (cur.fetchone() or {}).get("r"):
                return "Not found", 404
            cur.execute(
                """
                SELECT key, value_enc FROM api.secrets
                WHERE project_id = %s AND deleted_at IS NULL
                  AND id = ANY(%s::uuid[])
                ORDER BY key
                """,
                (str(project_id), ids),
            )
            rows = cur.fetchall() or []
            audit.log_secret(
                cur,
                project_id=project_id,
                action="exported",
                secret_key=f"bulk/{fmt} n={len(rows)}",
            )
            conn.commit()
        pairs = [(r["key"], crypto.decrypt(r["value_enc"])) for r in rows]
        if fmt == "json":
            body = json.dumps({k: v for k, v in pairs}, indent=2)
            mime, name = "application/json", f"secrets-selected.json"
        elif fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["key", "value"])
            w.writerows(pairs)
            body = buf.getvalue()
            mime, name = "text/csv", "secrets-selected.csv"
        else:
            body = "\n".join(f"{k}={v}" for k, v in pairs) + ("\n" if pairs else "")
            mime, name = "text/plain", "secrets-selected.env"
        return Response(
            body,
            mimetype=mime,
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )
