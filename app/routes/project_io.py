"""Project secret import/export."""

import csv
import io
import json
import logging

from flask import Response, flash, redirect, render_template, request, session, url_for

import audit
from auth import authz
from core import config
import crypto
from core import db
from secret_svc.secret_kinds import detect_secret_kind, normalize_kind, parse_secret_pairs
from secret_svc.secret_ops import _upsert_secret, fetch_project_reveal_enc_rows

log = logging.getLogger(__name__)

_KIND_OPTIONS = (
    ("plain", "Plain text / password"),
    ("database", "Database URL"),
    ("certificate", "Certificate (PEM)"),
    ("ssh", "SSH private key"),
    ("kv", "Key / value pairs"),
)


def _items_from_import_form():
    """Read import rows from commit form (values live in POST body, not session).

    Form fields are parallel lists indexed by key; read each directly so rows
    are never silently dropped by zip.

    Returns:
        list[dict]: Import item dicts with key, enc/value or value_enc, note, and kind.
            Empty list if no keys were posted.

    Example:
        items = _items_from_import_form()
    """
    keys = request.form.getlist("key")
    if not keys:
        return []
    values = request.form.getlist("value")
    value_encs = request.form.getlist("value_enc")
    notes = request.form.getlist("note")
    kinds = request.form.getlist("kind")
    encs = request.form.getlist("enc")

    def at(lst, i):
        return lst[i] if i < len(lst) else ""

    items = []
    for i, key_raw in enumerate(keys):
        key = (key_raw or "").strip()
        if not key:
            continue
        is_enc = (at(encs, i) or "").strip() in ("1", "true", "yes")
        body = {
            "key": key,
            "enc": is_enc,
            "note": at(notes, i) or "",
            "kind": normalize_kind(at(kinds, i)),
        }
        if is_enc:
            body["value_enc"] = at(value_encs, i) or ""
        else:
            body["value"] = at(values, i) or ""
        items.append(body)
    return items


def register(app):
    """Register project import and export routes."""
    app.get("/projects/<uuid:project_id>/export")(export_secrets)
    app.post("/projects/<uuid:project_id>/import/preview")(import_preview)
    app.post("/projects/<uuid:project_id>/import")(import_secrets)
    app.post("/projects/<uuid:project_id>/import/commit")(import_commit)
    app.post("/projects/<uuid:project_id>/export/bulk")(bulk_export)

@authz.login_required
def export_secrets(project_id):
    """Export all live project secrets as env, JSON, or CSV (plain or encrypted).

    Args:
        project_id: UUID of the project whose secrets are exported.

    Returns:
        File download Response, or a 404 string if the project is not readable.

    Example:
        GET /projects/<project_id>/export?format=json&mode=plain
    """
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
        # Ciphertext only for secrets the caller may reveal
        rows = fetch_project_reveal_enc_rows(cur, project_id)
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
                "Content-Disposition": f'attachment; filename="secrets-{project_id}-enc.json"',
                "Cache-Control": "no-store",
            },
        )
    pairs = [
        (
            r["key"],
            crypto.decrypt_for_project(
                project_id, r["value_enc"], r.get("crypto_provider") or "master"
            ),
        )
        for r in rows
    ]
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
    """Return raw import text from form payload or uploaded file.

    Returns:
        tuple: (raw_text, error_message). On success error_message is None;
            on failure raw_text is None and error_message is a user-facing string.

    Example:
        raw, err = _read_import_payload()
    """
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

@authz.login_required
def import_preview(project_id):
    """Parse an import payload and render a create/update preview for commit.

    Args:
        project_id: UUID of the project to import into.

    Returns:
        Rendered import_preview template, or redirect back to import tab on error.

    Example:
        POST /projects/<project_id>/import/preview with payload or file
    """
    back = url_for("project_detail", project_id=project_id, tab="import")
    raw, err = _read_import_payload()
    if err:
        flash(err, "error")
        return redirect(back)
    try:
        pairs = parse_secret_pairs(raw)
    except Exception as e:
        flash("Import data has an invalid format.", "error")
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

@authz.login_required
def import_secrets(project_id):
    """Legacy direct import — prefer preview + commit.

    Args:
        project_id: UUID of the project to import into.

    Returns:
        Same response as import_preview (preview page or redirect).

    Example:
        POST /projects/<project_id>/import
    """
    return import_preview(project_id)

@authz.login_required
def import_commit(project_id):
    """Commit previewed import rows into the project secrets store.

    Args:
        project_id: UUID of the project to write secrets into.

    Returns:
        Redirect to the project import tab with a success or error flash.

    Example:
        POST /projects/<project_id>/import/commit with key/value form lists
    """
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
                        crypto_provider=(
                            "project" if crypto.project_has_key(project_id) else "master"
                        ),
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
            flash("Could not process the import or export. Try again.", "error")
            return redirect(back)
    flash(f"Imported {n_ok} secret(s)", "ok")
    return redirect(back)

@authz.login_required
def bulk_export(project_id):
    """Export selected secrets as env, JSON, or CSV plaintext download.

    Args:
        project_id: UUID of the project containing the selected secrets.

    Returns:
        File download Response, 404 if not readable, or redirect if none selected.

    Example:
        POST /projects/<project_id>/export/bulk with secret_ids[] and format
    """
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
        want = {str(i) for i in ids}
        rows = [
            r
            for r in fetch_project_reveal_enc_rows(cur, project_id)
            if str(r.get("id")) in want
        ]
        if not rows:
            flash(
                "No selected secrets could be exported "
                "(missing reveal permission or approval)",
                "error",
            )
            return redirect(
                url_for("project_detail", project_id=project_id, tab="secrets")
            )
        skipped = len(ids) - len(rows)
        audit.log_secret(
            cur,
            project_id=project_id,
            action="exported",
            secret_key=f"bulk/{fmt} n={len(rows)}",
        )
        conn.commit()
        if skipped > 0:
            flash(
                f"Exported {len(rows)} secret(s); "
                f"skipped {skipped} without reveal permission",
                "ok",
            )
    pairs = [
        (
            r["key"],
            crypto.decrypt_for_project(
                project_id, r["value_enc"], r.get("crypto_provider") or "master"
            ),
        )
        for r in rows
    ]
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
