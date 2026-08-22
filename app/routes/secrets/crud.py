"""Secret create/update/delete and metadata routes."""

from __future__ import annotations

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException

import audit
from auth import authz
from core import config, db
from secret_svc.commands import (
    delete_secret_command,
    update_secret_value_command,
    upsert_secret_command,
)
from secret_svc.secret_kinds import (
    normalize_kind,
    parse_kv_lines,
)
from secret_svc.secret_ops import (
    _parse_access_mode,
    _parse_expires_at,
    _parse_requires_approval,
    compose_secret_value,
)

from .helpers import (
    _reveal_toggle_html,
    _secrets_redirect_or_partial,
)


@authz.login_required
def create_secret(project_id):
    """Create or upsert a secret from a project form submission.

    Args:
        project_id: UUID of the project that owns the secret.

    Returns:
        str | werkzeug.wrappers.Response: HTMX secrets partial when
            requested; otherwise a redirect to the project secrets tab.

    Example:
        POST /projects/<project_id>/secrets
    """
    key = request.form.get("key", "").strip()
    value = request.form.get("value", "")
    note = request.form.get("note", "").strip()
    kind = normalize_kind(request.form.get("kind"))
    if kind != "plain":
        flash("Structured secret types require the advanced form.", "error")
        return redirect(url_for("secret_new", project_id=project_id))
    req_appr = _parse_requires_approval(request.form)
    access_mode = _parse_access_mode(request.form)
    if not key or value is None:
        flash("Key and value required", "error")
        return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))
    try:
        expires_at = _parse_expires_at(request.form)
    except (ValueError, TypeError):
        flash("Could not save the secret. Try again.", "error")
        return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            upsert_secret_command(
                cur,
                project_id=project_id,
                key=key,
                value=value,
                note=note,
                expires_at=expires_at,
                kind=kind,
                requires_approval=req_appr,
                set_requires_approval=True,
                access_mode=access_mode,
                set_access_mode=True,
            )
            conn.commit()
        except HTTPException as e:
            conn.rollback()
            flash(str(e), "error")
    return _secrets_redirect_or_partial(project_id)


@authz.login_required
def delete_secret(project_id, secret_id):
    """Soft-delete a secret (move to trash).

    Args:
        project_id: UUID of the project that owns the secret.
        secret_id: UUID of the secret to soft-delete.

    Returns:
        str | werkzeug.wrappers.Response: HTMX secrets partial when
            requested; otherwise a redirect to the project secrets tab.

    Example:
        POST /projects/<project_id>/secrets/<secret_id>/delete
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            delete_secret_command(cur, project_id=project_id, secret_id=secret_id)
            conn.commit()
        except HTTPException as e:
            conn.rollback()
            flash(str(e), "error")
    return _secrets_redirect_or_partial(project_id)


@authz.login_required
def upsert_secret_meta(project_id, secret_id):
    """Add or update a custom metadata field (writers)."""
    key = (request.form.get("key") or "").strip()
    value = (request.form.get("value") or "").strip()
    meta_url = url_for("secret_view", project_id=project_id, secret_id=secret_id, tab="meta")
    import re

    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", key or ""):
        flash(
            "Metadata key must start with a letter/digit and use only "
            "A–Z, a–z, 0–9, ., _, - (max 64)",
            "error",
        )
        return redirect(meta_url)
    if len(value) > 2000:
        value = value[:2000]
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT api.can_access_secret(%s, 'write') AS w",
            (str(secret_id),),
        )
        if not (cur.fetchone() or {}).get("w"):
            flash("You don't have permission to do that", "error")
            return redirect(meta_url)
        try:
            cur.execute(
                """
                INSERT INTO api.secret_meta (secret_id, key, value, updated_at)
                VALUES (%s, %s, %s, now())
                ON CONFLICT (secret_id, key) DO UPDATE
                  SET value = EXCLUDED.value, updated_at = now()
                """,
                (str(secret_id), key, value),
            )
            cur.execute(
                """
                SELECT key FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            sec = cur.fetchone()
            if sec:
                audit.log_secret(
                    cur,
                    project_id=project_id,
                    secret_id=secret_id,
                    secret_key=sec["key"],
                    action="updated",
                )
            conn.commit()
            flash(f"Metadata “{key}” saved", "ok")
        except Exception:
            conn.rollback()
            flash("Could not save the secret. Try again.", "error")
    return redirect(meta_url)


@authz.login_required
def delete_secret_meta(project_id, secret_id, meta_key):
    """Remove a custom metadata field."""
    meta_url = url_for("secret_view", project_id=project_id, secret_id=secret_id, tab="meta")
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT api.can_access_secret(%s, 'write') AS w",
            (str(secret_id),),
        )
        if not (cur.fetchone() or {}).get("w"):
            flash("You don't have permission to do that", "error")
            return redirect(meta_url)
        cur.execute(
            """
            DELETE FROM api.secret_meta m
            USING api.secrets s
            WHERE m.secret_id = s.id AND s.id = %s AND s.project_id = %s
              AND m.key = %s
            RETURNING s.key
            """,
            (str(secret_id), str(project_id), meta_key),
        )
        row = cur.fetchone()
        if not row:
            flash("Field not found or not permitted", "error")
            conn.rollback()
        else:
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=secret_id,
                secret_key=row["key"],
                action="updated",
            )
            conn.commit()
            flash(f"Metadata “{meta_key}” removed", "ok")
    return redirect(meta_url)


@authz.login_required
def update_secret_value(project_id, secret_id):
    """In-place update after reveal (archives prior value via trigger).

    Args:
        project_id: UUID of the project that owns the secret.
        secret_id: UUID of the secret whose value to update.

    Returns:
        str | tuple | werkzeug.wrappers.Response: HTMX saved/masked partial
            when HTMX; redirect with flash otherwise; 400/403/404 on error.

    Example:
        POST /projects/<project_id>/secrets/<secret_id>/value
    """
    value = request.form.get("value")
    if value is None:
        return "Value required", 400
    try:
        # Always accept expires fields from edit form
        if request.form.get("clear_expires") or "expires_at" in request.form:
            expires_at = _parse_expires_at(request.form, allow_clear=True)
            set_expires = True
        else:
            expires_at = None
            set_expires = False
    except (ValueError, TypeError) as e:
        if authz.htmx():
            return str(e), 400
        flash("Could not save the secret. Try again.", "error")
        return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            update_secret_value_command(
                cur,
                project_id=project_id,
                secret_id=secret_id,
                value=value,
                expires_at=expires_at,
                set_expires=set_expires,
            )
            conn.commit()
        except HTTPException as e:
            conn.rollback()
            return str(e), e.code
    if authz.htmx():
        # Hide value again; show brief confirmation and restore Reveal control
        cell_id = f"reveal-{secret_id}"
        reveal_url = url_for("reveal_secret", project_id=project_id, secret_id=secret_id)
        body = render_template(
            "partials/reveal_saved.html",
            reveal_url=reveal_url,
            cell_id=cell_id,
        )
        body += _reveal_toggle_html(project_id, secret_id, revealed=False, cell=None)
        return body
    flash("Secret updated", "ok")
    return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))


@authz.login_required
def bulk_secrets(project_id):
    """Apply a bulk action (currently delete) to selected project secrets.

    Args:
        project_id: UUID of the project containing the secrets.

    Returns:
        werkzeug.wrappers.Response: Redirect to the project secrets tab
            with a flash message summarizing the result.

    Example:
        POST /projects/<project_id>/secrets/bulk
        form: bulk_action=delete, secret_ids=<id>...
    """
    action = (request.form.get("bulk_action") or "").strip()
    ids = request.form.getlist("secret_ids")
    back = url_for("project_detail", project_id=project_id, tab="secrets")
    if not ids:
        flash("Select at least one secret", "error")
        return redirect(back)
    if action != "delete":
        flash("Unknown bulk action", "error")
        return redirect(back)
    n = 0
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
        if not cur.fetchone()["w"]:
            flash("You don't have permission to do that", "error")
            return redirect(back)
        for sid in ids:
            cur.execute(
                """
                SELECT id, key FROM api.secrets
                WHERE id = %s::uuid AND project_id = %s AND deleted_at IS NULL
                """,
                (sid, str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                continue
            cur.execute(
                """
                UPDATE api.secrets SET deleted_at = now()
                WHERE id = %s::uuid AND project_id = %s AND deleted_at IS NULL
                """,
                (sid, str(project_id)),
            )
            if cur.rowcount:
                audit.log_secret(
                    cur,
                    project_id=project_id,
                    secret_id=row["id"],
                    secret_key=row["key"],
                    action="deleted",
                )
                n += 1
        conn.commit()
    flash(f"Moved {n} secret(s) to trash", "ok")
    return redirect(back)


@authz.login_required
def secret_new(project_id):
    """Show the new-secret form or create a secret of any kind.

    Args:
        project_id: UUID of the project that will own the new secret.

    Returns:
        str | tuple | werkzeug.wrappers.Response: New-secret form on GET
            or validation error (with status 400); redirect to project
            secrets on success; ``("Not found", 404)`` if project missing.

    Example:
        GET /projects/<project_id>/secrets/new
        POST /projects/<project_id>/secrets/new
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT p.*, t.name AS team_name
            FROM api.projects p JOIN api.teams t ON t.id = p.team_id
            WHERE p.id = %s
            """,
            (str(project_id),),
        )
        project = cur.fetchone()
        if not project:
            return "Not found", 404
        cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
        if not cur.fetchone()["w"]:
            flash("You don't have permission to do that", "error")
            return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))

    def _new_ctx(**extra):
        ctx = {
            "project": project,
            "kind": "plain",
            "key": "",
            "note": "",
            "expires_at": "",
            "kv_pairs": [("", "")],
            "secret_kinds": config.SECRET_KINDS,
            "access_mode": "inherit",
            "access_modes": config.ACCESS_MODES,
            "access_mode_labels": config.ACCESS_MODE_LABELS,
            "require_reveal_approval": bool(project.get("require_reveal_approval")),
        }
        ctx.update(extra)
        return ctx

    if request.method == "GET":
        return render_template("secret_new.html", **_new_ctx())
    kind = normalize_kind(request.form.get("kind"))
    key = (request.form.get("key") or "").strip()
    note = (request.form.get("note") or "").strip()
    value = compose_secret_value(kind, request.form)
    kv_pairs = parse_kv_lines(value) if kind == "kv" else []
    if not key or not value:
        flash("Key and value are required", "error")
        return render_template(
            "secret_new.html",
            **_new_ctx(
                kind=kind,
                key=key,
                note=note,
                expires_at=request.form.get("expires_at") or "",
                kv_pairs=kv_pairs or [("", "")],
                access_mode=_parse_access_mode(request.form),
            ),
        ), 400
    try:
        expires_at = _parse_expires_at(request.form)
    except (ValueError, TypeError):
        flash("Could not save the secret. Try again.", "error")
        return render_template(
            "secret_new.html",
            **_new_ctx(
                kind=kind,
                key=key,
                note=note,
                expires_at=request.form.get("expires_at") or "",
                kv_pairs=kv_pairs or [("", "")],
                access_mode=_parse_access_mode(request.form),
            ),
        ), 400
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            _sid, was_new = upsert_secret_command(
                cur,
                project_id=project_id,
                key=key,
                value=value,
                note=note,
                expires_at=expires_at,
                kind=kind,
                requires_approval=_parse_requires_approval(request.form),
                set_requires_approval=True,
                access_mode=_parse_access_mode(request.form),
                set_access_mode=True,
            )
            conn.commit()
            flash("Secret created" if was_new else "Secret updated", "ok")
        except HTTPException as e:
            conn.rollback()
            flash(str(e), "error")
            return render_template(
                "secret_new.html",
                **_new_ctx(
                    kind=kind,
                    key=key,
                    note=note,
                    expires_at=request.form.get("expires_at") or "",
                    kv_pairs=kv_pairs or [("", "")],
                    access_mode=_parse_access_mode(request.form),
                ),
            ), 400
    return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))
