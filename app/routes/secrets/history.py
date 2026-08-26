"""Secret version history and rollback routes."""

from __future__ import annotations

from flask import (
    flash,
    redirect,
    render_template,
    session,
    url_for,
)

import audit
import crypto
from auth import authz
from core import db, settings_svc
from secret_svc.secret_kinds import (
    STRUCTURED_VIEW_KINDS,
    normalize_kind,
)
from secret_svc.secret_ops import fetch_secret_version_enc

from .helpers import (
    _render_reveal_access_panel,
    _reveal_access_state,
    _reveal_toggle_html,
)


@authz.login_required
def secret_history(project_id, secret_id):
    """Show version history for a secret.

    Args:
        project_id: UUID of the project that owns the secret.
        secret_id: UUID of the secret whose history to display.

    Returns:
        str | tuple: Rendered ``secret_history.html``, or
            ``("Not found", 404)`` if the secret is missing.

    Example:
        GET /projects/<project_id>/secrets/<secret_id>/history
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, key, note, updated_at, expires_at
            FROM api.secrets
            WHERE id = %s AND project_id = %s AND deleted_at IS NULL
            """,
            (str(secret_id), str(project_id)),
        )
        secret = cur.fetchone()
        if not secret:
            return "Not found", 404
        cur.execute(
            """
            SELECT id, note, created_at
            FROM api.secret_versions
            WHERE secret_id = %s
            ORDER BY created_at DESC
            LIMIT 50
            """,
            (str(secret_id),),
        )
        versions = cur.fetchall()
        cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
        can_write = cur.fetchone()["w"]
        cur.execute(
            """
            SELECT p.name, p.id, t.name AS team_name, t.id AS team_id
            FROM api.projects p JOIN api.teams t ON t.id = p.team_id
            WHERE p.id = %s
            """,
            (str(project_id),),
        )
        project = cur.fetchone()
    return render_template(
        "secret_history.html",
        project=project,
        secret=secret,
        versions=versions,
        can_write=can_write,
        project_id=project_id,
    )


@authz.login_required
def reveal_secret_version(project_id, secret_id, version_id):
    """Decrypt and show a historical secret version inline (audited).

    Args:
        project_id: UUID of the project that owns the secret.
        secret_id: UUID of the parent secret.
        version_id: UUID of the archived version to reveal.

    Returns:
        str | tuple: HTML reveal fragment (and OOB toggle for HTMX), or
            ``("Not found", 404)`` when the version is missing.

    Example:
        GET /projects/<project_id>/secrets/<secret_id>/versions/<version_id>/reveal
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT s.key, s.note, s.kind, s.id AS secret_id
            FROM api.secret_versions v
            JOIN api.secrets s ON s.id = v.secret_id
            WHERE v.id = %s AND s.id = %s AND s.project_id = %s
              AND s.deleted_at IS NULL
            """,
            (str(version_id), str(secret_id), str(project_id)),
        )
        row = cur.fetchone()
        if not row:
            return "Not found", 404
        access_state, access_row = _reveal_access_state(
            cur, project_id, secret_id, session["user_id"]
        )
        if access_state == "denied":
            return ("Forbidden", 403)
        if access_state != "allowed":
            return _render_reveal_access_panel(
                project_id=project_id,
                secret_id=secret_id,
                secret_key=row["key"],
                state=access_state,
                request_row=access_row,
                version_id=version_id,
            )
        enc = fetch_secret_version_enc(cur, version_id, secret_id)
        if not enc:
            return ("Forbidden", 403)
        try:
            plaintext = crypto.decrypt_for_project(
                project_id, enc["value_enc"], enc.get("crypto_provider") or "master"
            )
        except ValueError as e:
            conn.rollback()
            return str(e), 422
        audit.log_secret(
            cur,
            project_id=project_id,
            secret_id=row["secret_id"],
            secret_key=row["key"],
            action="revealed",
        )
        conn.commit()
    kind = normalize_kind(row.get("kind"))
    structured = kind in STRUCTURED_VIEW_KINDS
    body = render_template(
        "partials/reveal.html",
        value=plaintext,
        secret_id=secret_id,
        project_id=project_id,
        version_id=version_id,
        kind=kind,
        view_url=url_for(
            "secret_view",
            project_id=project_id,
            secret_id=secret_id,
            version_id=version_id,
        )
        if structured
        else None,
        editable=False,
        can_write=False,
        is_pinned=False,
        clipboard_clear_seconds=settings_svc.int_setting("clipboard_clear_seconds", 30),
    )
    if authz.htmx():
        body += _reveal_toggle_html(
            project_id,
            secret_id,
            revealed=True,
            version_id=version_id,
        )
    return body


@authz.login_required
def hide_secret_version(project_id, secret_id, version_id):
    """Mask a revealed historical secret version (client re-mask; no audit).

    Args:
        project_id: UUID of the project that owns the secret.
        secret_id: UUID of the parent secret.
        version_id: UUID of the version cell to re-mask.

    Returns:
        str: HTML masked fragment, plus OOB toggle when HTMX.

    Example:
        GET /projects/<project_id>/secrets/<secret_id>/versions/<version_id>/hide
    """
    cell_id = f"reveal-v-{version_id}"
    reveal_url = url_for(
        "reveal_secret_version",
        project_id=project_id,
        secret_id=secret_id,
        version_id=version_id,
    )
    body = render_template(
        "partials/secret_masked.html",
        reveal_url=reveal_url,
        cell_id=cell_id,
    )
    if authz.htmx():
        body += _reveal_toggle_html(
            project_id,
            secret_id,
            revealed=False,
            version_id=version_id,
        )
    return body


@authz.login_required
def rollback_secret(project_id, secret_id, version_id):
    """Restore the current secret value from a historical version.

    Args:
        project_id: UUID of the project that owns the secret.
        secret_id: UUID of the secret to roll back.
        version_id: UUID of the version whose value/note to restore.

    Returns:
        werkzeug.wrappers.Response: Redirect to the secret history page.

    Example:
        POST /projects/<project_id>/secrets/<secret_id>/rollback/<version_id>
    """
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT s.id, s.key, v.note
            FROM api.secret_versions v
            JOIN api.secrets s ON s.id = v.secret_id
            WHERE v.id = %s AND s.id = %s AND s.project_id = %s
              AND s.deleted_at IS NULL
            """,
            (str(version_id), str(secret_id), str(project_id)),
        )
        row = cur.fetchone()
        if not row:
            flash("Version not found", "error")
            return redirect(url_for("secret_history", project_id=project_id, secret_id=secret_id))
        enc = fetch_secret_version_enc(cur, version_id, secret_id)
        if not enc:
            flash("You don't have permission to do that", "error")
            return redirect(url_for("secret_history", project_id=project_id, secret_id=secret_id))
        cur.execute(
            """
            UPDATE api.secrets
            SET value_enc = %s, note = %s, crypto_provider = %s
            WHERE id = %s AND project_id = %s AND deleted_at IS NULL
            """,
            (
                enc["value_enc"],
                row["note"] or "",
                enc.get("crypto_provider") or "master",
                str(secret_id),
                str(project_id),
            ),
        )
        if cur.rowcount == 0:
            flash("You don't have permission to do that", "error")
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
            flash("Rolled back to selected version", "ok")
    return redirect(url_for("secret_history", project_id=project_id, secret_id=secret_id))
