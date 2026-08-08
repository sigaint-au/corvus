"""Secret CRUD, reveal, history, trash."""

import logging

from flask import flash, make_response, redirect, render_template, request, session, url_for

import audit
import authz
import config
import crypto
import db
import paging
import pins
from secret_kinds import (
    STRUCTURED_VIEW_KINDS,
    as_utc,
    normalize_kind,
    parse_database_url,
    parse_kv_lines,
    parse_pem_blocks,
    split_cert_and_key,
)
from secret_ops import (
    _load_secrets_page,
    _parse_expires_at,
    _upsert_secret,
    compose_secret_value,
)

log = logging.getLogger(__name__)


def register(app):
    """Register secret CRUD, reveal, history, and trash routes on the app.

    Args:
        app: Flask application instance to attach routes to.

    Returns:
        None

    Example:
        >>> from routes.secrets import register
        >>> register(app)
    """

    @app.get("/secrets")
    @authz.login_required
    def secrets_list():
        """List all non-deleted secrets for the current team with optional search.

        Args:
            None

        Returns:
            str: Rendered ``secrets.html`` template with team, secrets, and
                search query context.

        Example:
            GET /secrets?q=password
        """
        tid = session.get("team_id")
        q = (request.args.get("q") or "").strip()
        team, secrets = None, []
        if tid:
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
                team = cur.fetchone()
                if team:
                    sql = """
                        SELECT s.id, s.key, s.note, s.kind, s.updated_at,
                               p.id AS project_id, p.name AS project_name
                        FROM api.secrets s
                        JOIN api.projects p ON p.id = s.project_id
                        WHERE p.team_id = %s AND s.deleted_at IS NULL
                    """
                    params = [tid]
                    if q:
                        like = f"%{q}%"
                        sql += " AND (s.key ILIKE %s OR s.note ILIKE %s OR p.name ILIKE %s)"
                        params.extend([like, like, like])
                    cur.execute(sql + " ORDER BY p.name, s.key", params)
                    secrets = cur.fetchall()
        return render_template("secrets.html", team=team, secrets=secrets, search_q=q)


    @app.get("/trash")
    @authz.login_required
    def trash():
        """List soft-deleted secrets for the current team with optional search.

        Args:
            None

        Returns:
            str: Rendered ``trash.html`` template with team, trash items, and
                search query context.

        Example:
            GET /trash?q=old-key
        """
        tid = session.get("team_id")
        team, items = None, []
        q = (request.args.get("q") or "").strip()
        if tid:
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
                team = cur.fetchone()
                if team:
                    if q:
                        like = f"%{q}%"
                        cur.execute(
                            """
                            SELECT s.id, s.key, s.note, s.deleted_at, s.project_id,
                                   p.name AS project_name,
                                   api.can_write_project(s.project_id) AS can_write
                            FROM api.secrets s
                            JOIN api.projects p ON p.id = s.project_id
                            WHERE p.team_id = %s AND s.deleted_at IS NOT NULL
                              AND (
                                s.key ILIKE %s OR s.note ILIKE %s
                                OR p.name ILIKE %s
                              )
                            ORDER BY s.deleted_at DESC
                            """,
                            (tid, like, like, like),
                        )
                    else:
                        cur.execute(
                            """
                            SELECT s.id, s.key, s.note, s.deleted_at, s.project_id,
                                   p.name AS project_name,
                                   api.can_write_project(s.project_id) AS can_write
                            FROM api.secrets s
                            JOIN api.projects p ON p.id = s.project_id
                            WHERE p.team_id = %s AND s.deleted_at IS NOT NULL
                            ORDER BY s.deleted_at DESC
                            """,
                            (tid,),
                        )
                    items = cur.fetchall()
        return render_template(
            "trash.html", team=team, items=items, search_q=q
        )


    @app.post("/trash/secrets/<uuid:secret_id>/restore")
    @authz.login_required
    def restore_secret(secret_id):
        """Restore a soft-deleted secret from the trash.

        Args:
            secret_id: UUID of the soft-deleted secret to restore.

        Returns:
            werkzeug.wrappers.Response: Redirect to the trash page, preserving
                the search query when present.

        Example:
            POST /trash/secrets/<secret_id>/restore
        """
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    SELECT id, project_id, key FROM api.secrets
                    WHERE id = %s AND deleted_at IS NOT NULL
                      AND api.can_write_project(project_id)
                    """,
                    (str(secret_id),),
                )
                row = cur.fetchone()
                if not row:
                    flash("Could not restore — missing permission or key already exists", "error")
                    conn.commit()
                    return redirect(url_for("trash", q=request.args.get("q") or None))
                cur.execute(
                    """
                    UPDATE api.secrets
                    SET deleted_at = NULL
                    WHERE id = %s AND deleted_at IS NOT NULL
                    """,
                    (str(secret_id),),
                )
                if cur.rowcount == 0:
                    flash("Could not restore — missing permission or key already exists", "error")
                else:
                    audit.log_secret(
                        cur,
                        project_id=row["project_id"],
                        secret_id=row["id"],
                        secret_key=row["key"],
                        action="restored",
                    )
                    flash("Secret restored", "ok")
                conn.commit()
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("trash", q=request.args.get("q") or None))


    @app.post("/trash/secrets/<uuid:secret_id>/purge")
    @authz.login_required
    def purge_secret(secret_id):
        """Permanently delete a soft-deleted secret from the trash.

        Args:
            secret_id: UUID of the soft-deleted secret to purge.

        Returns:
            werkzeug.wrappers.Response: Redirect to the trash page, preserving
                the search query when present.

        Example:
            POST /trash/secrets/<secret_id>/purge
        """
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, project_id, key FROM api.secrets
                WHERE id = %s AND deleted_at IS NOT NULL
                  AND api.can_write_project(project_id)
                """,
                (str(secret_id),),
            )
            row = cur.fetchone()
            if row:
                audit.log_secret(
                    cur,
                    project_id=row["project_id"],
                    secret_id=row["id"],
                    secret_key=row["key"],
                    action="purged",
                )
                cur.execute(
                    """
                    DELETE FROM api.secrets
                    WHERE id = %s AND deleted_at IS NOT NULL
                    """,
                    (str(secret_id),),
                )
            conn.commit()
        return redirect(url_for("trash", q=request.args.get("q") or None))


    @app.post("/projects/<uuid:project_id>/secrets")
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
        key = request.form["key"].strip()
        value = request.form["value"]
        note = request.form.get("note", "").strip()
        kind = normalize_kind(request.form.get("kind"))
        if not key or value is None:
            flash("Key and value required", "error")
            return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))
        try:
            expires_at = _parse_expires_at(request.form)
        except (ValueError, TypeError) as e:
            flash(str(e), "error")
            return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                sid, was_new = _upsert_secret(
                    cur,
                    project_id,
                    key,
                    value,
                    note=note,
                    expires_at=expires_at,
                    kind=kind,
                )
                if not sid:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    audit.log_secret(
                        cur,
                        project_id=project_id,
                        secret_id=sid,
                        secret_key=key,
                        action="created" if was_new else "updated",
                    )
                    conn.commit()
            except Exception as e:
                flash(str(e), "error")
        if authz.htmx():
            return _secrets_partial(project_id)
        return redirect(
            url_for(
                "project_detail",
                project_id=project_id,
                tab="secrets",
                page=paging.page_arg("page"),
                q=paging.list_state_q() or None,
            )
        )


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/delete")
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
            cur.execute(
                """
                SELECT id, key FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                flash("Secret not found", "error")
            else:
                cur.execute(
                    """
                    UPDATE api.secrets SET deleted_at = now()
                    WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                    """,
                    (str(secret_id), str(project_id)),
                )
                if cur.rowcount == 0:
                    # SELECT allowed (read), UPDATE blocked (write) — e.g. read-only role
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    audit.log_secret(
                        cur,
                        project_id=project_id,
                        secret_id=row["id"],
                        secret_key=row["key"],
                        action="deleted",
                    )
                    conn.commit()
        if authz.htmx():
            return _secrets_partial(project_id)
        return redirect(
            url_for(
                "project_detail",
                project_id=project_id,
                tab="secrets",
                page=paging.page_arg("page"),
                q=paging.list_state_q() or None,
            )
        )


    def _reveal_cell_ids(secret_id, cell: str | None = None, version_id=None):
        """Return HTMX element ids for a reveal/hide target cell and toggle.

        Args:
            secret_id: UUID of the secret being revealed or hidden.
            cell: Optional cell discriminator (e.g. ``"current"``) for
                multi-cell layouts; ignored when ``version_id`` is set.
            version_id: Optional version UUID; when set, version-specific
                element ids are returned.

        Returns:
            tuple[str, str]: Pair of ``(cell_id, toggle_id)`` HTML element ids.

        Example:
            >>> cell_id, toggle_id = _reveal_cell_ids(secret_id, cell="current")
        """
        if version_id is not None:
            return f"reveal-v-{version_id}", f"reveal-toggle-v-{version_id}"
        if (cell or "").strip().lower() == "current":
            return (
                f"reveal-current-{secret_id}",
                f"reveal-toggle-current-{secret_id}",
            )
        return f"reveal-{secret_id}", f"reveal-toggle-{secret_id}"

    def _reveal_toggle_html(
        project_id,
        secret_id,
        *,
        revealed: bool,
        cell: str | None = None,
        version_id=None,
    ):
        """Render the out-of-band HTMX reveal/hide toggle partial.

        Args:
            project_id: UUID of the project that owns the secret.
            secret_id: UUID of the secret.
            revealed: Whether the secret value is currently shown.
            cell: Optional cell discriminator for multi-cell layouts.
            version_id: Optional version UUID for history reveal toggles.

        Returns:
            str: Rendered ``partials/reveal_toggle.html`` HTML fragment with
                OOB swap enabled.

        Example:
            >>> html = _reveal_toggle_html(project_id, secret_id, revealed=True)
        """
        cell_id, toggle_id = _reveal_cell_ids(secret_id, cell, version_id)
        if version_id is not None:
            reveal_url = url_for(
                "reveal_secret_version",
                project_id=project_id,
                secret_id=secret_id,
                version_id=version_id,
            )
            hide_url = url_for(
                "hide_secret_version",
                project_id=project_id,
                secret_id=secret_id,
                version_id=version_id,
            )
        else:
            kwargs = {"project_id": project_id, "secret_id": secret_id}
            if cell:
                kwargs["cell"] = cell
            reveal_url = url_for("reveal_secret", **kwargs)
            hide_url = url_for("hide_secret", **kwargs)
        return render_template(
            "partials/reveal_toggle.html",
            toggle_id=toggle_id,
            cell_id=cell_id,
            reveal_url=reveal_url,
            hide_url=hide_url,
            revealed=revealed,
            oob=True,
        )

    @app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/reveal")
    @authz.login_required
    def reveal_secret(project_id, secret_id):
        """Decrypt and show a secret value inline (audited).

        Args:
            project_id: UUID of the project that owns the secret.
            secret_id: UUID of the secret to reveal.

        Returns:
            str | tuple: HTML fragment with plaintext (and OOB toggle for HTMX),
                or ``("Not found", 404)`` when the secret is missing.

        Example:
            GET /projects/<project_id>/secrets/<secret_id>/reveal?cell=current
        """
        cell = (request.args.get("cell") or "").strip() or None
        force_inline = (request.args.get("inline") or "").strip() in ("1", "true", "yes")
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, key, value_enc, note, kind, expires_at FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = bool(cur.fetchone()["w"])
            try:
                pins.touch_recent(cur, session["user_id"], secret_id)
            except Exception:
                pass
            is_fav = False
            try:
                is_fav = pins.is_pinned(cur, session["user_id"], secret_id)
            except Exception:
                pass
            plaintext = crypto.decrypt(row["value_enc"])
            kind = normalize_kind(row.get("kind"))
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=row["id"],
                secret_key=row["key"],
                action="revealed",
            )
            conn.commit()
        exp = row.get("expires_at")
        exp_date = ""
        exp_display = ""
        if exp is not None:
            try:
                exp_date = as_utc(exp).date().isoformat()
            except Exception:
                exp_date = str(exp)[:10]
            exp_display = audit.format_expires(exp)
        # Always expand inline for a consistent list UX. Structured kinds get a
        # preview + "Open full view"; plain single/multi-line stay in the cell.
        structured = kind in STRUCTURED_VIEW_KINDS
        view_url = url_for(
            "secret_view", project_id=project_id, secret_id=secret_id
        )
        # force_inline kept for callers; no longer gates redirect.
        del force_inline
        body = render_template(
            "partials/reveal.html",
            value=plaintext,
            secret_id=secret_id,
            project_id=project_id,
            kind=kind,
            view_url=view_url,
            editable=not structured,
            can_write=can_write and not structured,
            is_pinned=is_fav,
            expires_at=exp_date,
            expires_display=exp_display,
            clipboard_clear_seconds=config.CLIPBOARD_CLEAR_SECONDS,
        )
        if authz.htmx():
            body += _reveal_toggle_html(
                project_id, secret_id, revealed=True, cell=cell
            )
        return body

    def _render_secret_view(
        *,
        project_id,
        secret_id,
        row,
        plaintext: str,
        kind: str,
        can_write: bool,
        is_version: bool = False,
        status: int = 200,
    ):
        """Render the type-specific secret view/edit page template.

        Args:
            project_id: UUID of the project that owns the secret.
            secret_id: UUID of the secret being viewed.
            row: Mapping with secret metadata (key, note, expires_at,
                project_name, etc.).
            plaintext: Decrypted secret value.
            kind: Normalized secret kind (e.g. ``"kv"``, ``"certificate"``).
            can_write: Whether the current user may edit the secret.
            is_version: If True, render a historical version (read-only).
            status: HTTP status code to pair with the rendered body.

        Returns:
            tuple: ``(html_body, status)`` for the secret view page.

        Example:
            >>> body, code = _render_secret_view(
            ...     project_id=pid, secret_id=sid, row=row,
            ...     plaintext=text, kind="kv", can_write=True,
            ... )
        """
        exp = row.get("expires_at")
        exp_date = ""
        if exp is not None:
            try:
                exp_date = as_utc(exp).date().isoformat()
            except Exception:
                exp_date = str(exp)[:10]
        cert_pem, cert_key = ("", "")
        if kind == "certificate":
            cert_pem, cert_key = split_cert_and_key(plaintext)
        return (
            render_template(
                "secret_view.html",
                project_id=project_id,
                project_name=row.get("project_name") or "",
                secret_id=secret_id,
                secret_key=row["key"],
                note=(row.get("note") or ""),
                kind=kind,
                value=plaintext,
                is_version=is_version,
                kv_pairs=parse_kv_lines(plaintext) if kind == "kv" else [("", "")],
                pem_blocks=parse_pem_blocks(plaintext)
                if kind in ("certificate", "ssh")
                else [],
                cert_pem=cert_pem,
                cert_key=cert_key,
                db_parts=parse_database_url(plaintext) if kind == "database" else {},
                expires_at=exp_date,
                can_write=can_write and not is_version,
                clipboard_clear_seconds=config.CLIPBOARD_CLEAR_SECONDS,
            ),
            status,
        )

    @app.route(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/view",
        methods=["GET", "POST"],
    )
    @authz.login_required
    def secret_view(project_id, secret_id):
        """Type-specific view/edit page (KV, cert, SSH, database URL).

        Args:
            project_id: UUID of the project that owns the secret.
            secret_id: UUID of the secret to view or update.

        Returns:
            tuple | werkzeug.wrappers.Response: ``(html, status)`` for GET or
                failed POST validation; redirect on successful POST or when
                unauthorized; ``("Not found", 404)`` if missing.

        Example:
            GET /projects/<project_id>/secrets/<secret_id>/view
            POST /projects/<project_id>/secrets/<secret_id>/view
            GET /projects/<project_id>/secrets/<secret_id>/view?version_id=<id>
        """
        version_id = (request.args.get("version_id") or "").strip() or None
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at,
                       p.name AS project_name
                FROM api.secrets s
                JOIN api.projects p ON p.id = s.project_id
                WHERE s.id = %s AND s.project_id = %s AND s.deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            value_enc = row["value_enc"]
            is_version = False
            if version_id:
                cur.execute(
                    """
                    SELECT value_enc FROM api.secret_versions
                    WHERE id = %s::uuid AND secret_id = %s::uuid
                    """,
                    (version_id, str(secret_id)),
                )
                ver = cur.fetchone()
                if not ver:
                    return "Not found", 404
                value_enc = ver["value_enc"]
                is_version = True
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = bool(cur.fetchone()["w"])

            if request.method == "POST":
                if is_version or not can_write:
                    flash("You don't have permission to do that", "error")
                    return redirect(
                        url_for(
                            "secret_view",
                            project_id=project_id,
                            secret_id=secret_id,
                        )
                    )
                kind = normalize_kind(request.form.get("kind") or row.get("kind"))
                value = compose_secret_value(kind, request.form)
                if kind == "plain":
                    value = request.form.get("plain_value") or value or ""
                if kind == "ssh" and not value:
                    value = (request.form.get("ssh_key") or "").strip()
                note = (request.form.get("note") or "").strip()
                row_view = dict(row)
                row_view["note"] = note
                row_view["kind"] = kind
                row_view["project_name"] = row.get("project_name") or ""
                if not value:
                    flash("Value is required", "error")
                    body, code = _render_secret_view(
                        project_id=project_id,
                        secret_id=secret_id,
                        row=row_view,
                        plaintext=crypto.decrypt(row["value_enc"]),
                        kind=kind,
                        can_write=True,
                        status=400,
                    )
                    return body, code
                try:
                    expires_at = _parse_expires_at(request.form, allow_clear=True)
                except (ValueError, TypeError) as e:
                    flash(str(e), "error")
                    body, code = _render_secret_view(
                        project_id=project_id,
                        secret_id=secret_id,
                        row=row_view,
                        plaintext=value,
                        kind=kind,
                        can_write=True,
                        status=400,
                    )
                    return body, code
                cur.execute(
                    """
                    UPDATE api.secrets
                    SET value_enc = %s, note = %s, expires_at = %s, kind = %s
                    WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                    """,
                    (
                        crypto.encrypt(value),
                        note,
                        expires_at,
                        kind,
                        str(secret_id),
                        str(project_id),
                    ),
                )
                if cur.rowcount == 0:
                    conn.rollback()
                    flash("You don't have permission to do that", "error")
                    return redirect(
                        url_for("project_detail", project_id=project_id, tab="secrets")
                    )
                audit.log_secret(
                    cur,
                    project_id=project_id,
                    secret_id=row["id"],
                    secret_key=row["key"],
                    action="updated",
                )
                conn.commit()
                flash("Secret updated", "ok")
                return redirect(
                    url_for(
                        "secret_view",
                        project_id=project_id,
                        secret_id=secret_id,
                    )
                )

            try:
                pins.touch_recent(cur, session["user_id"], secret_id)
            except Exception:
                pass
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=row["id"],
                secret_key=row["key"],
                action="revealed",
            )
            conn.commit()
        plaintext = crypto.decrypt(value_enc)
        kind = normalize_kind(row.get("kind"))
        body, code = _render_secret_view(
            project_id=project_id,
            secret_id=secret_id,
            row=row,
            plaintext=plaintext,
            kind=kind,
            can_write=can_write,
            is_version=is_version,
        )
        return body, code

    @app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/hide")
    @authz.login_required
    def hide_secret(project_id, secret_id):
        """Mask a revealed secret (client re-mask; no audit).

        Args:
            project_id: UUID of the project that owns the secret.
            secret_id: UUID of the secret to re-mask.

        Returns:
            str: HTML fragment for the masked cell, plus OOB toggle when HTMX.

        Example:
            GET /projects/<project_id>/secrets/<secret_id>/hide?cell=current
        """
        cell = (request.args.get("cell") or "").strip() or None
        cell_id, _toggle_id = _reveal_cell_ids(secret_id, cell)
        reveal_url = url_for(
            "reveal_secret", project_id=project_id, secret_id=secret_id
        )
        if cell:
            reveal_url = url_for(
                "reveal_secret",
                project_id=project_id,
                secret_id=secret_id,
                cell=cell,
            )
        body = render_template(
            "partials/secret_masked.html",
            reveal_url=reveal_url,
            cell_id=cell_id,
        )
        if authz.htmx():
            body += _reveal_toggle_html(
                project_id, secret_id, revealed=False, cell=cell
            )
        return body


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/pin")
    @authz.login_required
    def toggle_secret_pin(project_id, secret_id):
        """Pin or unpin a secret for the current user.

        Args:
            project_id: UUID of the project that owns the secret.
            secret_id: UUID of the secret to pin or unpin.

        Returns:
            str | tuple | werkzeug.wrappers.Response: HTMX pin button plus
                sidebar OOB fragment when HTMX; redirect to project secrets
                otherwise; ``("Not found", 404)`` if the secret is missing.

        Example:
            POST /projects/<project_id>/secrets/<secret_id>/pin
        """
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            if not cur.fetchone():
                return "Not found", 404
            if pins.is_pinned(cur, session["user_id"], secret_id):
                pins.unpin(cur, session["user_id"], secret_id)
                pinned = False
            else:
                pins.pin(cur, session["user_id"], secret_id)
                pinned = True
            pin_rows = pins.list_pins(cur, session["user_id"])
            conn.commit()
        if authz.htmx():
            btn = render_template(
                "partials/pin_button.html",
                project_id=project_id,
                secret_id=secret_id,
                is_pinned=pinned,
            )
            oob = render_template(
                "partials/side_pins.html",
                nav_pins=pin_rows,
                oob=True,
            )
            return btn + oob
        return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/value")
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
            flash(str(e), "error")
            return redirect(
                url_for("project_detail", project_id=project_id, tab="secrets")
            )
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                return "Forbidden", 403
            cur.execute(
                """
                SELECT id, key FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            if set_expires:
                cur.execute(
                    """
                    UPDATE api.secrets SET value_enc = %s, expires_at = %s
                    WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                    """,
                    (
                        crypto.encrypt(value),
                        expires_at,
                        str(secret_id),
                        str(project_id),
                    ),
                )
            else:
                cur.execute(
                    """
                    UPDATE api.secrets SET value_enc = %s
                    WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                    """,
                    (crypto.encrypt(value), str(secret_id), str(project_id)),
                )
            if cur.rowcount == 0:
                conn.rollback()
                return "Forbidden", 403
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=row["id"],
                secret_key=row["key"],
                action="updated",
            )
            conn.commit()
        if authz.htmx():
            # Hide value again; show brief confirmation and restore Reveal control
            cell_id = f"reveal-{secret_id}"
            reveal_url = url_for(
                "reveal_secret", project_id=project_id, secret_id=secret_id
            )
            body = render_template(
                "partials/reveal_saved.html",
                reveal_url=reveal_url,
                cell_id=cell_id,
            )
            body += _reveal_toggle_html(
                project_id, secret_id, revealed=False, cell=None
            )
            return body
        flash("Secret updated", "ok")
        return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))


    def _secrets_partial(project_id):
        """Render the HTMX secrets list partial for a project.

        Args:
            project_id: UUID of the project whose secrets to load.

        Returns:
            str: Rendered ``partials/secrets.html`` with rows, pager, and
                write permission context.

        Example:
            >>> return _secrets_partial(project_id)
        """
        page = paging.page_arg("page")
        q = paging.list_state_q()
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            rows, secrets_pager = _load_secrets_page(cur, project_id, page, q)
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = cur.fetchone()["w"]
        return render_template(
            "partials/secrets.html",
            secrets=rows,
            project_id=project_id,
            can_write=can_write,
            secrets_pager=secrets_pager,
            search_q=q,
        )


    @app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/history")
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


    @app.get(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/versions/<uuid:version_id>/reveal"
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
        force_inline = (request.args.get("inline") or "").strip() in ("1", "true", "yes")
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT v.value_enc, s.key, s.note, s.kind, s.id AS secret_id
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
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=row["secret_id"],
                secret_key=row["key"],
                action="revealed",
            )
            conn.commit()
        plaintext = crypto.decrypt(row["value_enc"])
        kind = normalize_kind(row.get("kind"))
        structured = kind in STRUCTURED_VIEW_KINDS
        del force_inline
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
            clipboard_clear_seconds=config.CLIPBOARD_CLEAR_SECONDS,
        )
        if authz.htmx():
            body += _reveal_toggle_html(
                project_id,
                secret_id,
                revealed=True,
                version_id=version_id,
            )
        return body

    @app.get(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/versions/<uuid:version_id>/hide"
    )
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


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/rollback/<uuid:version_id>")
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
                SELECT s.id, s.key, v.value_enc, v.note
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
                return redirect(
                    url_for("secret_history", project_id=project_id, secret_id=secret_id)
                )
            cur.execute(
                """
                UPDATE api.secrets
                SET value_enc = %s, note = %s
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (row["value_enc"], row["note"] or "", str(secret_id), str(project_id)),
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


    @app.post("/projects/<uuid:project_id>/secrets/bulk")
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

    @app.post("/trash/bulk")
    @authz.login_required
    def bulk_trash():
        """Apply bulk restore or purge to selected trash secrets.

        Args:
            None

        Returns:
            werkzeug.wrappers.Response: Redirect to the trash page with a flash
                summary and optional search query preserved.

        Example:
            POST /trash/bulk
            form: bulk_action=restore|purge, secret_ids=<id>...
        """
        action = (request.form.get("bulk_action") or "").strip()
        ids = request.form.getlist("secret_ids")
        q = (request.form.get("q") or request.args.get("q") or "").strip() or None
        if not ids:
            flash("Select at least one secret", "error")
            return redirect(url_for("trash", q=q))
        n = 0
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            for sid in ids:
                cur.execute(
                    """
                    SELECT id, key, project_id FROM api.secrets
                    WHERE id = %s::uuid AND deleted_at IS NOT NULL
                    """,
                    (sid,),
                )
                row = cur.fetchone()
                if not row:
                    continue
                cur.execute(
                    "SELECT api.can_write_project(%s) AS w", (str(row["project_id"]),)
                )
                if not (cur.fetchone() or {}).get("w"):
                    continue
                if action == "restore":
                    cur.execute(
                        """
                        UPDATE api.secrets SET deleted_at = NULL
                        WHERE id = %s::uuid AND deleted_at IS NOT NULL
                        """,
                        (sid,),
                    )
                    if cur.rowcount:
                        audit.log_secret(
                            cur,
                            project_id=row["project_id"],
                            secret_id=row["id"],
                            secret_key=row["key"],
                            action="restored",
                        )
                        n += 1
                elif action == "purge":
                    cur.execute(
                        "DELETE FROM api.secrets WHERE id = %s::uuid AND deleted_at IS NOT NULL",
                        (sid,),
                    )
                    if cur.rowcount:
                        audit.log_secret(
                            cur,
                            project_id=row["project_id"],
                            secret_id=row["id"],
                            secret_key=row["key"],
                            action="purged",
                        )
                        n += 1
            conn.commit()
        if action == "restore":
            flash(f"Restored {n} secret(s)", "ok")
        else:
            flash(f"Permanently deleted {n} secret(s)", "ok")
        return redirect(url_for("trash", q=q))

    @app.route("/projects/<uuid:project_id>/secrets/new", methods=["GET", "POST"])
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
                return redirect(
                    url_for("project_detail", project_id=project_id, tab="secrets")
                )
        if request.method == "GET":
            return render_template(
                "secret_new.html",
                project=project,
                kind="plain",
                key="",
                note="",
                expires_at="",
                kv_pairs=[("", "")],
                secret_kinds=config.SECRET_KINDS,
            )
        kind = normalize_kind(request.form.get("kind"))
        key = (request.form.get("key") or "").strip()
        note = (request.form.get("note") or "").strip()
        value = compose_secret_value(kind, request.form)
        kv_pairs = parse_kv_lines(value) if kind == "kv" else []
        if not key or not value:
            flash("Key and value are required", "error")
            return render_template(
                "secret_new.html",
                project=project,
                kind=kind,
                key=key,
                note=note,
                expires_at=request.form.get("expires_at") or "",
                kv_pairs=kv_pairs or [("", "")],
                secret_kinds=config.SECRET_KINDS,
            ), 400
        try:
            expires_at = _parse_expires_at(request.form)
        except (ValueError, TypeError) as e:
            flash(str(e), "error")
            return render_template(
                "secret_new.html",
                project=project,
                kind=kind,
                key=key,
                note=note,
                expires_at=request.form.get("expires_at") or "",
                kv_pairs=kv_pairs or [("", "")],
                secret_kinds=config.SECRET_KINDS,
            ), 400
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                sid, was_new = _upsert_secret(
                    cur, project_id, key, value, note=note, expires_at=expires_at, kind=kind
                )
                if not sid:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    audit.log_secret(
                        cur,
                        project_id=project_id,
                        secret_id=sid,
                        secret_key=key,
                        action="created" if was_new else "updated",
                    )
                    conn.commit()
                    flash(
                        "Secret created" if was_new else "Secret updated",
                        "ok",
                    )
            except Exception as e:
                flash(str(e), "error")
                return render_template(
                    "secret_new.html",
                    project=project,
                    kind=kind,
                    key=key,
                    note=note,
                    expires_at=request.form.get("expires_at") or "",
                    kv_pairs=kv_pairs or [("", "")],
                    secret_kinds=config.SECRET_KINDS,
                ), 400
        return redirect(
            url_for("project_detail", project_id=project_id, tab="secrets")
        )
