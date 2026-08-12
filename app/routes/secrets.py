"""Secret CRUD, reveal, history, trash, access requests."""

import logging

from flask import flash, redirect, render_template, request, session, url_for

import audit
import authz
import config
import crypto
import db
import nav
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
    _load_team_secrets_page,
    _parse_access_mode,
    _parse_expires_at,
    _parse_requires_approval,
    _upsert_secret,
    compose_secret_value,
)

log = logging.getLogger(__name__)


def _secret_requires_approval(cur, secret_id) -> bool:
    """Return whether this secret effectively requires reveal approval.

    Per-secret ``requires_approval`` overrides the project
    ``require_reveal_approval`` default when not NULL.

    Args:
        cur: Open DB cursor.
        secret_id: UUID of the secret.

    Returns:
        bool: True when non-admins need an approved grant to reveal.
    """
    cur.execute("SELECT api.secret_requires_approval(%s) AS r", (str(secret_id),))
    return bool((cur.fetchone() or {}).get("r"))


def _reveal_access_state(cur, project_id, secret_id, user_id):
    """Return whether the user may reveal a secret without further approval.

    Open secrets (effective policy off) and project admins / team owners
    may always reveal. When approval is required, holders of an unexpired
    approved grant may reveal; others must request access.

    Args:
        cur: Open DB cursor under the caller's RLS context.
        project_id: UUID of the project that owns the secret.
        secret_id: UUID of the secret.
        user_id: UUID of the requesting user.

    Returns:
        tuple[str, dict | None]: ``(state, row)`` where state is one of
        ``allowed``, ``pending``, or ``need_request``. ``row`` is the matching
        access-request mapping when pending or an active grant exists.
        When allowed via grant, ``row`` includes ``approved_until``.

    Example:
        >>> state, row = _reveal_access_state(cur, pid, sid, uid)
        >>> state in ("allowed", "pending", "need_request")
        True
    """
    cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
    if (cur.fetchone() or {}).get("a"):
        return "allowed", None
    if not _secret_requires_approval(cur, secret_id):
        return "allowed", None
    cur.execute(
        """
        SELECT id, status, approved_until, created_at, reason
        FROM api.secret_access_requests
        WHERE secret_id = %s AND user_id = %s
          AND (
            status = 'pending'
            OR (status = 'approved' AND approved_until IS NOT NULL
                AND approved_until > now())
          )
        ORDER BY
          CASE status WHEN 'approved' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END,
          created_at DESC
        LIMIT 1
        """,
        (str(secret_id), str(user_id)),
    )
    row = cur.fetchone()
    if not row:
        return "need_request", None
    if row["status"] == "approved":
        return "allowed", row
    return "pending", row


def _render_reveal_access_panel(
    *,
    project_id,
    secret_id,
    secret_key: str,
    state: str,
    request_row=None,
    cell: str | None = None,
    version_id=None,
    dialog_body: bool = False,
):
    """Render access-request UI when reveal is blocked pending approval.

    Prefer the oak dialog (list menu / dialog form). When ``dialog_body`` is
    True, return only the dialog body fragment for HTMX swaps inside an open
    dialog. Otherwise return a full auto-opening oak dialog (e.g. direct
    reveal URL) or a compact inline panel for non-dialog contexts.

    Args:
        project_id: Project UUID.
        secret_id: Secret UUID.
        secret_key: Human-readable secret key for display.
        state: ``pending`` or ``need_request``.
        request_row: Optional pending request row for display.
        cell: Optional reveal cell discriminator.
        version_id: Optional version UUID (history reveal).
        dialog_body: If True, render ``access_request_dialog_body.html`` only.

    Returns:
        str: Rendered HTML for the access-request UI.
    """
    if dialog_body or (request.form.get("dialog") or request.args.get("dialog")):
        # Swap dialog *contents* (innerHTML of <dialog>)
        return render_template(
            "partials/access_request_dialog_body.html",
            project_id=project_id,
            secret_id=secret_id,
            secret_key=secret_key,
            state=state,
            request_row=request_row,
            cell=cell,
            version_id=version_id,
        )
    # Full dialog + open (fallback when /reveal is hit directly)
    html = render_template(
        "partials/access_request_dialog.html",
        project_id=project_id,
        secret_id=secret_id,
        secret_key=secret_key,
        state=state,
        request_row=request_row,
        cell=cell,
        version_id=version_id,
    )
    html += (
        f'<script>'
        f'(function(){{var d=document.getElementById("access-dlg-{secret_id}");'
        f'if(d&&window.oatOpenDialog)window.oatOpenDialog(d);'
        f'else if(d&&d.showModal)d.showModal();}})();'
        f'</script>'
    )
    return html


def register(app):
    """Register secret CRUD, reveal, history, trash, and access routes on the app.

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
        """List team secrets with pagination and filters.

        Query params: ``q``, ``page``, ``project`` (UUID), ``kind``, ``due``
        (overdue|soon|none), ``acl`` (restricted|inherit).

        Example:
            GET /secrets?q=password&kind=database&page=2
        """
        tid = nav.ensure_active_team(session["user_id"])
        q = paging.list_state_q()
        page = paging.page_arg()
        project = (request.args.get("project") or "").strip() or None
        kind = (request.args.get("kind") or "").strip() or None
        if kind and kind not in config.SECRET_KINDS:
            kind = None
        due = (request.args.get("due") or "").strip() or None
        if due not in ("overdue", "soon", "none", None):
            due = None
        acl = (request.args.get("acl") or "").strip() or None
        if acl not in ("restricted", "inherit", None):
            acl = None
        team, secrets, team_projects = None, [], []
        secrets_pager = None
        if tid:
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
                team = cur.fetchone()
                if team:
                    secrets, secrets_pager, team_projects = _load_team_secrets_page(
                        cur,
                        tid,
                        page,
                        q,
                        project=project,
                        kind=kind,
                        due=due,
                        acl=acl,
                    )
        return render_template(
            "secrets.html",
            team=team,
            secrets=secrets,
            search_q=q,
            secrets_pager=secrets_pager,
            team_projects=team_projects,
            filter_project=project,
            filter_kind=kind,
            filter_due=due,
            filter_acl=acl,
            secret_kinds=config.SECRET_KINDS,
        )


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
        tid = nav.ensure_active_team(session["user_id"])
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
        if kind != "plain":
            flash("Use Advanced create for structured secret types", "error")
            return redirect(url_for("secret_new", project_id=project_id))
        req_appr = _parse_requires_approval(request.form)
        access_mode = _parse_access_mode(request.form)
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
                    requires_approval=req_appr,
                    set_requires_approval=True,
                    access_mode=access_mode,
                    set_access_mode=True,
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
        # The list-row toggle lives inside the secret kebab ot-dropdown; history
        # toggles sit in the acts cell. Pass the popover id so the swapped-in
        # Hide control renders as a proper menu item.
        menu = None
        if version_id is None and (cell or "").strip().lower() != "current":
            menu = f"secret-menu-{secret_id}"
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
            menu=menu,
        )

    @app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/reveal")
    @authz.login_required
    def reveal_secret(project_id, secret_id):
        """Decrypt and show a secret value inline (audited).

        Non-admins need an approved access request before the value is shown.

        Args:
            project_id: UUID of the project that owns the secret.
            secret_id: UUID of the secret to reveal.

        Returns:
            str | tuple: HTML fragment with plaintext (and OOB toggle for HTMX),
                an access-request panel when approval is required, or
                ``("Not found", 404)`` when the secret is missing.

        Example:
            GET /projects/<project_id>/secrets/<secret_id>/reveal?cell=current
        """
        cell = (request.args.get("cell") or "").strip() or None
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
            cur.execute(
                "SELECT api.can_access_secret(%s, 'reveal') AS ok",
                (str(secret_id),),
            )
            if not (cur.fetchone() or {}).get("ok"):
                return render_template(
                    "partials/reveal_access.html",
                    project_id=project_id,
                    secret_id=secret_id,
                    secret_key=row["key"],
                    state="denied",
                    cell=cell,
                ), 403
            access_state, access_row = _reveal_access_state(
                cur, project_id, secret_id, session["user_id"]
            )
            if access_state != "allowed":
                return _render_reveal_access_panel(
                    project_id=project_id,
                    secret_id=secret_id,
                    secret_key=row["key"],
                    state=access_state,
                    request_row=access_row,
                    cell=cell,
                )
            cur.execute(
                "SELECT api.can_access_secret(%s, 'write') AS w",
                (str(secret_id),),
            )
            can_write = bool((cur.fetchone() or {}).get("w"))
            try:
                pins.touch_recent(cur, session["user_id"], secret_id)
            except Exception:
                pass
            try:
                cur.execute(
                    "SELECT private.touch_secret_access(%s::uuid)",
                    (str(secret_id),),
                )
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
        can_admin: bool = False,
        secret_bindings=None,
        can_reveal: bool = True,
        team_groups=None,
        active_tab: str = "secret",
        access_blocked: bool = False,
        access_state=None,
        access_request=None,
        custom_meta=None,
        effective_access=None,
    ):
        """Render the type-specific secret view/edit page template."""
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
        access_mode = (row.get("access_mode") or "inherit").strip() or "inherit"
        tab = (active_tab or "secret").strip().lower()
        if tab not in ("secret", "meta", "access"):
            tab = "secret"
        if is_version:
            tab = "secret"
        if tab == "access" and not can_admin:
            tab = "secret"
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
                can_admin=can_admin,
                can_reveal=can_reveal,
                access_mode=access_mode,
                access_modes=config.ACCESS_MODES,
                access_mode_labels=config.ACCESS_MODE_LABELS,
                can_edit_access=can_admin,
                role_dropdown=config.RBAC_SECRET_ROLE_DROPDOWN,
                subject_kinds=config.RBAC_SUBJECT_KINDS,
                secret_bindings=secret_bindings or [],
                team_groups=team_groups or [],
                active_tab=tab,
                access_blocked=access_blocked,
                access_state=access_state,
                access_request=access_request,
                requires_approval=row.get("requires_approval"),
                require_reveal_approval=row.get("require_reveal_approval"),
                clipboard_clear_seconds=config.CLIPBOARD_CLEAR_SECONDS,
                created_at=row.get("created_at"),
                updated_at=row.get("updated_at"),
                last_accessed_at=row.get("last_accessed_at"),
                last_accessed_by_email=row.get("last_accessed_by_email") or "",
                custom_meta=custom_meta or [],
                effective_access=effective_access or [],
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
        active_tab = (request.args.get("tab") or "secret").strip().lower()
        if active_tab not in ("secret", "meta", "access"):
            active_tab = "secret"
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at,
                       s.requires_approval, s.access_mode, s.created_at, s.updated_at,
                       s.last_accessed_at, s.last_accessed_by,
                       p.name AS project_name, p.require_reveal_approval
                FROM api.secrets s
                JOIN api.projects p ON p.id = s.project_id
                WHERE s.id = %s AND s.project_id = %s AND s.deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            row = dict(row)
            row["last_accessed_by_email"] = ""
            if row.get("last_accessed_by"):
                try:
                    with db.connect_admin() as aconn, aconn.cursor() as acur:
                        acur.execute(
                            "SELECT email FROM private.users WHERE id = %s::uuid",
                            (str(row["last_accessed_by"]),),
                        )
                        u = acur.fetchone() or {}
                        row["last_accessed_by_email"] = (
                            (u.get("email") if u else None) or ""
                        )
                except Exception:
                    row["last_accessed_by_email"] = ""
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
            cur.execute(
                "SELECT api.can_access_secret(%s, 'write') AS w",
                (str(secret_id),),
            )
            can_write = bool((cur.fetchone() or {}).get("w"))
            cur.execute(
                "SELECT api.can_access_secret(%s, 'reveal') AS r",
                (str(secret_id),),
            )
            can_reveal_acl = bool((cur.fetchone() or {}).get("r"))
            access_state, access_row = _reveal_access_state(
                cur, project_id, secret_id, session["user_id"]
            )
            can_reveal = can_reveal_acl and access_state == "allowed"
            cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
            can_admin = bool((cur.fetchone() or {}).get("a"))
            custom_meta = []
            try:
                cur.execute(
                    "SELECT * FROM private.secret_meta_rows(%s::uuid)",
                    (str(secret_id),),
                )
                custom_meta = cur.fetchall() or []
            except Exception:
                custom_meta = []
            secret_bindings = []
            team_groups = []
            effective_access = []
            if can_admin:
                try:
                    cur.execute(
                        """
                        SELECT b.id, b.subject_kind, b.subject_id, b.created_at,
                               r.name AS role_name,
                               g.name AS group_name
                        FROM rbac.bindings b
                        JOIN rbac.roles r ON r.id = b.role_id
                        LEFT JOIN api.groups g
                          ON b.subject_kind = 'Group' AND g.id = b.subject_id
                        WHERE b.scope_kind = 'secret' AND b.scope_id = %s::uuid
                        ORDER BY b.created_at DESC
                        """,
                        (str(secret_id),),
                    )
                    secret_bindings = list(cur.fetchall() or [])
                except Exception:
                    secret_bindings = []
                import rbac_sync

                rbac_sync.enrich_binding_emails(secret_bindings)
                try:
                    cur.execute(
                        """
                        SELECT g.id, g.name
                        FROM api.groups g
                        JOIN api.projects p ON p.team_id = g.team_id
                        WHERE p.id = %s
                        ORDER BY g.name
                        """,
                        (str(project_id),),
                    )
                    team_groups = cur.fetchall() or []
                except Exception:
                    team_groups = []
                try:
                    cur.execute(
                        "SELECT * FROM api.effective_access_rows('secret', %s::uuid)",
                        (str(secret_id),),
                    )
                    effective_access = list(cur.fetchall() or [])
                except Exception:
                    conn.rollback()
                    effective_access = []

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
                # ACL + reveal approval live on the Access tab — preserve on value save
                req_appr = row.get("requires_approval")
                access_mode = (row.get("access_mode") or "inherit").strip() or "inherit"
                row_view = dict(row)
                row_view["note"] = note
                row_view["kind"] = kind
                row_view["project_name"] = row.get("project_name") or ""
                row_view["requires_approval"] = req_appr
                row_view["access_mode"] = access_mode
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
                        can_admin=can_admin,
                        active_tab="secret",
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
                        can_admin=can_admin,
                        active_tab="secret",
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

            # Meta / Access tabs: never decrypt or audit reveal
            if active_tab in ("meta", "access") and not is_version:
                if active_tab == "access" and not can_admin:
                    active_tab = "meta"
                body, code = _render_secret_view(
                    project_id=project_id,
                    secret_id=secret_id,
                    row=row,
                    plaintext="",
                    kind=normalize_kind(row.get("kind")),
                    can_write=can_write,
                    is_version=False,
                    can_admin=can_admin,
                    secret_bindings=secret_bindings,
                    can_reveal=can_reveal,
                    team_groups=team_groups,
                    effective_access=effective_access,
                    active_tab=active_tab,
                    access_blocked=can_reveal_acl and access_state != "allowed",
                    access_state=access_state,
                    access_request=access_row,
                    custom_meta=custom_meta,
                )
                return body, code

            if not can_reveal:
                # Metadata only — do not decrypt or audit a reveal
                body, code = _render_secret_view(
                    project_id=project_id,
                    secret_id=secret_id,
                    row=row,
                    plaintext="",
                    kind=normalize_kind(row.get("kind")),
                    can_write=False,
                    is_version=is_version,
                    can_admin=can_admin,
                    secret_bindings=secret_bindings if can_admin else [],
                    can_reveal=False,
                    team_groups=team_groups if can_admin else [],
                    effective_access=effective_access,
                    active_tab="meta" if active_tab == "meta" else "secret",
                    access_blocked=can_reveal_acl and access_state != "allowed",
                    access_state=access_state,
                    access_request=access_row,
                    custom_meta=custom_meta,
                )
                return body, code

            try:
                plaintext = crypto.decrypt(value_enc)
            except ValueError as e:
                conn.rollback()
                flash(str(e), "error")
                body, code = _render_secret_view(
                    project_id=project_id,
                    secret_id=secret_id,
                    row=row,
                    plaintext="",
                    kind=normalize_kind(row.get("kind")),
                    can_write=False,
                    is_version=is_version,
                    can_admin=can_admin,
                    secret_bindings=secret_bindings if can_admin else [],
                    can_reveal=False,
                    team_groups=team_groups if can_admin else [],
                    effective_access=effective_access,
                    active_tab="meta" if active_tab == "meta" else "secret",
                    access_blocked=True,
                    access_state="decrypt_error",
                    custom_meta=custom_meta,
                )
                return body, code
            try:
                pins.touch_recent(cur, session["user_id"], secret_id)
            except Exception:
                pass
            try:
                cur.execute(
                    "SELECT private.touch_secret_access(%s::uuid)",
                    (str(secret_id),),
                )
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
        kind = normalize_kind(row.get("kind"))
        body, code = _render_secret_view(
            project_id=project_id,
            secret_id=secret_id,
            row=row,
            plaintext=plaintext,
            kind=kind,
            can_write=can_write,
            is_version=is_version,
            can_admin=can_admin,
            secret_bindings=secret_bindings,
            can_reveal=can_reveal,
            team_groups=team_groups,
            effective_access=effective_access,
            active_tab=active_tab,
            custom_meta=custom_meta,
        )
        return body, code

    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/meta")
    @authz.login_required
    def upsert_secret_meta(project_id, secret_id):
        """Add or update a custom metadata field (writers)."""
        key = (request.form.get("key") or "").strip()
        value = (request.form.get("value") or "").strip()
        meta_url = url_for(
            "secret_view", project_id=project_id, secret_id=secret_id, tab="meta"
        )
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
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(meta_url)

    @app.post(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/meta/<path:meta_key>/delete"
    )
    @authz.login_required
    def delete_secret_meta(project_id, secret_id, meta_key):
        """Remove a custom metadata field."""
        meta_url = url_for(
            "secret_view", project_id=project_id, secret_id=secret_id, tab="meta"
        )
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
            access_mode_labels=config.ACCESS_MODE_LABELS,
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
            cur.execute(
                "SELECT api.can_access_secret(%s, 'reveal') AS ok",
                (str(secret_id),),
            )
            if not (cur.fetchone() or {}).get("ok"):
                return ("Forbidden", 403)
            access_state, access_row = _reveal_access_state(
                cur, project_id, secret_id, session["user_id"]
            )
            if access_state != "allowed":
                return _render_reveal_access_panel(
                    project_id=project_id,
                    secret_id=secret_id,
                    secret_key=row["key"],
                    state=access_state,
                    request_row=access_row,
                    version_id=version_id,
                )
            try:
                plaintext = crypto.decrypt(row["value_enc"])
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


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/access-request")
    @authz.login_required
    def request_secret_access(project_id, secret_id):
        """Request approval to reveal a secret (non-admins only).

        Project admins and team owners can already reveal; this creates a
        pending access request for everyone else.

        Args:
            project_id: UUID of the project that owns the secret.
            secret_id: UUID of the secret to request access for.

        Returns:
            HTML fragment (HTMX) or redirect to the project access tab.

        Example:
            POST /projects/<project_id>/secrets/<secret_id>/access-request
        """
        reason = (request.form.get("reason") or "").strip()
        if len(reason) > 500:
            reason = reason[:500]
        cell = (request.form.get("cell") or request.args.get("cell") or "").strip() or None
        wants_htmx = authz.htmx()
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
                if wants_htmx:
                    return "Not found", 404
                flash("Secret not found", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))
            access_state, access_row = _reveal_access_state(
                cur, project_id, secret_id, session["user_id"]
            )
            if access_state == "allowed":
                if wants_htmx:
                    return redirect(
                        url_for(
                            "reveal_secret",
                            project_id=project_id,
                            secret_id=secret_id,
                            cell=cell,
                        )
                    )
                flash("You already have access to reveal this secret", "ok")
                return redirect(
                    url_for("project_detail", project_id=project_id, tab="requests")
                )
            if access_state == "pending":
                if wants_htmx:
                    return _render_reveal_access_panel(
                        project_id=project_id,
                        secret_id=secret_id,
                        secret_key=row["key"],
                        state="pending",
                        request_row=access_row,
                        cell=cell,
                    )
                flash("Access request already pending approval", "ok")
                return redirect(
                    url_for("project_detail", project_id=project_id, tab="requests")
                )
            try:
                cur.execute(
                    """
                    INSERT INTO api.secret_access_requests
                      (project_id, secret_id, user_id, reason, status)
                    SELECT %s, %s, %s, %s, 'pending'
                    WHERE NOT EXISTS (
                      SELECT 1 FROM api.secret_access_requests
                      WHERE secret_id = %s AND user_id = %s AND status = 'pending'
                    )
                    RETURNING id, status, created_at, reason
                    """,
                    (
                        str(project_id),
                        str(secret_id),
                        session["user_id"],
                        reason,
                        str(secret_id),
                        session["user_id"],
                    ),
                )
                created = cur.fetchone()
                if not created:
                    # Race: another request became pending
                    access_state, access_row = _reveal_access_state(
                        cur, project_id, secret_id, session["user_id"]
                    )
                    conn.commit()
                    if wants_htmx:
                        return _render_reveal_access_panel(
                            project_id=project_id,
                            secret_id=secret_id,
                            secret_key=row["key"],
                            state=access_state if access_state != "allowed" else "pending",
                            request_row=access_row,
                            cell=cell,
                        )
                    flash("Access request already pending approval", "ok")
                    return redirect(
                        url_for("project_detail", project_id=project_id, tab="requests")
                    )
                audit.log_secret(
                    cur,
                    project_id=project_id,
                    secret_id=row["id"],
                    secret_key=row["key"],
                    action="access_requested",
                )
                conn.commit()
                if wants_htmx:
                    return _render_reveal_access_panel(
                        project_id=project_id,
                        secret_id=secret_id,
                        secret_key=row["key"],
                        state="pending",
                        request_row=created,
                        cell=cell,
                    )
                flash(
                    f"Access requested for “{row['key']}”. "
                    "A project admin or team owner must approve it.",
                    "ok",
                )
            except Exception as e:
                conn.rollback()
                log.exception("access request failed")
                flash(str(e), "error")
        return redirect(url_for("project_detail", project_id=project_id, tab="requests"))

    @app.post("/projects/<uuid:project_id>/access-requests/<uuid:req_id>/approve")
    @authz.login_required
    def approve_secret_access(project_id, req_id):
        """Approve a pending secret reveal access request.

        Args:
            project_id: UUID of the project.
            req_id: UUID of the access request to approve.

        Returns:
            Redirect to the project Access requests tab.

        Example:
            POST /projects/<project_id>/access-requests/<req_id>/approve
        """
        minutes_raw = (
            request.form.get("minutes") or request.form.get("hours") or ""
        ).strip()
        try:
            minutes = (
                int(minutes_raw)
                if minutes_raw
                else config.REVEAL_ACCESS_GRANT_MINUTES
            )
            # Legacy form field "hours" (if still submitted as 1/4/24)
            if request.form.get("hours") and not request.form.get("minutes"):
                if minutes in (1, 4, 24, 168):
                    minutes = minutes * 60
        except (TypeError, ValueError):
            minutes = config.REVEAL_ACCESS_GRANT_MINUTES
        if minutes not in config.REVEAL_ACCESS_GRANT_CHOICES:
            minutes = config.REVEAL_ACCESS_GRANT_MINUTES
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
            if not (cur.fetchone() or {}).get("a"):
                flash(
                    "Only a project admin or team owner can approve access requests",
                    "error",
                )
                return redirect(
                    url_for("project_detail", project_id=project_id, tab="requests")
                )
            cur.execute(
                """
                SELECT r.id, r.secret_id, r.user_id, r.status, s.key AS secret_key
                FROM api.secret_access_requests r
                LEFT JOIN api.secrets s ON s.id = r.secret_id
                WHERE r.id = %s AND r.project_id = %s
                """,
                (str(req_id), str(project_id)),
            )
            req = cur.fetchone()
            if not req or req["status"] != "pending":
                flash("Request not found or already resolved", "error")
                return redirect(
                    url_for("project_detail", project_id=project_id, tab="requests")
                )
            try:
                cur.execute(
                    """
                    UPDATE api.secret_access_requests
                    SET status = 'approved',
                        resolved_at = now(),
                        resolved_by = %s,
                        approved_until = now() + (%s || ' minutes')::interval
                    WHERE id = %s AND status = 'pending'
                    """,
                    (session["user_id"], str(minutes), str(req_id)),
                )
                if cur.rowcount == 0:
                    flash("Request not found or already resolved", "error")
                    conn.rollback()
                else:
                    audit.log_secret(
                        cur,
                        project_id=project_id,
                        secret_id=req["secret_id"],
                        secret_key=req.get("secret_key") or "",
                        action="access_approved",
                    )
                    conn.commit()
                    if minutes < 60:
                        dur = f"{minutes} minutes"
                    elif minutes == 60:
                        dur = "1 hour"
                    elif minutes % 1440 == 0:
                        dur = f"{minutes // 1440} day(s)"
                    else:
                        dur = f"{minutes // 60} hours"
                    flash(
                        f"Access approved for {dur}"
                        + (
                            f" on “{req['secret_key']}”"
                            if req.get("secret_key")
                            else ""
                        ),
                        "ok",
                    )
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("project_detail", project_id=project_id, tab="requests"))

    @app.post("/projects/<uuid:project_id>/access-requests/<uuid:req_id>/deny")
    @authz.login_required
    def deny_secret_access(project_id, req_id):
        """Deny a pending secret reveal access request.

        Args:
            project_id: UUID of the project.
            req_id: UUID of the access request to deny.

        Returns:
            Redirect to the project Access requests tab.

        Example:
            POST /projects/<project_id>/access-requests/<req_id>/deny
        """
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
            if not (cur.fetchone() or {}).get("a"):
                flash(
                    "Only a project admin or team owner can deny access requests",
                    "error",
                )
                return redirect(
                    url_for("project_detail", project_id=project_id, tab="requests")
                )
            cur.execute(
                """
                SELECT r.id, r.secret_id, r.status, s.key AS secret_key
                FROM api.secret_access_requests r
                LEFT JOIN api.secrets s ON s.id = r.secret_id
                WHERE r.id = %s AND r.project_id = %s
                """,
                (str(req_id), str(project_id)),
            )
            req = cur.fetchone()
            if not req or req["status"] != "pending":
                flash("Request not found or already resolved", "error")
                return redirect(
                    url_for("project_detail", project_id=project_id, tab="requests")
                )
            try:
                cur.execute(
                    """
                    UPDATE api.secret_access_requests
                    SET status = 'denied',
                        resolved_at = now(),
                        resolved_by = %s,
                        approved_until = NULL
                    WHERE id = %s AND status = 'pending'
                    """,
                    (session["user_id"], str(req_id)),
                )
                if cur.rowcount == 0:
                    flash("Request not found or already resolved", "error")
                    conn.rollback()
                else:
                    audit.log_secret(
                        cur,
                        project_id=project_id,
                        secret_id=req["secret_id"],
                        secret_key=req.get("secret_key") or "",
                        action="access_denied",
                    )
                    conn.commit()
                    flash(
                        "Access request denied"
                        + (f" for “{req['secret_key']}”" if req.get("secret_key") else ""),
                        "ok",
                    )
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("project_detail", project_id=project_id, tab="requests"))

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
                "require_reveal_approval": bool(
                    project.get("require_reveal_approval")
                ),
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
        except (ValueError, TypeError) as e:
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
                    requires_approval=_parse_requires_approval(request.form),
                    set_requires_approval=True,
                    access_mode=_parse_access_mode(request.form),
                    set_access_mode=True,
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
                    **_new_ctx(
                        kind=kind,
                        key=key,
                        note=note,
                        expires_at=request.form.get("expires_at") or "",
                        kv_pairs=kv_pairs or [("", "")],
                        access_mode=_parse_access_mode(request.form),
                    ),
                ), 400
        return redirect(
            url_for("project_detail", project_id=project_id, tab="secrets")
        )

    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/access")
    @authz.login_required
    def update_secret_access(project_id, secret_id):
        """Set per-secret ACL mode and reveal-approval override (project admin only)."""
        mode = _parse_access_mode(request.form)
        req_appr = _parse_requires_approval(request.form)
        access_url = url_for(
            "secret_view",
            project_id=project_id,
            secret_id=secret_id,
            tab="access",
        )
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
            if not (cur.fetchone() or {}).get("a"):
                flash("Only project admins can change secret access", "error")
                return redirect(access_url)
            cur.execute(
                """
                UPDATE api.secrets
                SET access_mode = %s, requires_approval = %s
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                RETURNING key
                """,
                (mode, req_appr, str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                flash("Secret not found or not permitted", "error")
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
                label = config.ACCESS_MODE_LABELS.get(mode, mode)
                flash(f"Access settings saved ({label})", "ok")
        return redirect(access_url)

    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/access/bindings")
    @authz.login_required
    def add_secret_access_binding(project_id, secret_id):
        """Bind a user, group, or service account to a secret role (project admin).

        Uses the same subject/role vocabulary as every other binding form:
        ``subject_kind`` + ``subject_email`` / ``subject_group`` / ``subject_sa``
        and a ``role_name`` (``secret-*``). Legacy ``email`` / ``group_id`` /
        ``permission`` fields are still accepted.
        """
        subject_kind = (request.form.get("subject_kind") or "User").strip()
        if subject_kind not in ("User", "Group", "ServiceAccount"):
            subject_kind = "User"
        email = (
            request.form.get("subject_email") or request.form.get("email") or ""
        ).strip().lower()
        group_id = (
            request.form.get("subject_group")
            or request.form.get("group_id")
            or ""
        ).strip()
        sa_id = (request.form.get("subject_sa") or "").strip()
        secret_role_names = [name for name, _ in config.RBAC_SECRET_ROLE_DROPDOWN]
        role_name = (request.form.get("role_name") or "").strip()
        if role_name not in secret_role_names:
            # Legacy permission (read/reveal/write) fallback
            legacy = {
                "read": "secret-read",
                "reveal": "secret-reveal",
                "write": "secret-write",
            }
            perm = (request.form.get("permission") or "reveal").strip().lower()
            role_name = legacy.get(perm, "secret-reveal")
        access_url = url_for(
            "secret_view",
            project_id=project_id,
            secret_id=secret_id,
            tab="access",
        )
        if subject_kind == "User" and not email:
            flash("User email required", "error")
            return redirect(access_url)
        if subject_kind == "Group" and not group_id:
            flash("Select a group", "error")
            return redirect(access_url)
        if subject_kind == "ServiceAccount" and not sa_id:
            flash("Enter a machine account ID", "error")
            return redirect(access_url)
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
            if not (cur.fetchone() or {}).get("a"):
                flash("Only project admins can manage secret bindings", "error")
                return redirect(access_url)
            cur.execute(
                """
                SELECT s.id, s.key, s.access_mode, p.team_id
                FROM api.secrets s
                JOIN api.projects p ON p.id = s.project_id
                WHERE s.id = %s AND s.project_id = %s AND s.deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            sec = cur.fetchone()
            if not sec:
                flash("Secret not found", "error")
                return redirect(
                    url_for("project_detail", project_id=project_id, tab="secrets")
                )
            cur.execute(
                "SELECT id FROM rbac.roles WHERE name = %s", (role_name,)
            )
            role = cur.fetchone()
            if not role:
                flash(f"Built-in role {role_name} missing — run schema ensure", "error")
                return redirect(access_url)
            try:
                if subject_kind == "User":
                    cur.execute("SELECT private.lookup_user(%s) AS id", (email,))
                    u = cur.fetchone()
                    if not u or not u.get("id"):
                        flash(
                            "User not found — they must register or sign in first",
                            "error",
                        )
                        return redirect(access_url)
                    subject_id, who = str(u["id"]), email
                elif subject_kind == "Group":
                    cur.execute(
                        """
                        SELECT id, name FROM api.groups
                        WHERE id = %s AND team_id = %s
                        """,
                        (group_id, str(sec["team_id"])),
                    )
                    g = cur.fetchone()
                    if not g:
                        flash("Group not found on this team", "error")
                        return redirect(access_url)
                    subject_id, who = str(g["id"]), f"group {g['name']}"
                else:
                    cur.execute(
                        """
                        SELECT mt.id
                        FROM api.machine_tokens mt
                        WHERE mt.id = %s::uuid
                          AND mt.project_id = %s
                        """,
                        (sa_id, str(project_id)),
                    )
                    sa = cur.fetchone()
                    if not sa:
                        flash("Machine account not found in this project", "error")
                        return redirect(access_url)
                    subject_id, who = str(sa["id"]), f"machine account {sa_id[:8]}"
                # Replace any existing secret-scope binding for this subject
                cur.execute(
                    """
                    DELETE FROM rbac.bindings
                    WHERE scope_kind = 'secret' AND scope_id = %s::uuid
                      AND subject_kind = %s AND subject_id = %s::uuid
                    """,
                    (str(secret_id), subject_kind, subject_id),
                )
                cur.execute(
                    """
                    INSERT INTO rbac.bindings
                      (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                    VALUES (%s::uuid, %s, %s::uuid, 'secret', %s::uuid, %s::uuid)
                    """,
                    (
                        str(role["id"]),
                        subject_kind,
                        subject_id,
                        str(secret_id),
                        session["user_id"],
                    ),
                )
                # Restricted mode if not already — bindings only apply as exclusive when restricted
                if (sec.get("access_mode") or "inherit") != "restricted":
                    cur.execute(
                        """
                        UPDATE api.secrets SET access_mode = 'restricted'
                        WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                        """,
                        (str(secret_id), str(project_id)),
                    )
                audit.log_secret(
                    cur,
                    project_id=project_id,
                    secret_id=secret_id,
                    secret_key=sec["key"],
                    action="updated",
                )
                conn.commit()
                flash(f"Bound {who} as {role_name}", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(access_url)

    @app.post(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/access/bindings/<uuid:grant_id>/delete"
    )
    @authz.login_required
    def delete_secret_access_binding(project_id, secret_id, grant_id):
        """Remove a secret-scope role binding (project admin only)."""
        access_url = url_for(
            "secret_view",
            project_id=project_id,
            secret_id=secret_id,
            tab="access",
        )
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
            if not (cur.fetchone() or {}).get("a"):
                flash("Only project admins can manage secret bindings", "error")
                return redirect(access_url)
            cur.execute(
                """
                DELETE FROM rbac.bindings b
                USING api.secrets s
                WHERE b.id = %s::uuid
                  AND b.scope_kind = 'secret'
                  AND b.scope_id = s.id
                  AND s.id = %s::uuid AND s.project_id = %s::uuid
                RETURNING s.key
                """,
                (str(grant_id), str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                flash("Binding not found", "error")
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
                flash("Binding removed", "ok")
        return redirect(access_url)
