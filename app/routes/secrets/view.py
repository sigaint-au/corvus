"""Secret reveal, view, hide, and pin routes."""

from __future__ import annotations

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
import audit
import authz
import config
import crypto
import db
import pins
from lib.users import user_email
from secret_kinds import (
    STRUCTURED_VIEW_KINDS,
    as_utc,
    normalize_kind,
)
from secret_ops import (
    _parse_expires_at,
    compose_secret_value,
)
from .helpers import (
    _render_reveal_access_panel,
    _render_secret_view,
    _reveal_access_state,
    _reveal_cell_ids,
    _reveal_toggle_html,
)


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
                   p.name AS project_name, p.require_reveal_approval,
                   p.team_id, t.name AS team_name,
                   api.is_team_member(p.team_id) AS is_team_member
            FROM api.secrets s
            JOIN api.projects p ON p.id = s.project_id
            LEFT JOIN api.teams t ON t.id = p.team_id
            WHERE s.id = %s AND s.project_id = %s AND s.deleted_at IS NULL
            """,
            (str(secret_id), str(project_id)),
        )
        row = cur.fetchone()
        if not row:
            return "Not found", 404
        row = dict(row)
        row["shared_access"] = row.get("is_team_member") is False
        row["last_accessed_by_email"] = ""
        if row.get("last_accessed_by"):
            with db.connect_admin() as aconn, aconn.cursor() as acur:
                row["last_accessed_by_email"] = user_email(
                    acur, str(row["last_accessed_by"])
                )
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
        can_reveal_perm = bool((cur.fetchone() or {}).get("r"))
        access_state, access_row = _reveal_access_state(
            cur, project_id, secret_id, session["user_id"]
        )
        can_reveal = can_reveal_perm and access_state == "allowed"
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
                access_blocked=can_reveal_perm and access_state != "allowed",
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
                access_blocked=can_reveal_perm and access_state != "allowed",
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
