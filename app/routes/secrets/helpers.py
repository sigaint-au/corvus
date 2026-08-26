"""Shared helpers for secret reveal/view rendering."""

from __future__ import annotations

from flask import (
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from auth import authz
from core import config, db, settings_svc
from secret_svc.secret_kinds import (
    as_utc,
    parse_database_url,
    parse_kv_lines,
    parse_pem_blocks,
    split_cert_and_key,
)
from secret_svc.secret_ops import _load_secrets_page
from ui import paging


def _active_reveal_grant(cur, secret_id, user_id):
    """Return the current pending request or unexpired approved grant, if any."""
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
    if not row or row.get("status") not in ("pending", "approved"):
        return None
    return row


def _reveal_access_state(cur, project_id, secret_id, user_id):
    """Return whether the user may reveal a secret without further approval.

    ``api.can_reveal_secret`` is the source of truth (same gate as ciphertext
    fetch). Project admins / team-owners / global admins are also allowed via
    ``can_admin_project``. Everyone else who can see the secret may hold an
    approved grant, a pending request, or need to request access.

    Args:
        cur: Open DB cursor under the caller's RLS context.
        project_id: UUID of the project that owns the secret.
        secret_id: UUID of the secret.
        user_id: UUID of the requesting user.

    Returns:
        tuple[str, dict | None]: ``(state, row)`` where state is one of
        ``allowed``, ``pending``, ``need_request``, or ``denied``. ``row`` is the matching
        access-request mapping when pending or an active grant exists.
        When allowed via grant, ``row`` includes ``approved_until``.

    Example:
        >>> state, row = _reveal_access_state(cur, pid, sid, uid)
        >>> state in ("allowed", "pending", "need_request")
        True
    """
    cur.execute(
        """
        SELECT api.can_reveal_secret(%s) AS r,
               api.can_admin_project(%s) AS a
        """,
        (str(secret_id), str(project_id)),
    )
    flags = cur.fetchone() or {}
    if flags.get("r") or flags.get("a"):
        return "allowed", None
    row = _active_reveal_grant(cur, secret_id, user_id)
    if row and row["status"] == "approved":
        return "allowed", row
    if row and row["status"] == "pending":
        return "pending", row
    cur.execute(
        "SELECT api.can_access_secret(%s, 'reveal') AS r",
        (str(secret_id),),
    )
    if (cur.fetchone() or {}).get("r"):
        return "need_request", None
    cur.execute(
        "SELECT api.team_allows_reveal_requests(%s) AS ok",
        (str(project_id),),
    )
    if (cur.fetchone() or {}).get("ok"):
        return "need_request", None
    return "denied", None


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
        f"<script>"
        f'(function(){{var d=document.getElementById("access-dlg-{secret_id}");'
        f"if(d&&window.oatOpenDialog)window.oatOpenDialog(d);"
        f"else if(d&&d.showModal)d.showModal();}})();"
        f"</script>"
    )
    return html


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
    rotation_next = row.get("rotation_next_at")
    rotation_next_date = ""
    if rotation_next is not None:
        try:
            rotation_next_date = as_utc(rotation_next).date().isoformat()
        except Exception:
            rotation_next_date = str(rotation_next)[:10]
    rotated = row.get("rotated_at")
    rotated_date = ""
    if rotated is not None:
        try:
            rotated_date = as_utc(rotated).date().isoformat()
        except Exception:
            rotated_date = str(rotated)[:10]
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
            team_id=row.get("team_id"),
            team_name=row.get("team_name"),
            secret_id=secret_id,
            secret_key=row["key"],
            note=(row.get("note") or ""),
            kind=kind,
            value=plaintext,
            is_version=is_version,
            kv_pairs=parse_kv_lines(plaintext) if kind == "kv" else [("", "")],
            pem_blocks=parse_pem_blocks(plaintext) if kind in ("certificate", "ssh") else [],
            cert_pem=cert_pem,
            cert_key=cert_key,
            db_parts=parse_database_url(plaintext) if kind == "database" else {},
            expires_at=exp_date,
            rotation_interval_days=row.get("rotation_interval_days"),
            rotation_owner=row.get("rotation_owner") or "",
            rotation_next_at=rotation_next_date,
            rotated_at=rotated_date,
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
            clipboard_clear_seconds=settings_svc.int_setting("clipboard_clear_seconds", 30),
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
            last_accessed_at=row.get("last_accessed_at"),
            last_accessed_by_email=row.get("last_accessed_by_email") or "",
            custom_meta=custom_meta or [],
            effective_access=effective_access or [],
            shared_access=bool(row.get("shared_access")),
        ),
        status,
    )


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


def _secrets_redirect_or_partial(project_id):
    """Return the HTMX secrets partial, or redirect to the project secrets tab.

    Args:
        project_id: UUID of the project whose secrets were mutated.

    Returns:
        str | werkzeug.wrappers.Response: HTMX partial when requested;
        otherwise a redirect preserving the list page/search state.

    Example:
        >>> return _secrets_redirect_or_partial(project_id)
    """
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
