"""Secret reveal access-request routes."""

from __future__ import annotations

import logging

from flask import (
    flash,
    redirect,
    request,
    session,
    url_for,
)

import audit
from auth import authz
from core import config, db

from .helpers import (
    _render_reveal_access_panel,
    _reveal_access_state,
)

log = logging.getLogger(__name__)


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
        except Exception:
            conn.rollback()
            log.exception("access request failed")
            flash("Could not update access. Try again.", "error")
    return redirect(url_for("project_detail", project_id=project_id, tab="requests"))


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
        except Exception:
            conn.rollback()
            flash("Could not update access. Try again.", "error")
    return redirect(url_for("project_detail", project_id=project_id, tab="requests"))


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
        except Exception:
            conn.rollback()
            flash("Could not update access. Try again.", "error")
    return redirect(url_for("project_detail", project_id=project_id, tab="requests"))
