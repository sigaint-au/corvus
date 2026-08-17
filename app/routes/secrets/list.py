"""Secret list, trash, and bulk-trash routes."""

from __future__ import annotations

import logging

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
import audit
from auth import authz
from core import config
from core import db
from ui import nav
from ui import paging
from secret_svc.secret_ops import _load_shared_secrets_page, _load_team_secrets_page

log = logging.getLogger(__name__)


@authz.login_required
def secrets_list():
    """List team secrets with pagination and filters.

    Query params: ``q``, ``page``, ``project`` (UUID), ``kind``, ``due``
    (overdue|soon|none), ``access_mode`` (restricted|inherit).

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
    access_mode = (request.args.get("access_mode") or "").strip() or None
    if access_mode not in ("restricted", "inherit", None):
        access_mode = None
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
                    access_mode=access_mode,
                )
    template = (
        "partials/secrets_results.html" if authz.htmx() else "secrets.html"
    )
    return render_template(
        template,
        team=team,
        secrets=secrets,
        search_q=q,
        secrets_pager=secrets_pager,
        team_projects=team_projects,
        filter_project=project,
        filter_kind=kind,
        filter_due=due,
        filter_access_mode=access_mode,
        secret_kinds=config.SECRET_KINDS,
    )


@authz.login_required
def shared_secrets_list():
    """List secrets shared with the current user outside team membership.

    Only secret-scope grants where the user is not a team member, and the
    secret does not require reveal approval. Used by Workspace → Shared secrets.

    Query params: ``q``, ``page``.

    Example:
        GET /shared?q=API
    """
    q = paging.list_state_q()
    page = paging.page_arg()
    secrets, secrets_pager = [], None
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            secrets, secrets_pager = _load_shared_secrets_page(cur, page, q)
        except Exception:
            log.exception("shared_secrets_list failed")
            flash("Could not load shared secrets", "error")
            secrets, secrets_pager = [], paging.page_window(0, page)
            secrets_pager.update(endpoint="shared_secrets_list", q=q or None)
    template = (
        "partials/shared_results.html" if authz.htmx() else "shared_secrets.html"
    )
    return render_template(
        template,
        secrets=secrets,
        search_q=q,
        secrets_pager=secrets_pager,
    )


def _trash_items(tid, q):
    """Return trash items (with search) for the given team id."""
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
        team = cur.fetchone()
        if not team:
            return team, []
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
        return team, cur.fetchall()


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
        team, items = _trash_items(tid, q)
    if authz.htmx():
        return render_template(
            "partials/trash_results.html", team=team, items=items, search_q=q
        )
    return render_template(
        "trash.html", team=team, items=items, search_q=q
    )


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
            else:
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
            flash("Could not update the trash. Try again.", "error")
    q = request.args.get("q") or ""
    if authz.htmx():
        tid = nav.ensure_active_team(session["user_id"])
        team, items = _trash_items(tid, q) if tid else (None, [])
        return render_template(
            "partials/trash_results.html", team=team, items=items, search_q=q
        )
    return redirect(url_for("trash", q=q or None))


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
    q = request.args.get("q") or ""
    if authz.htmx():
        tid = nav.ensure_active_team(session["user_id"])
        team, items = _trash_items(tid, q) if tid else (None, [])
        return render_template(
            "partials/trash_results.html", team=team, items=items, search_q=q
        )
    return redirect(url_for("trash", q=q or None))


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
