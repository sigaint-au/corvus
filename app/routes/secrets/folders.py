"""Folder routes: list, create, delete, move within a project."""
from flask import flash, redirect, render_template, request, session, url_for
from werkzeug.exceptions import Forbidden, HTTPException

from auth import authz
from core import db
from secret_svc.folder_ops import create_folder, delete_folder, list_children, move_folder

from .helpers import _secrets_redirect_or_partial


@authz.login_required
def folder_list(project_id):
    """Render one folder level (child folders + leaf secrets) as a partial."""
    folder_id = request.args.get("folder") or None
    page = int(request.args.get("page") or 1)
    q = (request.args.get("q") or "").strip()
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        rows, pager, folder_rows, tree_secrets = list_children(cur, project_id, folder_id, page, q)
        return render_template(
            "partials/folder_content.html",
            rows=rows,
            pager=pager,
            folder_rows=folder_rows,
            tree_secrets=tree_secrets,
            search_q=q,
            folder_id=folder_id,
        )


@authz.login_required
def folder_redirect(project_id, folder_id):
    """Open a folder by id (redirect to the secrets tab tree view)."""
    return redirect(url_for("project_detail", project_id=project_id, tab="secrets", folder=folder_id))


@authz.login_required
def folder_create(project_id):
    """Create a folder under the current folder (or project root)."""
    name = (request.form.get("name") or "").strip()
    parent_id = (request.form.get("parent_id") or "").strip() or None
    if not name:
        flash("Folder name required", "error")
        return _secrets_redirect_or_partial(project_id)
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            path = name
            if parent_id:
                cur.execute(
                    "SELECT path FROM api.folders WHERE id = %s AND project_id = %s",
                    (parent_id, str(project_id)),
                )
                parent = cur.fetchone()
                if not parent:
                    raise Forbidden("Parent folder not found")
                from lib.folders import validate_path
                validate_path(parent["path"] + "/" + name)
                path = parent["path"] + "/" + name
            create_folder(cur, project_id, path, actor_email=session.get("email"))
            conn.commit()
            flash("Folder created", "ok")
        except HTTPException as e:
            conn.rollback()
            flash(str(e), "error")
    return _secrets_redirect_or_partial(project_id, folder_id=parent_id)


@authz.login_required
def folder_delete(project_id, folder_id):
    """Delete a folder; pass recursive=1 to trash descendant secrets first."""
    recursive = bool(request.form.get("recursive"))
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            delete_folder(
                cur, folder_id, project_id=project_id,
                recursive=recursive, actor_email=session.get("email"),
            )
            conn.commit()
            flash("Folder deleted", "ok")
        except HTTPException as e:
            conn.rollback()
            flash(str(e), "error")
    return _secrets_redirect_or_partial(project_id)


@authz.login_required
def folder_move(project_id, folder_id):
    """Rename/move a folder to new_path (rewrites descendant keys)."""
    new_path = (request.form.get("new_path") or "").strip()
    if not new_path:
        flash("New path required", "error")
        return _secrets_redirect_or_partial(project_id)
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            move_folder(
                cur, folder_id, new_path,
                project_id=project_id, actor_email=session.get("email"),
            )
            conn.commit()
            flash("Folder moved", "ok")
        except HTTPException as e:
            conn.rollback()
            flash(str(e), "error")
    return _secrets_redirect_or_partial(project_id)
