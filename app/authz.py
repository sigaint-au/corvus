"""Auth decorators and admin checks."""
from functools import wraps

from flask import flash, redirect, request, session, url_for

import db


def login_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*a, **kw)

    return wrapped


def global_admin_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if not session.get("is_global_admin"):
            flash("Global admin access required", "error")
            return redirect(url_for("projects_list"))
        return f(*a, **kw)

    return wrapped


def htmx():
    return request.headers.get("HX-Request") == "true"


def is_global_admin(user_id: str) -> bool:
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT is_global_admin FROM private.users WHERE id = %s::uuid",
                (user_id,),
            )
            row = cur.fetchone()
            return bool(row and row.get("is_global_admin"))
    except Exception:
        return False
