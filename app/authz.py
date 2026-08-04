"""Auth decorators, admin checks, CSRF."""
import secrets
from functools import wraps
from urllib.parse import urlsplit

from flask import abort, current_app, flash, redirect, request, session, url_for

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


def csrf_token() -> str:
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_hex(16)
        session["_csrf"] = tok
    return tok


def csrf_protect():
    """Reject POSTs without a valid session CSRF token (form or X-CSRF-Token)."""
    if request.method != "POST":
        return
    # Unit tests skip unless CSRF_TESTING is set
    if current_app.config.get("TESTING") and not current_app.config.get("CSRF_TESTING"):
        return
    want = session.get("_csrf")
    got = request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
    if not want or got != want:
        abort(400, description="CSRF token missing or invalid")


def safe_redirect_target(nxt: str | None, fallback: str) -> str:
    """Allow only same-origin relative paths (blocks //evil open redirects)."""
    if not nxt:
        return fallback
    parts = urlsplit(nxt)
    if parts.scheme or parts.netloc or not nxt.startswith("/"):
        return fallback
    return nxt
