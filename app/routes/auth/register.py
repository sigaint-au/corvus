"""Local account registration route."""

from __future__ import annotations

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from auth import authz
from core import db
import psycopg
from core import settings_svc
from auth import totp_svc
from .helpers import (
    _establish_session,
    _finish_login_redirect,
    _maybe_promote_bootstrap_admin,
)


def register_page():
    """Render registration form or create a new local account.

    Args:
        None (reads form ``email``, ``password``, ``name`` on POST).

    Returns:
        HTML register page, redirect on success/disabled, or 400 on error.

    Example:
        GET/POST /register
    """
    notice = settings_svc.setup_notice()
    if not settings_svc.registration_enabled():
        flash(notice or "Account registration is disabled", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        name = request.form.get("name", "").strip()
        if len(password) < 8:
            flash("Password must be at least 8 characters", "error")
            return render_template("register.html", setup_notice=notice), 400
        try:
            with db.connect(autocommit=True) as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT private.register_user(%s, %s, %s) AS id",
                    (email, password, name),
                )
                uid = cur.fetchone()["id"]
        except psycopg.errors.UniqueViolation:
            flash("Email already registered", "error")
            return render_template("register.html", setup_notice=notice), 400
        except Exception as e:
            flash(str(e), "error")
            return render_template("register.html", setup_notice=notice), 400
        _maybe_promote_bootstrap_admin(email.lower(), uid)
        is_admin = authz.is_global_admin(str(uid))
        # New accounts: only force enroll if bootstrap made them global admin
        if is_admin and totp_svc.enforce_global_admins():
            _establish_session(uid, email.lower(), name, is_admin)
            session["totp_setup_required"] = True
            flash("Global admins must enable two-factor authentication.", "error")
            return redirect(url_for("totp_setup"))
        _establish_session(uid, email.lower(), name, is_admin)
        return _finish_login_redirect()
    return render_template("register.html", setup_notice=notice)
