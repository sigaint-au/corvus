"""Local account registration route."""

from __future__ import annotations

import logging

import psycopg
from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from auth import authz, totp_svc
from core import db, settings_svc
from integrations import mailer

from .helpers import (
    _establish_session,
    _finish_login_redirect,
    _maybe_promote_bootstrap_admin,
    send_verification_email,
)

log = logging.getLogger(__name__)

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
        flash(notice or "Registration is disabled", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm") or ""
        name = request.form.get("name", "").strip()
        if len(password) < 8:
            flash("Password must be at least 8 characters", "error")
            return render_template("register.html", setup_notice=notice), 400
        if password != password_confirm:
            flash("Passwords do not match", "error")
            return render_template("register.html", setup_notice=notice), 400
        try:
            with db.connect(autocommit=True) as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT private.register_user(%s, %s, %s) AS id",
                    (email, password, name),
                )
                uid = cur.fetchone()["id"]
        except psycopg.errors.UniqueViolation:
            flash("An account with this email already exists", "error")
            return render_template("register.html", setup_notice=notice), 400
        except Exception:
            flash("Account creation failed. Try again.", "error")
            return render_template("register.html", setup_notice=notice), 400
        _maybe_promote_bootstrap_admin(email.lower(), uid)
        if mailer.smtp_configured():
            if send_verification_email(uid, email.lower()):
                flash("We sent a verification link to your inbox. Sign in to activate your account.", "ok")
                return redirect(url_for("login"))
            # SMTP broke mid-signup: fail open so the account is not locked out.
            log.warning("verification send failed; auto-verified %s", email.lower())
        # No SMTP, or send failed: stamp verified so the next login is not gated.
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE private.users SET email_verified_at = now()"
                " WHERE id = %s::uuid",
                (str(uid),),
            )
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
