"""Login, OIDC, 2FA, and password-recovery routes."""

from __future__ import annotations

import logging
import os
from datetime import (
    datetime,
    timezone,
)

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from auth import authz, lockout, passwords, totp_svc, user_sessions
from core import db, settings_svc
from integrations import ldap_auth, mailer, oidc_auth

from .helpers import (
    _establish_session,
    _finish_login_redirect,
    _login_page,
    _post_password_login,
)

log = logging.getLogger(__name__)


def login():
    """Render login form or process local/LDAP credentials.

    Args:
        None (reads form ``email``/``password`` on POST; uses session).

    Returns:
        HTML login page, or redirect after success; may return 401/403/429/500.

    Example:
        GET/POST /login
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        ldap_on = settings_svc.truthy(ldap_auth.ldap_cfg().get("ldap_enabled"))
        if lockout.is_locked(email):
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return _login_page(), 429
        user = None
        # 1) Local password accounts (break-glass / non-LDAP users)
        with db.connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM private.verify_user(%s, %s)", (email, password))
            user = cur.fetchone()
        # 2) LDAP when enabled and local auth failed
        if not user and ldap_on:
            ldap_user = ldap_auth.ldap_authenticate(email, password)
            if ldap_user:
                try:
                    user = ldap_auth.sync_ldap_user(
                        ldap_user["email"],
                        ldap_user.get("name") or "",
                        ldap_user.get("groups") or [],
                    )
                except Exception:
                    log.exception("LDAP user sync failed")
                    flash("LDAP sign-in succeeded, but account setup failed. Try again.", "error")
                    return _login_page(), 500
        if not user:
            lockout.record_failure(email)
            flash("Invalid email or password", "error")
            return _login_page(), 401
        if authz.is_account_disabled(str(user["id"])):
            flash("This account has been disabled. Contact an administrator.", "error")
            return _login_page(), 403
        lockout.clear_failures(email)
        return _post_password_login(user)
    return _login_page()


def login_oidc():
    """Begin OIDC SSO by redirecting to the identity provider.

    Args:
        None (reads OIDC settings and request URL root for redirect URI).

    Returns:
        Redirect to the IdP authorize URL, or back to login on error.

    Example:
        GET /login/oidc
    """
    if not oidc_auth.oidc_enabled():
        flash("SSO is not enabled", "error")
        return redirect(url_for("login"))
    try:
        state, nonce = oidc_auth.new_state_nonce()
        session["oidc_state"] = state
        session["oidc_nonce"] = nonce
        redirect_uri = oidc_auth.redirect_uri_for_request(request.url_root)
        session["oidc_redirect_uri"] = redirect_uri
        url = oidc_auth.build_authorize_url(
            redirect_uri=redirect_uri, state=state, nonce=nonce
        )
        return redirect(url)
    except Exception:
        log.exception("OIDC start failed")
        flash("Could not start SSO sign-in. Try again.", "error")
        return redirect(url_for("login"))


def login_oidc_callback():
    """Handle OIDC callback: exchange code, sync user, complete login.

    Args:
        None (reads query ``code``, ``state``, ``error``; uses session OIDC keys).

    Returns:
        Redirect after successful login, or to login with an error flash.

    Example:
        GET /login/oidc/callback?code=...&state=...
    """
    if not oidc_auth.oidc_enabled():
        flash("SSO is not enabled", "error")
        return redirect(url_for("login"))
    err = request.args.get("error")
    if err:
        desc = request.args.get("error_description") or err
        flash(f"SSO login denied: {desc}", "error")
        return redirect(url_for("login"))
    code = request.args.get("code") or ""
    state = request.args.get("state") or ""
    want_state = session.pop("oidc_state", None)
    nonce = session.pop("oidc_nonce", None)
    redirect_uri = session.pop("oidc_redirect_uri", None) or oidc_auth.redirect_uri_for_request(
        request.url_root
    )
    if not code or not want_state or state != want_state or not nonce:
        flash("SSO login failed (invalid state). Try again.", "error")
        return redirect(url_for("login"))
    try:
        tokens = oidc_auth.exchange_code(code=code, redirect_uri=redirect_uri)
        id_token = tokens.get("id_token")
        if not id_token:
            raise RuntimeError("token response missing id_token")
        claims = oidc_auth.verify_id_token(id_token, nonce=nonce)
        ident = oidc_auth.claims_to_identity(claims)
        user = oidc_auth.sync_oidc_user(
            ident["email"], ident["name"], ident.get("groups") or []
        )
    except Exception:
        log.exception("OIDC callback failed")
        flash("SSO sign-in failed. Try again.", "error")
        return redirect(url_for("login"))
    if authz.is_account_disabled(str(user["id"])):
        flash("This account has been disabled. Contact an administrator.", "error")
        return redirect(url_for("login"))
    return _post_password_login(user)


def login_2fa():
    """Render or process the second-factor (TOTP/recovery) challenge.

    Args:
        None (reads pending 2FA session keys; form ``code`` on POST).

    Returns:
        HTML 2FA form, or redirect after success; may return 401/429.

    Example:
        GET/POST /login/2fa
    """
    uid = session.get("pending_2fa_uid")
    if not uid:
        return redirect(url_for("login"))
    if authz.is_account_disabled(uid):
        session.clear()
        flash("This account has been disabled. Contact an administrator.", "error")
        return redirect(url_for("login"))
    email = session.get("pending_2fa_email") or ""
    if request.method == "POST":
        if lockout.is_locked(email or uid):
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login_2fa.html", email=email), 429
        code = request.form.get("code") or ""
        ok, method = totp_svc.verify_user_code(uid, code)
        if not ok:
            lockout.record_failure(email or uid)
            flash("Invalid authentication code", "error")
            return render_template("login_2fa.html", email=email), 401
        lockout.clear_failures(email or uid)
        name = session.get("pending_2fa_name") or ""
        is_admin = bool(session.get("pending_2fa_admin"))
        # Drop pending keys via full establish
        _establish_session(uid, email, name, is_admin)
        if method == "recovery":
            left = totp_svc.recovery_codes_remaining(uid)
            flash(
                f"Signed in with a recovery code. {left} recovery code(s) remaining. "
                "Consider regenerating codes on your profile.",
                "ok",
            )
        if mailer.login_alerts_enabled():
            try:
                ua, ip = user_sessions.client_meta()
                when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                mailer.send_login_alert(
                    email, ip=ip, user_agent=ua, when=when
                )
            except Exception:
                log.exception("login alert email failed")
        return _finish_login_redirect()
    return render_template("login_2fa.html", email=email)


def forgot_password():
    """Request a password reset link for a local account.

    Always shows a generic success message to avoid account enumeration.
    When SMTP is configured, emails the link; in insecure-dev mode may flash it.

    Args:
        None (reads form ``email`` on POST; uses session if already logged in).

    Returns:
        HTML forgot-password form, or redirect to login/profile.

    Example:
        GET/POST /forgot-password
    """
    if session.get("user_id"):
        return redirect(url_for("profile"))
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        token = passwords.create_reset_token(email)
        # Always same response (no account enumeration)
        msg = (
            "If a local account exists for that email, a password reset link "
            "has been prepared. Check with your administrator if you do not "
            "receive one."
        )
        if token:
            link = url_for("reset_password", token=token, _external=True)
            mailed = False
            if mailer.smtp_configured():
                ok, err = mailer.send_password_reset(email.strip().lower(), link)
                if ok:
                    mailed = True
                    log.info("password reset email sent for %s", email.lower())
                else:
                    log.warning(
                        "password reset email failed for %s: %s", email.lower(), err
                    )
            else:
                log.info(
                    "password reset token created for local user %s (SMTP not configured)",
                    email.lower(),
                )
            # Dev mode: surface the link when mail was not sent
            if not mailed and os.environ.get("ALLOW_INSECURE_DEFAULTS", "").lower() in (
                "1",
                "true",
                "yes",
            ):
                flash(f"Development reset link: {link}", "ok")
                log.warning("password reset token issued for %s (dev mode)", email)
            else:
                flash(msg, "ok")
        else:
            flash(msg, "ok")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


def reset_password(token):
    """Show reset form or consume a password-reset token.

    Args:
        token: One-time reset token from the URL path.

    Returns:
        HTML reset form, redirect to login/profile, or 400 on validation failure.

    Example:
        GET/POST /reset-password/<token>
    """
    if session.get("user_id"):
        return redirect(url_for("profile"))
    if request.method == "POST":
        pw = request.form.get("password") or ""
        pw2 = request.form.get("password_confirm") or ""
        if pw != pw2:
            flash("Passwords do not match", "error")
            return render_template("reset_password.html", token=token), 400
        ok, err = passwords.consume_reset_token(token, pw)
        if not ok:
            flash(err or "Reset failed", "error")
            return render_template("reset_password.html", token=token), 400
        flash("Password updated. Sign in with your new password.", "ok")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)
