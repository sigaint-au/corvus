"""Two-factor setup and recovery routes."""

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
from auth import authz
from auth import totp_svc
log = logging.getLogger(__name__)


@authz.login_required
def totp_setup():
    """Start or continue TOTP enrollment and show QR / secret.

    Args:
        None (uses session user, pending secret, and setup-required flag).

    Returns:
        HTML TOTP setup page, or redirect if already enabled.

    Example:
        GET /profile/2fa
    """
    uid = session["user_id"]
    if totp_svc.is_enabled(uid) and not session.get("totp_setup_required"):
        flash("Two-factor authentication is already enabled", "ok")
        return redirect(url_for("profile", tab="security"))
    secret = session.get("pending_totp_secret")
    if not secret:
        secret = totp_svc.new_secret()
        session["pending_totp_secret"] = secret
    email = session.get("email") or ""
    uri = totp_svc.provisioning_uri(secret, email)
    try:
        qr = totp_svc.qr_data_uri(uri)
    except Exception:
        log.exception("QR generation failed")
        qr = None
    return render_template(
        "totp_setup.html",
        secret=secret,
        qr_data_uri=qr,
        provisioning_uri=uri,
        required=bool(session.get("totp_setup_required")),
    )


@authz.login_required
def totp_setup_confirm():
    """Confirm TOTP enrollment with a code from the authenticator app.

    Args:
        None (reads form ``code`` and session ``pending_totp_secret``).

    Returns:
        Redirect to recovery-codes page on success, or back to setup on error.

    Example:
        POST /profile/2fa/confirm
    """
    uid = session["user_id"]
    secret = session.get("pending_totp_secret")
    code = request.form.get("code") or ""
    if not secret:
        flash("Setup session expired — start again", "error")
        return redirect(url_for("totp_setup"))
    if not totp_svc.verify_code(secret, code):
        flash("Invalid code — check your authenticator and try again", "error")
        return redirect(url_for("totp_setup"))
    try:
        recovery = totp_svc.enable(uid, secret)
    except Exception as e:
        log.exception("totp enable failed")
        flash("Could not update two-factor authentication. Try again.", "error")
        return redirect(url_for("totp_setup"))
    session.pop("pending_totp_secret", None)
    session.pop("totp_setup_required", None)
    session["new_recovery_codes"] = recovery
    flash("Two-factor authentication enabled", "ok")
    return redirect(url_for("totp_recovery_codes"))


@authz.login_required
def totp_recovery_codes():
    """Display newly generated recovery codes once from the session.

    Args:
        None (pops ``new_recovery_codes`` from session).

    Returns:
        HTML recovery-codes page, or redirect if no codes are pending.

    Example:
        GET /profile/2fa/recovery-codes
    """
    codes = session.pop("new_recovery_codes", None)
    if not codes:
        return redirect(url_for("profile", tab="security"))
    return render_template("totp_recovery.html", codes=codes)


@authz.login_required
def totp_disable():
    """Disable TOTP after verifying a current code or recovery code.

    Args:
        None (reads form ``code``; uses session for user and enforcement flags).

    Returns:
        Redirect to profile security or forced setup page.

    Example:
        POST /profile/2fa/disable
    """
    uid = session["user_id"]
    if session.get("totp_setup_required"):
        flash("You must finish setting up two-factor authentication", "error")
        return redirect(url_for("totp_setup"))
    if not totp_svc.is_enabled(uid):
        flash("Two-factor authentication is not enabled", "error")
        return redirect(url_for("profile", tab="security"))
    # When enforce is on, global admins cannot disable
    if session.get("is_global_admin") and totp_svc.enforce_global_admins():
        flash(
            "Global admins cannot disable two-factor authentication while it is enforced",
            "error",
        )
        return redirect(url_for("profile", tab="security"))
    code = request.form.get("code") or ""
    ok, _method = totp_svc.verify_user_code(uid, code)
    if not ok:
        flash("Invalid authentication or recovery code", "error")
        return redirect(url_for("profile", tab="security"))
    totp_svc.disable(uid)
    session.pop("pending_totp_secret", None)
    flash("Two-factor authentication disabled", "ok")
    return redirect(url_for("profile", tab="security"))


@authz.login_required
def totp_regenerate_recovery():
    """Regenerate TOTP recovery codes after verifying a second factor.

    Args:
        None (reads form ``code``; uses session user).

    Returns:
        Redirect to recovery-codes page or profile security on error.

    Example:
        POST /profile/2fa/recovery-codes/regenerate
    """
    uid = session["user_id"]
    if not totp_svc.is_enabled(uid):
        flash("Enable two-factor authentication first", "error")
        return redirect(url_for("profile", tab="security"))
    code = request.form.get("code") or ""
    ok, _method = totp_svc.verify_user_code(uid, code)
    if not ok:
        flash("Invalid authentication or recovery code", "error")
        return redirect(url_for("profile", tab="security"))
    codes = totp_svc.regenerate_recovery_codes(uid)
    session["new_recovery_codes"] = codes
    flash("New recovery codes generated — save them now", "ok")
    return redirect(url_for("totp_recovery_codes"))
