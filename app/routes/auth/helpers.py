"""Shared login/session/2FA helper functions."""

from __future__ import annotations

import logging
from datetime import (
    datetime,
    timezone,
)
from flask import (
    flash,
    redirect,
    render_template,
    session,
    url_for,
)
import authz
import db
import ldap_auth
import mailer
import oidc_auth
import settings_svc
import totp_svc
import user_sessions
from config import bootstrap_admin_email
log = logging.getLogger(__name__)


def _maybe_promote_bootstrap_admin(email: str, user_id) -> bool:
    """Promote a user to global admin if email matches bootstrap config.

    Args:
        email: User email to compare against bootstrap admin email.
        user_id: UUID of the user to promote (string or UUID-like).

    Returns:
        ``True`` if the user is (or was just made) a global admin; otherwise
        the current global-admin flag from the database.

    Example:
        >>> _maybe_promote_bootstrap_admin("admin@example.com", user_id)
        True
    """
    boot = bootstrap_admin_email()
    if not boot or (email or "").strip().lower() != boot:
        return authz.is_global_admin(str(user_id))
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE private.users SET is_global_admin = true WHERE id = %s::uuid",
                (str(user_id),),
            )
        return True
    except Exception:
        log.exception("bootstrap admin promote failed")
        return authz.is_global_admin(str(user_id))


def _preserve_auth_extras():
    """Snapshot invite token and CSRF for session regeneration.

    Args:
        None (reads Flask session).

    Returns:
        Dict with ``invite_token`` and ``_csrf`` values from the current session.

    Example:
        >>> extras = _preserve_auth_extras()
        >>> session.clear()
        >>> _restore_auth_extras(extras)
    """
    return {
        "invite_token": session.get("invite_token"),
        "_csrf": session.get("_csrf"),
    }


def _restore_auth_extras(extras: dict):
    """Restore invite token and CSRF into the Flask session.

    Args:
        extras: Mapping previously returned by ``_preserve_auth_extras``.

    Returns:
        None.

    Example:
        >>> _restore_auth_extras({"invite_token": "abc", "_csrf": "tok"})
    """
    if extras.get("invite_token"):
        session["invite_token"] = extras["invite_token"]
    if extras.get("_csrf"):
        session["_csrf"] = extras["_csrf"]


def _establish_session(user_id, email, name, is_global_admin: bool):
    """Clear session, restore extras, and set authenticated session values.

    Args:
        user_id: Authenticated user UUID.
        email: User email to store in session.
        name: Display name (empty string if missing).
        is_global_admin: Whether the user is a global admin.

    Returns:
        None (mutates Flask session; may create a server-side session row).

    Example:
        >>> _establish_session(uid, "u@example.com", "Ada", False)
    """
    extras = _preserve_auth_extras()
    session.clear()
    _restore_auth_extras(extras)
    session["user_id"] = str(user_id)
    session["email"] = email
    session["name"] = name or ""
    session["is_global_admin"] = bool(is_global_admin)
    session["jwt"] = db.make_jwt(user_id)
    sid = user_sessions.create_session(user_id)
    if sid:
        session["sid"] = sid


def _begin_2fa_challenge(user_id, email, name, is_global_admin: bool):
    """Start a pending 2FA challenge after primary credentials succeed.

    Args:
        user_id: User UUID awaiting second factor.
        email: User email for lockout and display.
        name: Display name to use after successful 2FA.
        is_global_admin: Admin flag to restore after 2FA.

    Returns:
        None (writes ``pending_2fa_*`` keys into the session).

    Example:
        >>> _begin_2fa_challenge(uid, "u@example.com", "Ada", True)
        >>> # then redirect to /login/2fa
    """
    extras = _preserve_auth_extras()
    session.clear()
    _restore_auth_extras(extras)
    session["pending_2fa_uid"] = str(user_id)
    session["pending_2fa_email"] = email
    session["pending_2fa_name"] = name or ""
    session["pending_2fa_admin"] = bool(is_global_admin)


def _finish_login_redirect():
    """Redirect after successful login, honoring a pending invite token.

    Args:
        None (reads Flask session for ``invite_token``).

    Returns:
        Flask redirect Response to invite redemption or teams list.

    Example:
        >>> return _finish_login_redirect()
    """
    pending_invite = session.get("invite_token")
    if pending_invite:
        return redirect(url_for("redeem_invite", token=pending_invite))
    return redirect(url_for("teams"))


def _post_password_login(user):
    """Complete login after password/LDAP/OIDC primary auth succeeds.

    Handles bootstrap admin promotion, TOTP challenge or forced enrollment,
    optional login-alert email, and final redirect.

    Args:
        user: Mapping with at least ``id``, ``email``, and optional ``name``.

    Returns:
        Flask response: redirect to 2FA, TOTP setup, invite, teams, or login.

    Example:
        >>> return _post_password_login(user_row)
    """
    _maybe_promote_bootstrap_admin(user["email"], user["id"])
    is_admin = authz.is_global_admin(str(user["id"]))
    try:
        step = totp_svc.needs_challenge(str(user["id"]), is_admin)
    except totp_svc.TotpStoreError:
        log.exception("TOTP check failed during login")
        flash("Sign-in temporarily unavailable. Try again shortly.", "error")
        return redirect(url_for("login"))
    if step == "verify":
        _begin_2fa_challenge(user["id"], user["email"], user.get("name") or "", is_admin)
        return redirect(url_for("login_2fa"))
    if step == "enroll":
        _establish_session(user["id"], user["email"], user.get("name") or "", is_admin)
        session["totp_setup_required"] = True
        flash("Global admins must enable two-factor authentication.", "error")
        return redirect(url_for("totp_setup"))
    _establish_session(user["id"], user["email"], user.get("name") or "", is_admin)
    if mailer.login_alerts_enabled():
        try:
            ua, ip = user_sessions.client_meta()
            when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            ok, err = mailer.send_login_alert(
                user["email"], ip=ip, user_agent=ua, when=when
            )
            if not ok:
                log.warning("login alert email failed for %s: %s", user["email"], err)
        except Exception:
            log.exception("login alert email failed")
    return _finish_login_redirect()


def _login_page(**extra):
    """Render the login template with current auth provider flags.

    Args:
        **extra: Extra template context keyword arguments.

    Returns:
        Rendered HTML for ``login.html``.

    Example:
        >>> return _login_page()
        >>> return _login_page(), 401
    """
    ldap_on = settings_svc.truthy(ldap_auth.ldap_cfg().get("ldap_enabled"))
    oidc_on = oidc_auth.oidc_enabled()
    cfg = oidc_auth.oidc_cfg()
    return render_template(
        "login.html",
        ldap_enabled=ldap_on,
        oidc_enabled=oidc_on,
        oidc_button_label=cfg.get("oidc_button_label") or "Sign in with SSO",
        registration_enabled=settings_svc.registration_enabled(),
        setup_notice=settings_svc.setup_notice(),
        **extra,
    )
