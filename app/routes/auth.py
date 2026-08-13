"""Login, register, logout, index, password, sessions."""

import os
from datetime import datetime, timezone

from flask import flash, redirect, render_template, request, session, url_for
import psycopg

import authz
import config
from config import bootstrap_admin_email
import db
import ldap_auth
import lockout
import mailer
import nav
import oidc_auth
import passwords
import pats
import pins
import settings_svc
import totp_svc
import user_sessions


log = __import__("logging").getLogger(__name__)

PROFILE_TABS = ("account", "security", "myaccess", "teams", "projects", "activity")


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


def register(app):
    """Register authentication and profile routes on the Flask app.

    Args:
        app: Flask application instance to attach routes to.

    Returns:
        None.

    Example:
        >>> from app.routes import auth
        >>> auth.register(app)
    """
    @app.post("/select-team")
    @authz.login_required
    def select_team():
        """Set the active team in session and redirect safely.

        Args:
            None (reads ``team_id`` and ``next`` from the form; uses session).

        Returns:
            Redirect Response to ``next``, referrer, or projects list.

        Example:
            POST /select-team
        """
        tid = (request.form.get("team_id") or "").strip()
        session["team_id"] = tid or None
        nxt = request.form.get("next") or request.referrer or url_for("projects_list")
        # Leave project URLs that belong to another team (e.g. secrets tab
        # stayed on the old project and looked like a no-op).
        nxt = nav.redirect_after_team_switch(nxt, tid or None)
        return redirect(nxt)


    # ── Auth ──────────────────────────────────────────────────────────


    @app.get("/")
    def index():
        """Redirect root URL to teams when logged in, otherwise login.

        Args:
            None (reads Flask session for ``user_id``).

        Returns:
            Redirect Response to teams or login.

        Example:
            GET /
        """
        if session.get("user_id"):
            return redirect(url_for("teams"))
        return redirect(url_for("login"))


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

    @app.route("/login", methods=["GET", "POST"])
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
            email = request.form["email"].strip()
            password = request.form["password"]
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
                    except Exception as e:
                        log.exception("LDAP user sync failed")
                        flash(f"LDAP login succeeded but account sync failed: {e}", "error")
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

    @app.get("/login/oidc")
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
        except Exception as e:
            log.exception("OIDC start failed")
            flash(f"SSO start failed: {e}", "error")
            return redirect(url_for("login"))

    @app.get("/login/oidc/callback")
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
        except Exception as e:
            log.exception("OIDC callback failed")
            flash(f"SSO login failed: {e}", "error")
            return redirect(url_for("login"))
        if authz.is_account_disabled(str(user["id"])):
            flash("This account has been disabled. Contact an administrator.", "error")
            return redirect(url_for("login"))
        return _post_password_login(user)


    @app.route("/login/2fa", methods=["GET", "POST"])
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


    @app.route("/register", methods=["GET", "POST"])
    def register():
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
            email = request.form["email"].strip()
            password = request.form["password"]
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


    @app.post("/logout")
    def logout():
        """Sign out the current user via POST and clear the session.

        Args:
            None (reads ``user_id`` and ``sid`` from session).

        Returns:
            Redirect Response to the login page.

        Example:
            POST /logout
        """
        uid = session.get("user_id")
        sid = session.get("sid")
        if uid and sid:
            user_sessions.revoke_session(sid, uid)
        session.clear()
        return redirect(url_for("login"))

    # Allow GET cancel from 2FA page without CSRF form complexity when needed
    @app.get("/logout")
    def logout_get():
        """Sign out via GET (e.g. cancel 2FA) when a session or pending 2FA exists.

        Args:
            None (reads pending 2FA / user session keys).

        Returns:
            Redirect Response to the login page.

        Example:
            GET /logout
        """
        if session.get("pending_2fa_uid") or session.get("user_id"):
            uid = session.get("user_id")
            sid = session.get("sid")
            if uid and sid:
                user_sessions.revoke_session(sid, uid)
            session.clear()
        return redirect(url_for("login"))


    @app.route("/forgot-password", methods=["GET", "POST"])
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
                    flash(f"Dev reset link (ALLOW_INSECURE_DEFAULTS): {link}", "ok")
                    log.warning("password reset token issued for %s (dev mode)", email)
                else:
                    flash(msg, "ok")
            else:
                flash(msg, "ok")
            return redirect(url_for("login"))
        return render_template("forgot_password.html")


    @app.route("/reset-password/<token>", methods=["GET", "POST"])
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


    @app.post("/profile/tokens")
    @authz.login_required
    def create_personal_token():
        """Create a personal access token for the current user.

        Args:
            None (reads form ``name`` and ``expires_days``; uses session user).

        Returns:
            Redirect to profile security tab (raw token stored in session once).

        Example:
            POST /profile/tokens
        """
        name = (request.form.get("name") or "").strip()
        days_raw = (request.form.get("expires_days") or "").strip()
        expires_days = None
        if days_raw:
            try:
                expires_days = int(days_raw)
            except ValueError:
                flash("Expires days must be a positive integer", "error")
                return redirect(url_for("profile", tab="security"))
        try:
            raw = pats.create(session["user_id"], name, expires_days=expires_days)
            session["new_pat"] = raw
            flash("Personal access token created — copy it now; it is shown once", "ok")
        except ValueError as e:
            flash(str(e), "error")
        except Exception as e:
            log.exception("create PAT failed")
            flash(str(e), "error")
        return redirect(url_for("profile", tab="security"))

    @app.post("/profile/tokens/<uuid:token_id>/delete")
    @authz.login_required
    def delete_personal_token(token_id):
        """Revoke a personal access token owned by the current user.

        Args:
            token_id: UUID of the PAT to revoke (path parameter).

        Returns:
            Redirect to profile security tab with success or error flash.

        Example:
            POST /profile/tokens/<uuid>/delete
        """
        if pats.revoke(session["user_id"], str(token_id)):
            flash("Token revoked", "ok")
        else:
            flash("Token not found", "error")
        return redirect(url_for("profile", tab="security"))

    @app.post("/profile/password")
    @authz.login_required
    def change_password():
        """Change the current user's local password and revoke other sessions.

        Args:
            None (reads form ``current_password``, ``new_password``,
            ``new_password_confirm``; uses session).

        Returns:
            Redirect to profile security tab with status flash.

        Example:
            POST /profile/password
        """
        uid = session["user_id"]
        old = request.form.get("current_password") or ""
        new = request.form.get("new_password") or ""
        conf = request.form.get("new_password_confirm") or ""
        if new != conf:
            flash("New passwords do not match", "error")
            return redirect(url_for("profile", tab="security"))
        ok, err = passwords.change_password(uid, old, new)
        if not ok:
            flash(err or "Could not change password", "error")
            return redirect(url_for("profile", tab="security"))
        # Keep current session; sign out other devices after password change
        sid = session.get("sid")
        if sid:
            n = user_sessions.revoke_other_sessions(uid, sid)
            if n:
                flash(f"Password updated. Signed out {n} other session(s).", "ok")
            else:
                flash("Password updated.", "ok")
        else:
            flash("Password updated.", "ok")
        return redirect(url_for("profile", tab="security"))


    @app.post("/profile/sessions/revoke-others")
    @authz.login_required
    def revoke_other_sessions():
        """Revoke all of the user's sessions except the current browser.

        Args:
            None (reads ``user_id`` and ``sid`` from session).

        Returns:
            Redirect to profile security tab.

        Example:
            POST /profile/sessions/revoke-others
        """
        uid = session["user_id"]
        sid = session.get("sid")
        if not sid:
            flash("No active session registry entry for this browser", "error")
            return redirect(url_for("profile", tab="security"))
        n = user_sessions.revoke_other_sessions(uid, sid)
        flash(f"Signed out {n} other session(s).", "ok")
        return redirect(url_for("profile", tab="security"))


    @app.post("/profile/sessions/<uuid:session_id>/revoke")
    @authz.login_required
    def revoke_session(session_id):
        """Revoke one session; signing out the current session clears cookies.

        Args:
            session_id: UUID of the session to revoke (path parameter).

        Returns:
            Redirect to login if current session was revoked, else profile security.

        Example:
            POST /profile/sessions/<uuid>/revoke
        """
        uid = session["user_id"]
        sid = str(session_id)
        if sid == session.get("sid"):
            user_sessions.revoke_session(sid, uid)
            session.clear()
            flash("Signed out this session.", "ok")
            return redirect(url_for("login"))
        if user_sessions.revoke_session(sid, uid):
            flash("Session signed out.", "ok")
        else:
            flash("Session not found or already signed out.", "error")
        return redirect(url_for("profile", tab="security"))


    @app.get("/profile/2fa")
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


    @app.post("/profile/2fa/confirm")
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
            flash(str(e), "error")
            return redirect(url_for("totp_setup"))
        session.pop("pending_totp_secret", None)
        session.pop("totp_setup_required", None)
        session["new_recovery_codes"] = recovery
        flash("Two-factor authentication enabled", "ok")
        return redirect(url_for("totp_recovery_codes"))


    @app.get("/profile/2fa/recovery-codes")
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


    @app.post("/profile/2fa/disable")
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


    @app.post("/profile/2fa/recovery-codes/regenerate")
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


    @app.get("/profile")
    @authz.login_required
    def profile():
        """Render the tabbed profile page (account, security, teams, etc.).

        Args:
            None (reads query ``tab``; uses session ``user_id`` and related data).

        Returns:
            HTML profile template, or redirect if the user cannot be loaded.

        Example:
            GET /profile?tab=security
        """
        tab = (request.args.get("tab") or "account").strip().lower()
        if tab not in PROFILE_TABS:
            tab = "account"

        uid = session["user_id"]
        user = None
        try:
            with db.connect_admin() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, email, name, is_global_admin, auth_source, created_at,
                           totp_enabled_at
                    FROM private.users
                    WHERE id = %s::uuid
                    """,
                    (uid,),
                )
                user = cur.fetchone()
        except Exception:
            log.exception("profile: load user failed")
        if not user:
            flash("Could not load your profile", "error")
            return redirect(url_for("projects_list"))

        totp_on = bool(user.get("totp_enabled_at"))
        recovery_left = totp_svc.recovery_codes_remaining(uid) if totp_on else 0
        totp_enforced = bool(
            user.get("is_global_admin") and totp_svc.enforce_global_admins()
        )

        active_sessions = user_sessions.list_sessions(uid) if tab == "security" else []
        current_sid = session.get("sid")
        personal_tokens = []
        if tab == "security":
            try:
                personal_tokens = pats.list_for_user(uid)
            except Exception:
                log.exception("profile: list PATs failed")
                personal_tokens = []
        teams, projects, pending, pins_list, recent = [], [], [], [], []
        secret_count = pin_count = 0
        my_access = []
        try:
            with db.as_user(uid) as conn, conn.cursor() as cur:
                if tab in ("account", "teams"):
                    cur.execute(
                        """
                        SELECT t.id, t.name,
                               api.team_role(t.id) AS role,
                               'rbac' AS source,
                               t.created_at,
                          (SELECT count(*) FROM api.projects p WHERE p.team_id = t.id)
                            AS project_count
                        FROM api.teams t
                        WHERE api.is_team_member(t.id)
                        ORDER BY t.name
                        """,
                        (),
                    )
                    teams = cur.fetchall() or []

                if tab in ("account", "projects"):
                    cur.execute(
                        """
                        SELECT p.id, p.name, p.created_at,
                               t.id AS team_id, t.name AS team_name,
                               api.team_role(t.id) AS team_role,
                               api.project_role(p.id) AS project_role,
                          (SELECT count(*) FROM api.secrets s
                           WHERE s.project_id = p.id AND s.deleted_at IS NULL)
                            AS secret_count
                        FROM api.projects p
                        JOIN api.teams t ON t.id = p.team_id
                        WHERE api.can_read_project(p.id)
                        ORDER BY t.name, p.name
                        """,

                    )
                    projects = cur.fetchall() or []

                if tab == "account":
                    cur.execute(
                        "SELECT count(*) AS n FROM api.secrets WHERE deleted_at IS NULL"
                    )
                    row = cur.fetchone()
                    secret_count = int(row["n"]) if row else 0
                    cur.execute(
                        """
                        SELECT count(*) AS n FROM api.secret_pins
                        WHERE user_id = %s
                        """,
                        (uid,),
                    )
                    row = cur.fetchone()
                    pin_count = int(row["n"]) if row else 0

                if tab in ("account", "teams"):
                    cur.execute(
                        """
                        SELECT r.id, r.role, r.status, r.created_at,
                               t.id AS team_id, t.name AS team_name
                        FROM api.team_join_requests r
                        JOIN api.teams t ON t.id = r.team_id
                        WHERE r.user_id = %s AND r.status = 'pending'
                        ORDER BY r.created_at DESC
                        """,
                        (uid,),
                    )
                    pending = cur.fetchall() or []

                if tab == "activity":
                    pins_list = pins.list_pins(cur, uid)
                    recent = pins.list_recent(cur, uid)
                if tab == "myaccess":
                    try:
                        cur.execute("SELECT * FROM api.my_access_rows()")
                        my_access = list(cur.fetchall() or [])
                    except Exception:
                        conn.rollback()
                        log.exception("profile: my access rows failed")
                        my_access = []
        except Exception:
            log.exception("profile: load memberships failed")

        # Prefer DB values for session-display consistency
        session["email"] = user.get("email") or session.get("email")
        session["name"] = user.get("name") or session.get("name") or ""
        session["is_global_admin"] = bool(user.get("is_global_admin"))

        # My access: bindings grouped by scope for the My access tab
        _scope_labels = {
            "cluster": "Global",
            "team": "Team access",
            "project": "Project access",
            "secret": "Secret access",
        }
        _scope_order = ("cluster", "team", "project", "secret")
        my_access_groups = []
        by_scope: dict[str, list] = {}
        for row in my_access:
            by_scope.setdefault(row["scope_kind"], []).append(row)
        for kind in _scope_order:
            rows = by_scope.get(kind)
            if rows:
                my_access_groups.append((_scope_labels[kind], rows))

        return render_template(
            "profile.html",
            user=user,
            teams=teams if tab == "teams" else [],
            projects=projects if tab == "projects" else [],
            pending_joins=pending if tab == "teams" else [],
            pins=pins_list,
            recent=recent,
            active_sessions=active_sessions,
            current_sid=current_sid,
            personal_tokens=personal_tokens,
            new_pat=session.pop("new_pat", None),
            totp_enabled=totp_on,
            totp_recovery_remaining=recovery_left,
            totp_enforced_for_user=totp_enforced,
            active_tab=tab,
            postgrest_url=config.POSTGREST_URL,
            my_access_groups=my_access_groups,
            stats={
                "teams": len(teams),
                "projects": len(projects),
                "secrets": secret_count,
                "pins": pin_count,
                "pending_joins": len(pending),
            },
        )
