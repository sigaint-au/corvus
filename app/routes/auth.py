"""Login, register, logout, index, password, sessions."""

import os
from datetime import datetime, timezone

from flask import flash, redirect, render_template, request, session, url_for
import psycopg

import authz
from config import bootstrap_admin_email
import db
import ldap_auth
import lockout
import mailer
import passwords
import pins
import settings_svc
import totp_svc
import user_sessions


log = __import__("logging").getLogger(__name__)


def _maybe_promote_bootstrap_admin(email: str, user_id) -> bool:
    """Promote email to global admin if it matches bootstrap config. Returns new is_global_admin."""
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
    """Keep invite + CSRF across session regeneration."""
    return {
        "invite_token": session.get("invite_token"),
        "_csrf": session.get("_csrf"),
    }


def _restore_auth_extras(extras: dict):
    if extras.get("invite_token"):
        session["invite_token"] = extras["invite_token"]
    if extras.get("_csrf"):
        session["_csrf"] = extras["_csrf"]


def _establish_session(user_id, email, name, is_global_admin: bool):
    """Clear session then set auth values (session regeneration)."""
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
    extras = _preserve_auth_extras()
    session.clear()
    _restore_auth_extras(extras)
    session["pending_2fa_uid"] = str(user_id)
    session["pending_2fa_email"] = email
    session["pending_2fa_name"] = name or ""
    session["pending_2fa_admin"] = bool(is_global_admin)


def _finish_login_redirect():
    pending_invite = session.get("invite_token")
    if pending_invite:
        return redirect(url_for("redeem_invite", token=pending_invite))
    return redirect(url_for("teams"))


def _post_password_login(user):
    """
    After password/LDAP success: 2FA challenge, forced enroll, or full session.
    Returns a Flask response.
    """
    _maybe_promote_bootstrap_admin(user["email"], user["id"])
    is_admin = authz.is_global_admin(str(user["id"]))
    step = totp_svc.needs_challenge(str(user["id"]), is_admin)
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
    @app.post("/select-team")
    @authz.login_required
    def select_team():
        tid = (request.form.get("team_id") or "").strip()
        session["team_id"] = tid or None
        nxt = request.form.get("next") or request.referrer or url_for("projects_list")
        nxt = authz.safe_redirect_target(nxt, url_for("projects_list"))
        return redirect(nxt)


    # ── Auth ──────────────────────────────────────────────────────────


    @app.get("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("teams"))
        return redirect(url_for("login"))


    @app.route("/login", methods=["GET", "POST"])
    def login():
        ldap_on = settings_svc.truthy(ldap_auth.ldap_cfg().get("ldap_enabled"))
        notice = settings_svc.setup_notice()
        if request.method == "POST":
            email = request.form["email"].strip()
            password = request.form["password"]
            if lockout.is_locked(email):
                flash("Too many failed attempts. Try again in a few minutes.", "error")
                return render_template(
                    "login.html",
                    ldap_enabled=ldap_on,
                    registration_enabled=settings_svc.registration_enabled(),
                    setup_notice=notice,
                ), 429
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
                        return render_template(
                            "login.html",
                            ldap_enabled=ldap_on,
                            registration_enabled=settings_svc.registration_enabled(),
                            setup_notice=notice,
                        ), 500
            if not user:
                lockout.record_failure(email)
                flash("Invalid email or password", "error")
                return render_template(
                    "login.html",
                    ldap_enabled=ldap_on,
                    registration_enabled=settings_svc.registration_enabled(),
                    setup_notice=notice,
                ), 401
            lockout.clear_failures(email)
            return _post_password_login(user)
        return render_template(
            "login.html",
            ldap_enabled=ldap_on,
            registration_enabled=settings_svc.registration_enabled(),
            setup_notice=notice,
        )


    @app.route("/login/2fa", methods=["GET", "POST"])
    def login_2fa():
        uid = session.get("pending_2fa_uid")
        if not uid:
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
        uid = session.get("user_id")
        sid = session.get("sid")
        if uid and sid:
            user_sessions.revoke_session(sid, uid)
        session.clear()
        return redirect(url_for("login"))

    # Allow GET cancel from 2FA page without CSRF form complexity when needed
    @app.get("/logout")
    def logout_get():
        if session.get("pending_2fa_uid") or session.get("user_id"):
            uid = session.get("user_id")
            sid = session.get("sid")
            if uid and sid:
                user_sessions.revoke_session(sid, uid)
            session.clear()
        return redirect(url_for("login"))


    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        """Request a password reset link (local accounts only)."""
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


    @app.post("/profile/password")
    @authz.login_required
    def change_password():
        uid = session["user_id"]
        old = request.form.get("current_password") or ""
        new = request.form.get("new_password") or ""
        conf = request.form.get("new_password_confirm") or ""
        if new != conf:
            flash("New passwords do not match", "error")
            return redirect(url_for("profile"))
        ok, err = passwords.change_password(uid, old, new)
        if not ok:
            flash(err or "Could not change password", "error")
            return redirect(url_for("profile"))
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
        return redirect(url_for("profile"))


    @app.post("/profile/sessions/revoke-others")
    @authz.login_required
    def revoke_other_sessions():
        uid = session["user_id"]
        sid = session.get("sid")
        if not sid:
            flash("No active session registry entry for this browser", "error")
            return redirect(url_for("profile"))
        n = user_sessions.revoke_other_sessions(uid, sid)
        flash(f"Signed out {n} other session(s).", "ok")
        return redirect(url_for("profile"))


    @app.post("/profile/sessions/<uuid:session_id>/revoke")
    @authz.login_required
    def revoke_session(session_id):
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
        return redirect(url_for("profile"))


    @app.get("/profile/2fa")
    @authz.login_required
    def totp_setup():
        """Start or continue TOTP enrollment."""
        uid = session["user_id"]
        if totp_svc.is_enabled(uid) and not session.get("totp_setup_required"):
            flash("Two-factor authentication is already enabled", "ok")
            return redirect(url_for("profile"))
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
        codes = session.pop("new_recovery_codes", None)
        if not codes:
            return redirect(url_for("profile"))
        return render_template("totp_recovery.html", codes=codes)


    @app.post("/profile/2fa/disable")
    @authz.login_required
    def totp_disable():
        uid = session["user_id"]
        if session.get("totp_setup_required"):
            flash("You must finish setting up two-factor authentication", "error")
            return redirect(url_for("totp_setup"))
        if not totp_svc.is_enabled(uid):
            flash("Two-factor authentication is not enabled", "error")
            return redirect(url_for("profile"))
        # When enforce is on, global admins cannot disable
        if session.get("is_global_admin") and totp_svc.enforce_global_admins():
            flash(
                "Global admins cannot disable two-factor authentication while it is enforced",
                "error",
            )
            return redirect(url_for("profile"))
        code = request.form.get("code") or ""
        ok, _method = totp_svc.verify_user_code(uid, code)
        if not ok:
            flash("Invalid authentication or recovery code", "error")
            return redirect(url_for("profile"))
        totp_svc.disable(uid)
        session.pop("pending_totp_secret", None)
        flash("Two-factor authentication disabled", "ok")
        return redirect(url_for("profile"))


    @app.post("/profile/2fa/recovery-codes/regenerate")
    @authz.login_required
    def totp_regenerate_recovery():
        uid = session["user_id"]
        if not totp_svc.is_enabled(uid):
            flash("Enable two-factor authentication first", "error")
            return redirect(url_for("profile"))
        code = request.form.get("code") or ""
        ok, _method = totp_svc.verify_user_code(uid, code)
        if not ok:
            flash("Invalid authentication or recovery code", "error")
            return redirect(url_for("profile"))
        codes = totp_svc.regenerate_recovery_codes(uid)
        session["new_recovery_codes"] = codes
        flash("New recovery codes generated — save them now", "ok")
        return redirect(url_for("totp_recovery_codes"))


    @app.get("/profile")
    @authz.login_required
    def profile():
        """My profile: account info, memberships, projects, and activity."""
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

        active_sessions = user_sessions.list_sessions(uid)
        current_sid = session.get("sid")
        teams, projects, pending, pins_list, recent = [], [], [], [], []
        secret_count = pin_count = 0
        try:
            with db.as_user(uid) as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT t.id, t.name, tm.role, tm.source, t.created_at,
                      (SELECT count(*) FROM api.projects p WHERE p.team_id = t.id)
                        AS project_count
                    FROM api.teams t
                    JOIN api.team_members tm ON tm.team_id = t.id
                    WHERE tm.user_id = %s
                    ORDER BY t.name
                    """,
                    (uid,),
                )
                teams = cur.fetchall() or []

                cur.execute(
                    """
                    SELECT p.id, p.name, p.created_at,
                           t.id AS team_id, t.name AS team_name,
                           tm.role AS team_role,
                           pm.role AS project_role,
                      (SELECT count(*) FROM api.secrets s
                       WHERE s.project_id = p.id AND s.deleted_at IS NULL)
                        AS secret_count
                    FROM api.projects p
                    JOIN api.teams t ON t.id = p.team_id
                    LEFT JOIN api.team_members tm
                      ON tm.team_id = t.id AND tm.user_id = %s
                    LEFT JOIN api.project_members pm
                      ON pm.project_id = p.id AND pm.user_id = %s
                    ORDER BY t.name, p.name
                    """,
                    (uid, uid),
                )
                projects = cur.fetchall() or []

                cur.execute(
                    """
                    SELECT count(*) AS n FROM api.secrets
                    WHERE deleted_at IS NULL
                    """
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

                pins_list = pins.list_pins(cur, uid)
                recent = pins.list_recent(cur, uid)
        except Exception:
            log.exception("profile: load memberships failed")

        # Prefer DB values for session-display consistency
        session["email"] = user.get("email") or session.get("email")
        session["name"] = user.get("name") or session.get("name") or ""
        session["is_global_admin"] = bool(user.get("is_global_admin"))

        return render_template(
            "profile.html",
            user=user,
            teams=teams,
            projects=projects,
            pending_joins=pending,
            pins=pins_list,
            recent=recent,
            active_sessions=active_sessions,
            current_sid=current_sid,
            totp_enabled=totp_on,
            totp_recovery_remaining=recovery_left,
            totp_enforced_for_user=totp_enforced,
            stats={
                "teams": len(teams),
                "projects": len(projects),
                "secrets": secret_count,
                "pins": pin_count,
                "pending_joins": len(pending),
            },
        )
