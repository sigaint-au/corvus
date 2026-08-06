"""Login, register, logout, index."""

from flask import flash, redirect, render_template, request, session, url_for
import psycopg

import authz
from config import bootstrap_admin_email
import db
import ldap_auth
import lockout
import settings_svc


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


def _establish_session(user_id, email, name, is_global_admin: bool):
    """Clear session then set auth values (session regeneration)."""
    session.clear()
    session["user_id"] = str(user_id)
    session["email"] = email
    session["name"] = name or ""
    session["is_global_admin"] = bool(is_global_admin)
    session["jwt"] = db.make_jwt(user_id)


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
            _maybe_promote_bootstrap_admin(user["email"], user["id"])
            is_admin = authz.is_global_admin(str(user["id"]))
            pending_invite = session.get("invite_token")
            _establish_session(user["id"], user["email"], user["name"], is_admin)
            if pending_invite:
                return redirect(url_for("redeem_invite", token=pending_invite))
            return redirect(url_for("teams"))
        return render_template(
            "login.html",
            ldap_enabled=ldap_on,
            registration_enabled=settings_svc.registration_enabled(),
            setup_notice=notice,
        )


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
            pending_invite = session.get("invite_token")
            _establish_session(uid, email.lower(), name, is_admin)
            if pending_invite:
                return redirect(url_for("redeem_invite", token=pending_invite))
            return redirect(url_for("teams"))
        return render_template("register.html", setup_notice=notice)


    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))
