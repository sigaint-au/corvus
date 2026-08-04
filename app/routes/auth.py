"""Login, register, logout, index."""

from flask import flash, redirect, render_template, request, session, url_for
import psycopg

import authz
import config
import db
import ldap_auth
from settings_svc import registration_enabled, truthy
import settings_svc


log = __import__("logging").getLogger(__name__)


def register(app):
    @app.post("/select-team")
    @authz.login_required
    def select_team():
        tid = (request.form.get("team_id") or "").strip()
        session["team_id"] = tid or None
        nxt = request.form.get("next") or request.referrer or url_for("projects_list")
        # only allow relative redirects
        if not nxt.startswith("/"):
            nxt = url_for("projects_list")
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
        if request.method == "POST":
            email = request.form["email"].strip()
            password = request.form["password"]
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
                        ), 500
            if not user:
                flash("Invalid email or password", "error")
                return render_template(
                    "login.html",
                    ldap_enabled=ldap_on,
                    registration_enabled=settings_svc.registration_enabled(),
                ), 401
            session["user_id"] = str(user["id"])
            session["email"] = user["email"]
            session["name"] = user["name"]
            session["is_global_admin"] = bool(user.get("is_global_admin"))
            session["jwt"] = db.make_jwt(user["id"])
            return redirect(url_for("teams"))
        return render_template(
            "login.html",
            ldap_enabled=ldap_on,
            registration_enabled=settings_svc.registration_enabled(),
        )


    @app.route("/register", methods=["GET", "POST"])
    def register():
        if not settings_svc.registration_enabled():
            flash("Account registration is disabled", "error")
            return redirect(url_for("login"))
        if request.method == "POST":
            email = request.form["email"].strip()
            password = request.form["password"]
            name = request.form.get("name", "").strip()
            if len(password) < 8:
                flash("Password must be at least 8 characters", "error")
                return render_template("register.html"), 400
            try:
                with db.connect(autocommit=True) as conn, conn.cursor() as cur:
                    cur.execute(
                        "SELECT private.register_user(%s, %s, %s) AS id",
                        (email, password, name),
                    )
                    uid = cur.fetchone()["id"]
            except psycopg.errors.UniqueViolation:
                flash("Email already registered", "error")
                return render_template("register.html"), 400
            except Exception as e:
                flash(str(e), "error")
                return render_template("register.html"), 400
            session["user_id"] = str(uid)
            session["email"] = email.lower()
            session["name"] = name
            session["is_global_admin"] = authz.is_global_admin(str(uid))
            session["jwt"] = db.make_jwt(uid)
            return redirect(url_for("teams"))
        return render_template("register.html")


    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))


