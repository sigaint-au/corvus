"""Global admin server settings."""

from flask import flash, redirect, render_template, request, session, url_for

import authz
import config
import crypto
import db
import settings_svc


log = __import__("logging").getLogger(__name__)


def register(app):
    # ── Server settings (global admin only) ────────────────────────────


    @app.route("/settings", methods=["GET", "POST"])
    @authz.global_admin_required
    def server_settings():
        if request.method == "POST":
            action = request.form.get("action") or "classification"
            if action == "classification":
                text = (request.form.get("classification_text") or "").strip()[:120]
                color = (request.form.get("classification_color") or "").strip()
                fg = (request.form.get("classification_fg") or "").strip()
                enabled = "true" if request.form.get("classification_enabled") else "false"
                if not config.HEX.match(color):
                    flash("Banner colour must be a hex value like #677381", "error")
                elif not config.HEX.match(fg):
                    flash("Text colour must be a hex value like #ffffff", "error")
                else:
                    settings_svc.set_setting("classification_enabled", enabled)
                    settings_svc.set_setting("classification_text", text)
                    settings_svc.set_setting("classification_color", color)
                    settings_svc.set_setting("classification_fg", fg)
                    flash("Classification banner saved", "ok")
            elif action == "registration":
                enabled = "true" if request.form.get("registration_enabled") else "false"
                settings_svc.set_setting("registration_enabled", enabled)
                flash(
                    "Account registration enabled" if enabled == "true" else "Account registration disabled",
                    "ok",
                )
            elif action == "ldap":
                enabled = "true" if request.form.get("ldap_enabled") else "false"
                settings_svc.set_setting("ldap_enabled", enabled)
                settings_svc.set_setting("ldap_url", (request.form.get("ldap_url") or "").strip())
                settings_svc.set_setting(
                    "ldap_start_tls",
                    "true" if request.form.get("ldap_start_tls") else "false",
                )
                settings_svc.set_setting("ldap_bind_dn", (request.form.get("ldap_bind_dn") or "").strip())
                new_pw = request.form.get("ldap_bind_password") or ""
                if new_pw.strip():
                    settings_svc.set_setting("ldap_bind_password", crypto.encrypt(new_pw.strip()))
                settings_svc.set_setting("ldap_user_base", (request.form.get("ldap_user_base") or "").strip())
                filt = (request.form.get("ldap_user_filter") or "").strip()
                settings_svc.set_setting(
                    "ldap_user_filter",
                    filt or config.DEFAULT_SETTINGS["ldap_user_filter"],
                )
                settings_svc.set_setting(
                    "ldap_email_attr",
                    (request.form.get("ldap_email_attr") or "mail").strip() or "mail",
                )
                settings_svc.set_setting(
                    "ldap_name_attr",
                    (request.form.get("ldap_name_attr") or "displayName").strip()
                    or "displayName",
                )
                settings_svc.set_setting("ldap_group_base", (request.form.get("ldap_group_base") or "").strip())
                gfilt = (request.form.get("ldap_group_filter") or "").strip()
                settings_svc.set_setting(
                    "ldap_group_filter",
                    gfilt or config.DEFAULT_SETTINGS["ldap_group_filter"],
                )
                settings_svc.set_setting(
                    "ldap_use_memberof",
                    "true" if request.form.get("ldap_use_memberof") else "false",
                )
                flash("LDAP settings saved", "ok")
            elif action == "ldap_role_map_add":
                ldap_group = (request.form.get("ldap_group") or "").strip()
                role = (request.form.get("role") or "global_admin").strip()
                if role != "global_admin":
                    flash("Unsupported role for LDAP map", "error")
                elif not ldap_group:
                    flash("LDAP group required", "error")
                else:
                    with db.connect_admin() as conn, conn.cursor() as cur:
                        try:
                            cur.execute(
                                """
                                INSERT INTO private.ldap_role_maps (ldap_group, role)
                                VALUES (%s, %s)
                                ON CONFLICT (ldap_group) DO UPDATE SET role = EXCLUDED.role
                                """,
                                (ldap_group, role),
                            )
                            flash("LDAP role mapping saved", "ok")
                        except Exception as e:
                            flash(str(e), "error")
            elif action == "ldap_role_map_delete":
                mid = (request.form.get("map_id") or "").strip()
                with db.connect_admin() as conn, conn.cursor() as cur:
                    cur.execute("DELETE FROM private.ldap_role_maps WHERE id = %s::uuid", (mid,))
                flash("LDAP role mapping removed", "ok")
            elif action == "promote":
                email = (request.form.get("email") or "").strip().lower()
                if not email:
                    flash("Email required", "error")
                else:
                    with db.connect_admin() as conn, conn.cursor() as cur:
                        cur.execute(
                            "UPDATE private.users SET is_global_admin = true WHERE email = %s RETURNING id",
                            (email,),
                        )
                        row = cur.fetchone()
                    if row:
                        flash(f"Promoted {email} to global admin", "ok")
                    else:
                        flash("User not found — they must register or sign in via LDAP first", "error")
            elif action == "demote":
                uid = (request.form.get("user_id") or "").strip()
                if uid == session.get("user_id"):
                    flash("You cannot remove your own global admin role", "error")
                else:
                    with db.connect_admin() as conn, conn.cursor() as cur:
                        cur.execute(
                            "UPDATE private.users SET is_global_admin = false WHERE id = %s::uuid",
                            (uid,),
                        )
                    flash("Global admin removed", "ok")
            return redirect(url_for("server_settings"))

        settings = settings_svc.get_settings()
        # never show raw bind password in the form
        settings = dict(settings)
        settings["ldap_bind_password_set"] = bool((settings.get("ldap_bind_password") or "").strip())
        settings["ldap_bind_password"] = ""
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, name, is_global_admin, auth_source, created_at
                FROM private.users
                ORDER BY is_global_admin DESC, email
                """
            )
            users = cur.fetchall()
            cur.execute(
                "SELECT id, ldap_group, role, created_at FROM private.ldap_role_maps ORDER BY ldap_group"
            )
            ldap_role_maps = cur.fetchall()
        return render_template(
            "settings.html",
            settings=settings,
            users=users,
            ldap_role_maps=ldap_role_maps,
            classification=settings_svc.classification(),
        )

