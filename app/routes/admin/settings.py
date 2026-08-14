"""Global server settings route."""

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
import authz
import config
import crypto
import db
import hsm
import ldap_auth
import mailer
import passwords
import project_keys
import settings_svc
import totp_svc
import user_sessions
from lib.users import user_email
log = logging.getLogger(__name__)


@authz.global_admin_required
def server_settings():
    """Render or update global server settings (branding, LDAP, OIDC, users).

    Args:
        None (reads query ``tab``; POST form ``action`` and setting fields).

    Returns:
        HTML settings template, or redirect to the relevant settings tab.

    Example:
        GET/POST /settings?tab=general
    """
    if request.method == "POST":
        action = request.form.get("action") or "classification"
        if action == "server_url":
            raw = (request.form.get("server_url") or "").strip().rstrip("/")
            if raw and not (
                raw.startswith("https://") or raw.startswith("http://")
            ):
                flash("Server URL must start with http:// or https://", "error")
            else:
                settings_svc.set_setting("server_url", raw)
                flash("Server URL saved", "ok")
        elif action == "branding":
            brand_name = (request.form.get("brand_name") or "").strip()[:80]
            brand_tagline = (request.form.get("brand_tagline") or "").strip()[:120]
            if not brand_name:
                flash("Brand name is required", "error")
            else:
                settings_svc.set_setting("brand_name", brand_name)
                settings_svc.set_setting("brand_tagline", brand_tagline)
                flash("Branding saved", "ok")
        elif action == "classification":
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
        elif action == "team_creation":
            enabled = "true" if request.form.get("user_team_creation_enabled") else "false"
            settings_svc.set_setting("user_team_creation_enabled", enabled)
            flash(
                "Non–global admins can create teams"
                if enabled == "true"
                else "Only global admins can create teams",
                "ok",
            )
        elif action == "totp_enforce":
            enabled = (
                "true" if request.form.get("totp_enforce_global_admins") else "false"
            )
            settings_svc.set_setting("totp_enforce_global_admins", enabled)
            flash(
                "Global admins must use two-factor authentication"
                if enabled == "true"
                else "2FA is optional for global admins (users may still enable it)",
                "ok",
            )
        elif action == "oidc":
            import oidc_auth

            enabled = "true" if request.form.get("oidc_enabled") else "false"
            issuer = (request.form.get("oidc_issuer") or "").strip().rstrip("/")
            client_id = (request.form.get("oidc_client_id") or "").strip()
            scopes = (request.form.get("oidc_scopes") or "openid email profile").strip()
            label = (request.form.get("oidc_button_label") or "Sign in with SSO").strip()
            if enabled == "true" and (not issuer or not client_id):
                flash("OIDC issuer and client ID are required when SSO is enabled", "error")
            elif enabled == "true" and not (
                issuer.startswith("https://")
                or issuer.startswith("http://localhost")
                or issuer.startswith("http://127.0.0.1")
            ):
                flash("OIDC issuer must be https:// (or http://localhost for dev)", "error")
            else:
                settings_svc.set_setting("oidc_enabled", enabled)
                settings_svc.set_setting("oidc_issuer", issuer)
                settings_svc.set_setting("oidc_client_id", client_id)
                settings_svc.set_setting(
                    "oidc_scopes", scopes or "openid email profile"
                )
                settings_svc.set_setting(
                    "oidc_button_label", label or "Sign in with SSO"
                )
                uclaim = (
                    request.form.get("oidc_username_claim") or "preferred_username"
                ).strip()
                settings_svc.set_setting(
                    "oidc_username_claim", uclaim or "preferred_username"
                )
                gclaim = (request.form.get("oidc_groups_claim") or "groups").strip()
                settings_svc.set_setting(
                    "oidc_groups_claim", gclaim or "groups"
                )
                require_ev = (
                    "true"
                    if request.form.get("oidc_require_email_verified")
                    else "false"
                )
                settings_svc.set_setting("oidc_require_email_verified", require_ev)
                new_secret = request.form.get("oidc_client_secret") or ""
                if new_secret.strip():
                    settings_svc.set_setting(
                        "oidc_client_secret", crypto.encrypt(new_secret.strip())
                    )
                oidc_auth.clear_discovery_cache()
                flash("OIDC / SSO settings saved", "ok")
        elif action == "oidc_role_map_add":
            oidc_group = (request.form.get("oidc_group") or "").strip()
            role = (request.form.get("role") or "global_admin").strip()
            if role != "global_admin":
                flash("Unsupported role for OIDC map", "error")
            elif not oidc_group:
                flash("OIDC group required", "error")
            else:
                with db.connect_admin() as conn, conn.cursor() as cur:
                    try:
                        cur.execute(
                            """
                            INSERT INTO private.oidc_role_maps (oidc_group, role)
                            VALUES (%s, %s)
                            ON CONFLICT (oidc_group) DO UPDATE SET role = EXCLUDED.role
                            """,
                            (oidc_group, role),
                        )
                        flash("OIDC role mapping saved", "ok")
                    except Exception as e:
                        flash(str(e), "error")
        elif action == "oidc_role_map_delete":
            mid = (request.form.get("map_id") or "").strip()
            with db.connect_admin() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM private.oidc_role_maps WHERE id = %s::uuid",
                    (mid,),
                )
            flash("OIDC role mapping removed", "ok")
        elif action == "ldap":
            enabled = "true" if request.form.get("ldap_enabled") else "false"
            ldap_url = (request.form.get("ldap_url") or "").strip()
            start_tls = bool(request.form.get("ldap_start_tls"))
            if enabled == "true" and ldap_url and not ldap_auth.ldap_tls_required_ok(
                ldap_url, start_tls
            ):
                flash(
                    "LDAP over cleartext is not allowed. Use ldaps:// or enable StartTLS.",
                    "error",
                )
            else:
                settings_svc.set_setting("ldap_enabled", enabled)
                settings_svc.set_setting("ldap_url", ldap_url)
                settings_svc.set_setting(
                    "ldap_start_tls",
                    "true" if start_tls else "false",
                )
                settings_svc.set_setting(
                    "ldap_bind_dn", (request.form.get("ldap_bind_dn") or "").strip()
                )
                new_pw = request.form.get("ldap_bind_password") or ""
                if new_pw.strip():
                    settings_svc.set_setting(
                        "ldap_bind_password", crypto.encrypt(new_pw.strip())
                    )
                settings_svc.set_setting(
                    "ldap_user_base",
                    (request.form.get("ldap_user_base") or "").strip(),
                )
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
                settings_svc.set_setting(
                    "ldap_group_base",
                    (request.form.get("ldap_group_base") or "").strip(),
                )
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
        elif action == "smtp":
            enabled = "true" if request.form.get("smtp_enabled") else "false"
            host = (request.form.get("smtp_host") or "").strip()
            port_raw = (request.form.get("smtp_port") or "587").strip() or "587"
            encryption = (request.form.get("smtp_encryption") or "starttls").strip().lower()
            if encryption not in config.SMTP_ENCRYPTION_MODES:
                encryption = "starttls"
            username = (request.form.get("smtp_username") or "").strip()
            from_email = (request.form.get("smtp_from_email") or "").strip()
            from_name = (request.form.get("smtp_from_name") or "").strip() or config.APP_NAME
            login_alerts = "true" if request.form.get("smtp_login_alerts") else "false"
            try:
                port = int(port_raw)
                if port < 1 or port > 65535:
                    raise ValueError("port out of range")
            except ValueError:
                flash("SMTP port must be a number between 1 and 65535", "error")
            else:
                settings_svc.set_setting("smtp_enabled", enabled)
                settings_svc.set_setting("smtp_host", host)
                settings_svc.set_setting("smtp_port", str(port))
                settings_svc.set_setting("smtp_encryption", encryption)
                settings_svc.set_setting("smtp_username", username)
                new_pw = request.form.get("smtp_password") or ""
                if new_pw.strip():
                    settings_svc.set_setting(
                        "smtp_password", crypto.encrypt(new_pw.strip())
                    )
                settings_svc.set_setting("smtp_from_email", from_email)
                settings_svc.set_setting("smtp_from_name", from_name)
                settings_svc.set_setting("smtp_login_alerts", login_alerts)
                flash("Email (SMTP) settings saved", "ok")
        elif action == "smtp_test":
            to_email = (request.form.get("test_email") or "").strip() or (
                session.get("email") or ""
            )
            if not to_email:
                flash("Enter a recipient email for the test message", "error")
            else:
                ok, err = mailer.send_test_email(to_email)
                if ok:
                    flash(f"Test email sent to {to_email}", "ok")
                else:
                    flash(f"Test email failed: {err}", "error")
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
        elif action == "user_disable":
            uid = (request.form.get("user_id") or "").strip()
            if not uid:
                flash("User required", "error")
            elif uid == session.get("user_id"):
                flash("You cannot disable your own account", "error")
            else:
                with db.connect_admin() as conn, conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE private.users
                        SET disabled_at = now()
                        WHERE id = %s::uuid AND disabled_at IS NULL
                        RETURNING email
                        """,
                        (uid,),
                    )
                    row = cur.fetchone()
                if row:
                    n = user_sessions.revoke_all_sessions(uid)
                    flash(
                        f"Disabled {row['email']}"
                        + (f" and signed out {n} session(s)" if n else ""),
                        "ok",
                    )
                else:
                    flash("User not found or already disabled", "error")
        elif action == "user_enable":
            uid = (request.form.get("user_id") or "").strip()
            if not uid:
                flash("User required", "error")
            else:
                with db.connect_admin() as conn, conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE private.users
                        SET disabled_at = NULL
                        WHERE id = %s::uuid AND disabled_at IS NOT NULL
                        RETURNING email
                        """,
                        (uid,),
                    )
                    row = cur.fetchone()
                if row:
                    flash(f"Re-enabled {row['email']}", "ok")
                else:
                    flash("User not found or already active", "error")
        elif action == "user_reset_password":
            uid = (request.form.get("user_id") or "").strip()
            token, err = passwords.create_reset_token_for_user(uid)
            if not token:
                flash(err or "Could not create password reset", "error")
            else:
                link = url_for("reset_password", token=token, _external=True)
                email = ""
                with db.connect_admin() as conn, conn.cursor() as cur:
                    email = user_email(cur, uid)
                mailed = False
                if email and mailer.smtp_configured():
                    ok, merr = mailer.send_password_reset(email, link)
                    mailed = ok
                    if not ok:
                        log.warning("admin password reset email failed: %s", merr)
                user_sessions.revoke_all_sessions(uid)
                if mailed:
                    flash(f"Password reset email sent to {email}", "ok")
                else:
                    # Surface link once for admin to share (SMTP optional)
                    flash(
                        f"Password reset link for {email or 'user'} (share securely; "
                        f"expires in 1 hour): {link}",
                        "ok",
                    )
        elif action == "user_reset_2fa":
            uid = (request.form.get("user_id") or "").strip()
            if not uid:
                flash("User required", "error")
            elif not totp_svc.is_enabled(uid):
                flash("User does not have two-factor authentication enabled", "error")
            else:
                email = ""
                with db.connect_admin() as conn, conn.cursor() as cur:
                    email = user_email(cur, uid) or uid
                totp_svc.disable(uid)
                user_sessions.revoke_all_sessions(uid)
                flash(
                    f"Two-factor authentication reset for {email}. "
                    "They must set up 2FA again at next sign-in if required.",
                    "ok",
                )
        elif action == "hsm_test":

            ok, msg = hsm.test_roundtrip()
            flash(f"HSM check: {msg}", "ok" if ok else "error")
        elif action == "hsm_kek_rotate":

            if not hsm.available():
                flash("External HSM is not configured", "error")
            else:
                try:
                    n = project_keys.rotate_hsm_kek()
                    flash(f"HSM KEK rotated — re-wrapped {n} project key(s)", "ok")
                except Exception as e:
                    flash(f"HSM KEK rotation failed: {e}", "error")
        elif action == "hsm_migrate_all":

            if not hsm.available():
                flash("External HSM is not configured", "error")
            else:
                try:
                    n = project_keys.migrate_all_local_to_hsm()
                    flash(f"Migrated {n} local project key(s) to HSM", "ok")
                except Exception as e:
                    flash(f"Bulk migration failed: {e}", "error")
        # Stay on the relevant tab after save
        tab_for = {
            "server_url": "general",
            "registration": "general",
            "team_creation": "general",
            "totp_enforce": "general",
            "branding": "branding",
            "classification": "banner",
            "promote": "admins",
            "demote": "admins",
            "ldap": "ldap",
            "ldap_role_map_add": "ldap",
            "ldap_role_map_delete": "ldap",
            "smtp": "email",
            "smtp_test": "email",
            "oidc": "oidc",
            "oidc_role_map_add": "oidc",
            "oidc_role_map_delete": "oidc",
            "user_disable": "users",
            "user_enable": "users",
            "user_reset_password": "users",
            "user_reset_2fa": "users",
            "hsm_test": "encryption",
            "hsm_kek_rotate": "encryption",
            "hsm_migrate_all": "encryption",
        }
        tab = tab_for.get(action, "general")
        return redirect(url_for("server_settings", tab=tab))

    tab = (request.args.get("tab") or "general").strip().lower()
    if tab not in (
        "general",
        "branding",
        "banner",
        "admins",
        "users",
        "ldap",
        "oidc",
        "email",
        "encryption",
    ):
        tab = "general"
    settings = settings_svc.get_settings()
    # never show raw passwords in the form
    settings = dict(settings)
    settings["ldap_bind_password_set"] = bool((settings.get("ldap_bind_password") or "").strip())
    settings["ldap_bind_password"] = ""
    settings["smtp_password_set"] = bool((settings.get("smtp_password") or "").strip())
    settings["smtp_password"] = ""
    settings["oidc_client_secret_set"] = bool(
        (settings.get("oidc_client_secret") or "").strip()
    )
    settings["oidc_client_secret"] = ""
    users, all_users, ldap_role_maps, oidc_role_maps = [], [], [], []
    with db.connect_admin() as conn, conn.cursor() as cur:
        if tab == "admins":
            cur.execute(
                """
                SELECT id, email, name, is_global_admin, auth_source, created_at
                FROM private.users
                ORDER BY is_global_admin DESC, email
                """
            )
            users = cur.fetchall()
        if tab == "users":
            cur.execute(
                """
                SELECT id, email, name, is_global_admin, auth_source,
                       totp_enabled_at, disabled_at, created_at
                FROM private.users
                ORDER BY
                  CASE WHEN disabled_at IS NOT NULL THEN 1 ELSE 0 END,
                  is_global_admin DESC,
                  email
                """
            )
            all_users = cur.fetchall() or []
        if tab == "ldap":
            cur.execute(
                "SELECT id, ldap_group, role, created_at FROM private.ldap_role_maps ORDER BY ldap_group"
            )
            ldap_role_maps = cur.fetchall()
        if tab == "oidc":
            cur.execute(
                "SELECT id, oidc_group, role, created_at FROM private.oidc_role_maps ORDER BY oidc_group"
            )
            oidc_role_maps = cur.fetchall() or []
    server_url = settings_svc.public_base_url()
    oidc_redirect_uri = (
        (server_url + "/login/oidc/callback") if server_url else ""
    )
    encryption = None
    if tab == "encryption":

        encryption = {
            "hsm": hsm.status(),
            "master_key_is_default": config.master_key_is_default(),
            "summary": project_keys.encryption_summary(),
        }
    return render_template(
        "settings.html",
        settings=settings,
        users=users,
        all_users=all_users,
        ldap_role_maps=ldap_role_maps,
        oidc_role_maps=oidc_role_maps,
        classification=settings_svc.classification(),
        active_tab=tab,
        smtp_encryption_modes=config.SMTP_ENCRYPTION_MODES,
        server_url=server_url,
        oidc_redirect_uri=oidc_redirect_uri,
        encryption=encryption,
    )
