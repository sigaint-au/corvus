"""Global server settings route."""

from __future__ import annotations

import logging
import time

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import audit
import crypto
from auth import authz, passwords, totp_svc, user_sessions
from core import cache, config, db, settings_svc
from crypto import hsm, project_keys
from integrations import ldap_auth, mailer
from lib.users import user_email

log = logging.getLogger(__name__)

_PROCESS_START = time.time()


def _format_uptime(start: float) -> str:
    """Return human-readable uptime since the given process-start timestamp."""
    delta = max(0, int(time.time() - start))
    days, rem = divmod(delta, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or parts:
        parts.append(f"{hours}h")
    if minutes or parts:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def _db_probe() -> dict:
    """Probe the Postgres admin connection and report version/database."""
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute("SELECT version() AS v, current_database() AS db, current_user AS usr")
            row = cur.fetchone() or {}
        detail = f"{row.get('v', 'n/a')} — database {row.get('db', '?')} as {row.get('usr', '?')}"
        return {"ok": True, "detail": detail}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


def _redis_probe() -> dict:
    """Probe Redis connectivity (returns ``ok=True`` with notice when disabled)."""
    client = cache.redis_client()
    if client is None:
        return {"ok": False, "detail": "not configured (REDIS_URL unset)"}
    try:
        info = client.info("server")
        version = (info or {}).get("redis_version", "unknown")
        return {"ok": True, "detail": f"Redis {version} reachable"}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


def _hsm_probe() -> tuple[list, dict]:
    """Probe every configured HSM slot; returns ``(slots, summary)``."""
    slots: list = []
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM private.hsm_slots ORDER BY is_default DESC, name")
            slots = cur.fetchall() or []
    except Exception as e:
        return [], {"ok": False, "detail": f"slot list unavailable: {e}", "count": 0}
    results = []
    for slot in slots:
        status = hsm.status_for_slot(slot["pkcs11_url"])
        results.append(
            {
                "id": slot["id"],
                "name": slot["name"],
                "is_default": slot.get("is_default", False),
                "ok": status.get("available") and not status.get("error"),
                "detail": status.get("error")
                or (
                    "connected, KEK present"
                    if status.get("kek_exists")
                    else "connected, KEK not present (created on first use)"
                ),
            }
        )
    ok = bool(slots) and all(r["ok"] for r in results)
    detail = (
        f"{len(slots)} slot(s), all reachable"
        if ok and slots
        else f"{len(slots)} slot(s), some unreachable"
        if slots
        else "no slots configured"
    )
    return results, {"ok": ok, "detail": detail, "count": len(slots)}


def _health_probe() -> dict:
    """Return live connectivity status for the server-health panel.

    Returns:
        Dict keyed by component (``postgres``, ``redis``, ``hsm``) with
        ``ok``/``detail``, plus ``uptime`` text.

    Example:
        >>> probe = _health_probe()
        >>> probe["postgres"]["ok"] in (True, False)
        True
    """
    slots, hsm = _hsm_probe()
    return {
        "uptime": _format_uptime(_PROCESS_START),
        "postgres": _db_probe(),
        "redis": _redis_probe(),
        "hsm": {**hsm, "slots": slots},
    }


# Form keys re-applied to the rendered form after a connection test, so the
# admin does not lose typed-but-unsaved values when probing LDAP/OIDC.
_PROBE_BOOL_KEYS = frozenset(
    {
        "ldap_enabled",
        "ldap_start_tls",
        "ldap_use_memberof",
        "oidc_enabled",
        "oidc_require_email_verified",
    }
)
_PROBE_FORM_KEYS = (
    "ldap_enabled",
    "ldap_url",
    "ldap_start_tls",
    "ldap_bind_dn",
    "ldap_probe_login",
    "ldap_user_base",
    "ldap_user_filter",
    "ldap_email_attr",
    "ldap_name_attr",
    "ldap_group_base",
    "ldap_group_filter",
    "ldap_use_memberof",
    "oidc_enabled",
    "oidc_issuer",
    "oidc_client_id",
    "oidc_scopes",
    "oidc_button_label",
    "oidc_username_claim",
    "oidc_groups_claim",
    "oidc_require_email_verified",
)


def _overlay_probe_form(settings: dict, form) -> None:
    """Copy submitted (non-secret) settings values back over the stored ones.

    Args:
        settings: Render settings dict to mutate in place.
        form: The request form that carried the connection-test values.

    Returns:
        None.

    Example:
        >>> # _overlay_probe_form(settings, request.form)
    """
    for key in _PROBE_FORM_KEYS:
        if key in _PROBE_BOOL_KEYS:
            settings[key] = "true" if form.get(key) else "false"
        else:
            val = (form.get(key) or "").strip()
            if val:
                settings[key] = val


def _ldap_test_probe(form) -> dict:
    """Attempt an LDAP service bind and user search with submitted values.

    Uses the same ``Server``/``Tls``/bind construction as the login path in
    ``integrations.ldap_auth`` with a shorter timeout. Never raises.

    Args:
        form: Submitted LDAP settings form (typed values, not saved ones).

    Returns:
        Status dict ``{"ok": bool, "warn": bool, "detail": str}`` for
        inline display in the LDAP card.

    Example:
        >>> # result = _ldap_test_probe(request.form)
        >>> # result["ok"] in (True, False)
        True
    """
    url = (form.get("ldap_url") or "").strip()
    user_base = (form.get("ldap_user_base") or "").strip()
    start_tls = bool(form.get("ldap_start_tls"))
    if not url or not user_base:
        return {
            "ok": False,
            "warn": False,
            "detail": "Server URL and user search base are required",
        }
    if not ldap_auth.ldap_tls_required_ok(url, start_tls):
        return {
            "ok": False,
            "warn": False,
            "detail": "Refused: use ldaps:// or enable StartTLS (cleartext is not allowed)",
        }
    want_tls = start_tls and not url.lower().startswith("ldaps://")
    bind_dn = (form.get("ldap_bind_dn") or "").strip()
    new_pw = (form.get("ldap_bind_password") or "").strip()
    if new_pw:
        bind_pw = new_pw
    else:
        stored = settings_svc.get_settings().get("ldap_bind_password") or ""
        bind_pw = ldap_auth.ldap_password_plain({"ldap_bind_password": stored})
    email_attr = (form.get("ldap_email_attr") or "mail").strip() or "mail"
    name_attr = (form.get("ldap_name_attr") or "displayName").strip() or "displayName"
    filt = (form.get("ldap_user_filter") or config.DEFAULT_SETTINGS["ldap_user_filter"]).strip()
    probe_login = (form.get("ldap_probe_login") or "").strip()
    conn = None
    try:
        import ssl

        from ldap3 import ALL, SUBTREE, Server, Tls

        try:
            tls = Tls(validate=ssl.CERT_REQUIRED)
        except TypeError:  # ldap3 < 2.9.1
            tls = None
        # ponytail: fixed 5s timeouts; per-deployment tuning only if probes hang
        server = Server(url, get_info=ALL, connect_timeout=5, tls=tls)
        if bind_dn:
            conn = ldap_auth._ldap_bind(
                server, user=bind_dn, password=bind_pw, start_tls=want_tls, receive_timeout=5
            )
        else:
            conn = ldap_auth._ldap_bind(server, start_tls=want_tls, receive_timeout=5)
        found = conn.search(
            user_base,
            filt.replace("{login}", ldap_auth.ldap_escape(probe_login)),
            search_scope=SUBTREE,
            attributes=[email_attr, name_attr, "memberOf", "cn", "uid"],
            size_limit=5,
        )
        if not found:
            return {
                "ok": True,
                "warn": True,
                "detail": f"Bind OK, but the user search failed: {conn.result}",
            }
        n = len(conn.entries or [])
        if not n:
            hint = "" if probe_login else " (add a probe login to test the filter)"
            return {
                "ok": True,
                "warn": True,
                "detail": f"Bind OK, but the user filter matched 0 entries{hint}",
            }
        return {
            "ok": True,
            "warn": False,
            "detail": f"Bind OK — user filter matched {n} "
            f"entr{'y' if n == 1 else 'ies'} under {user_base}",
        }
    except Exception as e:
        return {"ok": False, "warn": False, "detail": (str(e) or "Connection failed")[:300]}
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:
                pass


def _oidc_test_probe(issuer: str) -> dict:
    """Fetch the OIDC discovery document and validate required endpoints.

    Uses the same HTTP helper as the OIDC login path
    (``integrations.oidc_auth._http_json``). Never raises.

    Args:
        issuer: Issuer URL from the submitted form (falls back to nothing).

    Returns:
        Status dict ``{"ok": bool, "warn": bool, "detail": str}`` for
        inline display in the OIDC card.

    Example:
        >>> # result = _oidc_test_probe(request.form.get("oidc_issuer"))
        >>> # result["ok"] in (True, False)
        True
    """
    from integrations import oidc_auth

    iss = (issuer or "").strip().rstrip("/")
    if not iss:
        return {"ok": False, "warn": False, "detail": "Issuer URL is required"}
    try:
        doc = oidc_auth._http_json("GET", iss + "/.well-known/openid-configuration")
    except Exception as e:
        return {"ok": False, "warn": False, "detail": (str(e) or "Request failed")[:300]}
    missing = [
        key
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri")
        if not doc.get(key)
    ]
    if missing:
        return {
            "ok": False,
            "warn": False,
            "detail": "Discovery document is missing: " + ", ".join(missing),
        }
    return {
        "ok": True,
        "warn": False,
        "detail": "Discovery OK — authorization, token, and JWKS endpoints present",
    }


SETTINGS_CATEGORIES = [
    (
        "system",
        "System",
        [
            ("general", "General"),
            ("branding", "Branding"),
            ("banner", "Classification"),
            ("email", "Email"),
            ("encryption", "Encryption"),
            ("health", "Health"),
        ],
    ),
    ("access", "Access", [("admins", "Admins"), ("users", "Users")]),
    ("authentication", "Authentication", [("ldap", "LDAP"), ("oidc", "OIDC / SSO")]),
    ("integration", "Integrations", [("webhooks", "Webhooks")]),
]
ALL_TABS = tuple(t for _, _, subs in SETTINGS_CATEGORIES for t, _ in subs)


def _admin_webhook_action(action: str) -> None:
    """Create/delete/toggle a cluster-scope webhook from the settings form."""
    import secrets as _secrets

    from integrations import webhooks as wh

    with db.connect_admin() as conn, conn.cursor() as cur:
        if action == "webhook_create":
            url, events, ssl_verify, err = wh.validate_webhook_input(request.form)
            if err:
                flash(err, "error")
                return
            token = (request.form.get("secret_token") or "").strip()
            generated = False
            if not token:
                # ponytail: shown-once flash; rotate by re-creating
                token = _secrets.token_hex(32)
                generated = True
            name = (request.form.get("name") or "").strip()[:80] or "webhook"
            cur.execute(
                """
                INSERT INTO api.webhooks (name, url, secret_token, events, scope_kind, scope_id, ssl_verify)
                VALUES (%s, %s, %s, %s, 'cluster', NULL, %s)
                """,
                (name, url, token, events, ssl_verify),
            )
            flash(
                ("Signing secret (copy now, shown once): " + token) if generated
                else "Webhook created",
                "ok",
            )
        else:
            webhook_id = (request.form.get("webhook_id") or "").strip()
            if not webhook_id:
                flash("Missing webhook", "error")
                return
            if action == "webhook_toggle":
                cur.execute(
                    "UPDATE api.webhooks SET active = NOT active WHERE id = %s::uuid AND scope_kind = 'cluster'",
                    (webhook_id,),
                )
                flash("Webhook updated", "ok")
            else:
                cur.execute(
                    "DELETE FROM api.webhooks WHERE id = %s::uuid AND scope_kind = 'cluster'",
                    (webhook_id,),
                )
                flash("Webhook deleted", "ok")


def _cluster_webhooks() -> list[dict]:
    """Cluster-scope webhooks + recent deliveries for the admin tab."""
    from integrations import webhooks as wh

    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, url, events, active, ssl_verify, created_at
                FROM api.webhooks WHERE scope_kind = 'cluster'
                ORDER BY created_at DESC
                """
            )
            rows = list(cur.fetchall() or [])
            for r in rows:
                r["deliveries"] = wh.recent_deliveries(cur, str(r["id"]))
            return rows
    except Exception:
        logging.getLogger(__name__).exception("webhook listing failed")
        return []


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
    ldap_test = None
    oidc_test = None
    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        if action in ("webhook_create", "webhook_delete", "webhook_toggle"):
            _admin_webhook_action(action)
            return redirect(url_for("server_settings", tab="webhooks"))
        elif action == "ldap_test":
            ldap_test = _ldap_test_probe(request.form)
        elif action == "oidc_test":
            oidc_test = _oidc_test_probe(request.form.get("oidc_issuer"))
        elif action == "server_url":
            raw = (request.form.get("server_url") or "").strip().rstrip("/")
            if raw and not (raw.startswith("https://") or raw.startswith("http://")):
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
        elif action == "login_banner":
            enabled = "true" if request.form.get("login_banner_enabled") else "false"
            text = (request.form.get("login_banner_text") or "").strip()[:1000]
            link_text = (request.form.get("login_banner_link_text") or "").strip()[:80]
            link_url = (request.form.get("login_banner_link_url") or "").strip()[:500]
            if enabled == "true" and not text:
                flash("Banner text is required when the login banner is enabled", "error")
            elif link_url and not link_url.startswith(("/", "http://", "https://")):
                flash("Policy link must be an http(s) URL or a relative path", "error")
            else:
                settings_svc.set_setting("login_banner_enabled", enabled)
                settings_svc.set_setting("login_banner_text", text)
                settings_svc.set_setting("login_banner_link_text", link_text)
                settings_svc.set_setting("login_banner_link_url", link_url)
                flash("Login banner saved", "ok")
        elif action == "ux":

            def _int_field(name, default, minimum=0):
                raw = (request.form.get(name) or "").strip()
                try:
                    val = int(raw or default)
                except ValueError:
                    return None
                return max(minimum, val)

            clipboard = _int_field("clipboard_clear_seconds", 30)
            auto_hide = _int_field("reveal_auto_hide_seconds", 30)
            grant = _int_field("reveal_access_grant_minutes", 15, minimum=1)
            if clipboard is None or auto_hide is None or grant is None:
                flash("Clipboard/hide/grant values must be whole numbers", "error")
            else:
                settings_svc.set_setting("clipboard_clear_seconds", str(clipboard))
                settings_svc.set_setting("reveal_auto_hide_seconds", str(auto_hide))
                settings_svc.set_setting("reveal_access_grant_minutes", str(grant))
                flash("Reveal & clipboard settings saved", "ok")
        elif action == "registration":
            enabled = "true" if request.form.get("registration_enabled") else "false"
            settings_svc.set_setting("registration_enabled", enabled)
            flash(
                "Account registration enabled"
                if enabled == "true"
                else "Account registration disabled",
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
            enabled = "true" if request.form.get("totp_enforce_global_admins") else "false"
            settings_svc.set_setting("totp_enforce_global_admins", enabled)
            flash(
                "Global admins must use two-factor authentication"
                if enabled == "true"
                else "2FA is optional for global admins (users may still enable it)",
                "ok",
            )
        elif action == "token_policy":
            pat_max = (request.form.get("max_pat_lifetime_days") or "").strip()
            machine_max = (request.form.get("max_machine_token_lifetime_days") or "").strip()
            try:
                if pat_max and not 1 <= int(pat_max) <= config.MAX_EXPIRY_DAYS:
                    raise ValueError
                if machine_max and not 1 <= int(machine_max) <= config.MAX_EXPIRY_DAYS:
                    raise ValueError
            except ValueError:
                flash(
                    f"Max token lifetime must be between 1 and {config.MAX_EXPIRY_DAYS} days",
                    "error",
                )
            else:
                settings_svc.set_setting(
                    "require_pat_expiry",
                    "true" if request.form.get("require_pat_expiry") else "false",
                )
                settings_svc.set_setting("max_pat_lifetime_days", pat_max)
                settings_svc.set_setting(
                    "require_machine_token_expiry",
                    "true" if request.form.get("require_machine_token_expiry") else "false",
                )
                settings_svc.set_setting("max_machine_token_lifetime_days", machine_max)
                flash("Token expiry policy saved", "ok")
        elif action == "oidc":
            from integrations import oidc_auth

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
                settings_svc.set_setting("oidc_scopes", scopes or "openid email profile")
                settings_svc.set_setting("oidc_button_label", label or "Sign in with SSO")
                uclaim = (request.form.get("oidc_username_claim") or "preferred_username").strip()
                settings_svc.set_setting("oidc_username_claim", uclaim or "preferred_username")
                gclaim = (request.form.get("oidc_groups_claim") or "groups").strip()
                settings_svc.set_setting("oidc_groups_claim", gclaim or "groups")
                require_ev = "true" if request.form.get("oidc_require_email_verified") else "false"
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
                    except Exception:
                        flash("Could not save the setting. Try again.", "error")
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
            if (
                enabled == "true"
                and ldap_url
                and not ldap_auth.ldap_tls_required_ok(ldap_url, start_tls)
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
                    settings_svc.set_setting("ldap_bind_password", crypto.encrypt(new_pw.strip()))
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
                    (request.form.get("ldap_name_attr") or "displayName").strip() or "displayName",
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
            login_alerts_force = (
                "true" if request.form.get("smtp_login_alerts_force") else "false"
            )
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
                    settings_svc.set_setting("smtp_password", crypto.encrypt(new_pw.strip()))
                settings_svc.set_setting("smtp_from_email", from_email)
                settings_svc.set_setting("smtp_from_name", from_name)
                settings_svc.set_setting("smtp_login_alerts", login_alerts)
                settings_svc.set_setting("smtp_login_alerts_force", login_alerts_force)
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
                    except Exception:
                        flash("Could not save the setting. Try again.", "error")
        elif action == "ldap_role_map_delete":
            mid = (request.form.get("map_id") or "").strip()
            with db.connect_admin() as conn, conn.cursor() as cur:
                cur.execute("DELETE FROM private.ldap_role_maps WHERE id = %s::uuid", (mid,))
            flash("LDAP role mapping removed", "ok")
        elif action == "promote":
            email = (request.form.get("email") or "").strip().lower()
            if not email:
                flash("Enter an email address.", "error")
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
                    flash("No user with that email. They need to register or sign in via LDAP first.", "error")
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
        elif action == "hsm_migrate_all":
            target_slot = (request.form.get("target_slot") or "").strip() or None
            if not target_slot:
                flash("Choose a target HSM slot", "error")
            else:
                try:
                    n = project_keys.migrate_all_local_to_hsm(target_slot)
                    with db.connect_admin() as conn, conn.cursor() as cur:
                        audit.log_org(
                            cur,
                            action="hsm_bulk_migrated",
                            detail=f"migrated={n}",
                        )
                        conn.commit()
                    flash(f"Migrated {n} local project key(s) to HSM", "ok")
                except Exception:
                    flash("Could not migrate all project keys. Try again.", "error")
        elif action == "hsm_slot_delete":
            slot_id = (request.form.get("slot_id") or "").strip()
            if not slot_id:
                flash("Slot required", "error")
            else:
                try:
                    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                        cur.execute("SELECT api.hsm_slot_delete(%s::uuid)", (slot_id,))
                    crypto.clear_slot_url_cache()
                    with db.connect_admin() as conn, conn.cursor() as cur:
                        audit.log_org(cur, action="hsm_slot_deleted", detail=f"slot_id={slot_id}")
                        conn.commit()
                    flash("HSM slot deleted", "ok")
                except Exception:
                    flash("Could not delete the HSM slot. Try again.", "error")
        elif action == "hsm_slot_test":
            slot_id = (request.form.get("slot_id") or "").strip()
            slot_url = None
            with db.connect_admin() as conn, conn.cursor() as cur:
                if slot_id:
                    cur.execute(
                        "SELECT pkcs11_url FROM private.hsm_slots WHERE id = %s::uuid",
                        (slot_id,),
                    )
                    slot_url = (cur.fetchone() or {}).get("pkcs11_url")
            if not slot_url:
                flash("HSM slot not found", "error")
            else:
                ok, msg = hsm.test_connection_for_slot(slot_url)
                flash(f"HSM slot check: {msg}", "ok" if ok else "error")
        elif action == "hsm_slot_link":
            slot_id = (request.form.get("slot_id") or "").strip()
            try:
                n = project_keys.link_legacy_to_slot(slot_id)
                with db.connect_admin() as conn, conn.cursor() as cur:
                    audit.log_org(
                        cur, action="hsm_slot_linked", detail=f"slot_id={slot_id} linked={n}"
                    )
                    conn.commit()
                if n == 0:
                    flash("No legacy projects matched this slot's KEK label", "ok")
                else:
                    flash(f"Linked {n} legacy HSM project(s) to this slot", "ok")
            except Exception:
                flash("Could not link the HSM slot. Try again.", "error")
        elif action == "hsm_slot_rotate":
            slot_id = (request.form.get("slot_id") or "").strip()
            if not slot_id:
                flash("Slot required", "error")
            else:
                try:
                    n = project_keys.rotate_hsm_kek(slot_id)
                    with db.connect_admin() as conn, conn.cursor() as cur:
                        audit.log_org(
                            cur,
                            action="hsm_kek_rotated",
                            detail=f"slot={slot_id} re-wrapped={n}",
                        )
                        conn.commit()
                    flash(f"HSM KEK rotated — re-wrapped {n} project key(s)", "ok")
                except Exception:
                    flash("Could not rotate the HSM key. Try again.", "error")
        elif action in ("health_test_postgres", "health_test_redis", "health_test_hsm"):
            probe = _health_probe()
            if action == "health_test_postgres":
                ok, detail = probe["postgres"]["ok"], probe["postgres"]["detail"]
                label = "Postgres"
            elif action == "health_test_redis":
                ok, detail = probe["redis"]["ok"], probe["redis"]["detail"]
                label = "Redis"
            else:
                ok, detail = probe["hsm"]["ok"], probe["hsm"]["detail"]
                label = "HSM"
            flash(f"{label}: {detail}", "ok" if ok else "error")
        # Stay on the relevant tab after save; test actions fall through to a
        # re-render so the result can be shown inline next to the form.
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
            "hsm_migrate_all": "encryption",
            "hsm_slot_delete": "encryption",
            "hsm_slot_test": "encryption",
            "hsm_slot_link": "encryption",
            "hsm_slot_rotate": "encryption",
            "health_test_postgres": "health",
            "health_test_redis": "health",
            "health_test_hsm": "health",
            "token_policy": "general",
        }
        if ldap_test is None and oidc_test is None:
            tab = tab_for.get(action)
            if not tab:
                tab = (request.args.get("tab") or "general").strip().lower()
                if tab not in ALL_TABS:
                    tab = "general"
            return redirect(url_for("server_settings", tab=tab))

    tab = (request.args.get("tab") or "general").strip().lower()
    if tab not in ALL_TABS:
        tab = "general"
    settings = settings_svc.get_settings()
    # never show raw passwords in the form
    settings = dict(settings)
    settings["ldap_bind_password_set"] = bool((settings.get("ldap_bind_password") or "").strip())
    settings["ldap_bind_password"] = ""
    settings["smtp_password_set"] = bool((settings.get("smtp_password") or "").strip())
    settings["smtp_password"] = ""
    settings["oidc_client_secret_set"] = bool((settings.get("oidc_client_secret") or "").strip())
    settings["oidc_client_secret"] = ""
    if ldap_test is not None or oidc_test is not None:
        # Keep typed-but-unsaved values on screen after a connection test.
        _overlay_probe_form(settings, request.form)
    users, all_users, ldap_role_maps, oidc_role_maps = [], [], [], []
    cluster_webhooks = _cluster_webhooks() if tab == "webhooks" else []
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
    oidc_redirect_uri = (server_url + "/login/oidc/callback") if server_url else ""
    encryption = None
    encryption_q = ""
    encryption_page = 1
    projects_pager = None
    if tab == "encryption":
        encryption_q = (request.args.get("q") or "").strip()
        encryption_page_s = (request.args.get("page") or "1").strip()
        try:
            encryption_page = max(1, int(encryption_page_s))
        except ValueError:
            encryption_page = 1
        summary = project_keys.encryption_summary()
        all_projects = summary["projects"]
        if encryption_q:
            qn = encryption_q.lower()
            all_projects = [
                p
                for p in all_projects
                if qn in (p.get("team_name") or "").lower()
                or qn in (p.get("project_name") or "").lower()
                or qn in (p.get("provider") or "").lower()
                or qn in (p.get("key_id") or "").lower()
                or qn in (p.get("hsm_slot_name") or "").lower()
            ]
        from ui import paging

        per_page = 25
        total = len(all_projects)
        projects_pager = paging.page_window(total, encryption_page, per_page)
        projects_pager["endpoint"] = "server_settings"
        projects_pager["tab"] = "encryption"
        projects_pager["q"] = encryption_q or None
        offset = (encryption_page - 1) * per_page
        sliced = all_projects[offset : offset + per_page]
        summary = {
            "counts": summary["counts"],
            "projects": sliced,
            "total": total,
        }
        hsm_slots = []
        legacy_hsm_count = 0
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM private.hsm_slots ORDER BY is_default DESC, name")
            hsm_slots = cur.fetchall() or []
            cur.execute(
                "SELECT hsm_slot_id, count(*) AS n "
                "FROM private.project_crypto_keys "
                "WHERE key_provider = 'hsm' AND hsm_slot_id IS NOT NULL "
                "GROUP BY hsm_slot_id"
            )
            slot_counts = {row["hsm_slot_id"]: int(row["n"]) for row in cur.fetchall()}
            for slot in hsm_slots:
                slot["project_count"] = slot_counts.get(slot["id"], 0)
            cur.execute(
                "SELECT count(*) AS n FROM private.project_crypto_keys "
                "WHERE key_provider = 'hsm' AND hsm_slot_id IS NULL"
            )
            legacy_hsm_count = int((cur.fetchone() or {}).get("n") or 0)
        for slot in hsm_slots:
            slot["available"] = hsm.available_for_slot(slot["pkcs11_url"])
        encryption = {
            "master_key_is_default": config.master_key_is_default(),
            "summary": summary,
            "hsm_slots": hsm_slots,
            "legacy_hsm_count": legacy_hsm_count,
            "redact": hsm.redact_pkcs11_url,
        }
    health_probe = _health_probe() if tab == "health" else None
    return render_template(
        "settings.html",
        settings=settings,
        users=users,
        all_users=all_users,
        ldap_role_maps=ldap_role_maps,
        oidc_role_maps=oidc_role_maps,
        classification=settings_svc.classification(),
        active_tab=tab,
        categories=SETTINGS_CATEGORIES,
        smtp_encryption_modes=config.SMTP_ENCRYPTION_MODES,
        server_url=server_url,
        oidc_redirect_uri=oidc_redirect_uri,
        encryption=encryption,
        encryption_q=encryption_q,
        encryption_page=encryption_page,
        projects_pager=projects_pager,
        health_probe=health_probe,
        webhooks=cluster_webhooks,
        ldap_test=ldap_test,
        oidc_test=oidc_test,
    )


@authz.global_admin_required
def hsm_slot_new_wizard():
    """Render and handle the HSM slot wizard page (Test + Create / Edit).

    GET with ``?slot_id=<uuid>`` pre-fills the form for editing an existing slot.
    POST ``action=test`` validates the connection. POST ``action=create`` saves
    (creates or updates); when the connection test fails, the form re-renders
    with a "Save without testing" button (``force_save=1``).

    Example:
        GET /settings/encryption/hsm-slots/new
        GET /settings/encryption/hsm-slots/new?slot_id=<uuid>
        POST /settings/encryption/hsm-slots/new  (action=test|create)
    """
    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        name = (request.form.get("name") or "").strip()
        pkcs11_url = (request.form.get("pkcs11_url") or "").strip()
        description = (request.form.get("description") or "").strip()[:200]
        is_default = bool(request.form.get("is_default"))
        slot_id = (request.form.get("slot_id") or "").strip() or None
        force_save = action == "force_create"
        if slot_id and not pkcs11_url:
            with db.connect_admin() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT pkcs11_url FROM private.hsm_slots WHERE id = %s::uuid",
                    (slot_id,),
                )
                pkcs11_url = (cur.fetchone() or {}).get("pkcs11_url") or ""
        if not name or not pkcs11_url:
            return render_template(
                "hsm_slot_new.html",
                name=name,
                pkcs11_url=pkcs11_url,
                description=description,
                is_default=is_default,
                test_result=None,
                test_message="Name and PKCS#11 URL are required",
                slot_id=slot_id,
            )
        try:
            hsm.parse_pkcs11_url(pkcs11_url)
        except ValueError as e:
            return render_template(
                "hsm_slot_new.html",
                name=name,
                pkcs11_url=pkcs11_url,
                description=description,
                is_default=is_default,
                test_result=False,
                test_message=f"Invalid PKCS#11 URL: {e}",
                slot_id=slot_id,
            )
        test_ok = False
        test_message = None
        try:
            ok, msg = hsm.test_connection_for_slot(pkcs11_url)
            test_ok = ok
            test_message = msg
        except Exception as e:
            test_ok = False
            test_message = str(e)
        if action in ("create", "force_create") and (test_ok or force_save):
            try:
                with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                    cur.execute(
                        "SELECT api.hsm_slot_upsert(%s::uuid, %s, %s, %s, %s) AS id",
                        (slot_id, name, pkcs11_url, description, is_default),
                    )
                crypto.clear_slot_url_cache()
                with db.connect_admin() as conn, conn.cursor() as cur:
                    audit.log_org(
                        cur,
                        action="hsm_slot_added" if slot_id is None else "hsm_slot_edited",
                        detail=f"name={name} inline_pin={hsm.has_inline_pin(pkcs11_url)}",
                    )
                    conn.commit()
                msg = "HSM slot saved"
                if not test_ok:
                    msg += " (connection test failed — saved without testing)"
                if hsm.has_inline_pin(pkcs11_url):
                    msg += " (warning: inline PIN stored in database)"
                flash(msg, "ok")
                return redirect(url_for("server_settings", tab="encryption"))
            except Exception:
                flash("Could not save the HSM slot. Try again.", "error")
                return redirect(url_for("server_settings", tab="encryption"))
        return render_template(
            "hsm_slot_new.html",
            name=name,
            pkcs11_url=pkcs11_url,
            description=description,
            is_default=is_default,
            test_result=test_ok,
            test_message=test_message,
            slot_id=slot_id,
        )
    slot_id = (request.args.get("slot_id") or "").strip() or None
    name = ""
    pkcs11_url = ""
    pkcs11_url_display = ""
    description = ""
    is_default = False
    project_count = 0
    if slot_id:
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM api.list_hsm_slots() WHERE id = %s::uuid", (slot_id,))
            slot = cur.fetchone()
        if slot:
            name = slot["name"]
            pkcs11_url_display = hsm.redact_pkcs11_url(slot["pkcs11_url"])
            description = slot.get("description") or ""
            is_default = bool(slot.get("is_default"))
            try:
                with db.connect_admin() as conn, conn.cursor() as cur:
                    cur.execute(
                        "SELECT count(*) AS n FROM private.project_crypto_keys "
                        "WHERE key_provider = 'hsm' AND hsm_slot_id = %s::uuid",
                        (slot_id,),
                    )
                    project_count = int((cur.fetchone() or {}).get("n") or 0)
            except Exception:
                project_count = 0
    return render_template(
        "hsm_slot_new.html",
        name=name,
        pkcs11_url=pkcs11_url,
        pkcs11_url_display=pkcs11_url_display,
        description=description,
        is_default=is_default,
        project_count=project_count,
        test_result=None,
        test_message=None,
        slot_id=slot_id,
    )
