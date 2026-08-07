"""Environment and application constants."""
import os
import re

_DEFAULT_SECRET_KEY = "flask-session-secret-change-me"
_DEFAULT_JWT_SECRET = "dev-jwt-secret-change-me-32chars!!"
_DEFAULT_MASTER_KEY = "dev-master-key-change-in-prod!!"

SECRET_KEY = os.environ.get("SECRET_KEY", _DEFAULT_SECRET_KEY)
DATABASE_URL = os.environ["DATABASE_URL"]
# Superuser DSN for schema upgrades only. Do not fall back to DATABASE_URL
# (authenticator) — that silently fails policy DDL and masks misconfiguration.
DATABASE_ADMIN_URL = os.environ.get("DATABASE_ADMIN_URL", "").strip()
JWT_SECRET = os.environ.get("JWT_SECRET", _DEFAULT_JWT_SECRET)
MASTER_KEY = os.environ.get("MASTER_KEY", _DEFAULT_MASTER_KEY)
POSTGREST_URL = os.environ.get("POSTGREST_URL", "http://localhost:3000")
GLOBAL_ADMIN_EMAIL = os.environ.get("GLOBAL_ADMIN_EMAIL", "").strip().lower()
# Alias: promote this email once no global admin exists yet (same as GLOBAL_ADMIN_EMAIL).
BOOTSTRAP_ADMIN_EMAIL = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()


def bootstrap_admin_email() -> str:
    """Email that may be promoted to global admin (GLOBAL_ADMIN_EMAIL or BOOTSTRAP_ADMIN_EMAIL)."""
    return GLOBAL_ADMIN_EMAIL or BOOTSTRAP_ADMIN_EMAIL


def refuse_insecure_defaults():
    """Exit if production still uses baked-in default secrets."""
    if os.environ.get("FLASK_ENV") == "development":
        return
    if os.environ.get("ALLOW_INSECURE_DEFAULTS", "").lower() in ("1", "true", "yes"):
        return
    for name, current, default in (
        ("SECRET_KEY", SECRET_KEY, _DEFAULT_SECRET_KEY),
        ("JWT_SECRET", JWT_SECRET, _DEFAULT_JWT_SECRET),
        ("MASTER_KEY", MASTER_KEY, _DEFAULT_MASTER_KEY),
    ):
        if current == default:
            raise SystemExit(
                f"Refusing to start: {name} is still the default. "
                "Set a real value, or ALLOW_INSECURE_DEFAULTS=1 / FLASK_ENV=development for local use."
            )

APP_NAME = "Sigaint Secret Server"

HEX = re.compile(r"^#[0-9A-Fa-f]{6}$")
DEFAULT_SETTINGS = {
    "classification_enabled": "false",
    "classification_text": "OFFICIAL",
    "classification_color": "#677381",
    "classification_fg": "#ffffff",
    "registration_enabled": "true",
    "user_team_creation_enabled": "true",
    "ldap_enabled": "false",
    "ldap_url": "",
    "ldap_start_tls": "false",
    "ldap_bind_dn": "",
    "ldap_bind_password": "",
    "ldap_user_base": "",
    "ldap_user_filter": "(|(mail={login})(uid={login}))",
    "ldap_email_attr": "mail",
    "ldap_name_attr": "displayName",
    "ldap_group_base": "",
    "ldap_group_filter": "(member={dn})",
    "ldap_use_memberof": "true",
    # Outbound email (password resets, login alerts)
    "smtp_enabled": "false",
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_encryption": "starttls",  # none | starttls | ssl
    "smtp_username": "",
    "smtp_password": "",
    "smtp_from_email": "",
    "smtp_from_name": APP_NAME,
    "smtp_login_alerts": "false",
    "totp_enforce_global_admins": "false",
}
TEAM_ROLES = ("owner", "admin", "member", "viewer")
ROLE_RANK = {"owner": 4, "admin": 3, "member": 2, "viewer": 1}
# Invite / join-request roles (cannot self-invite as owner)
INVITE_ROLES = ("admin", "member", "viewer")
# Project-scoped membership (in addition to team roles)
PROJECT_ROLES = ("admin", "write", "read")
# Machine accounts / ESO tokens: read-only (fetch) or write (fetch + upsert API)
MACHINE_TOKEN_ROLES = ("read-only", "write")
# Clipboard auto-clear after copy (seconds); 0 disables
CLIPBOARD_CLEAR_SECONDS = max(
    0, int(os.environ.get("CLIPBOARD_CLEAR_SECONDS", "30") or "30")
)
# Auto-hide revealed secret values (seconds); 0 disables
REVEAL_AUTO_HIDE_SECONDS = max(
    0, int(os.environ.get("REVEAL_AUTO_HIDE_SECONDS", "30") or "30")
)
# Structured secret kinds for advanced create form
SECRET_KINDS = ("plain", "database", "certificate", "ssh", "kv")
# Upper bounds for optional expiry (secrets, machine tokens, team defaults)
MAX_EXPIRY_DAYS = 3650  # ~10 years
# Request body / secret import file cap (bytes) — memory DoS guard
MAX_CONTENT_LENGTH = max(
    64 * 1024,
    int(os.environ.get("MAX_CONTENT_LENGTH", str(1 * 1024 * 1024)) or str(1 * 1024 * 1024)),
)
MAX_IMPORT_BYTES = MAX_CONTENT_LENGTH
# Sidebar lists
SIDEBAR_PINS_LIMIT = 8
SIDEBAR_RECENT_LIMIT = 8
LDAP_SETTING_KEYS = (
    "ldap_enabled",
    "ldap_url",
    "ldap_start_tls",
    "ldap_bind_dn",
    "ldap_bind_password",
    "ldap_user_base",
    "ldap_user_filter",
    "ldap_email_attr",
    "ldap_name_attr",
    "ldap_group_base",
    "ldap_group_filter",
    "ldap_use_memberof",
)
SMTP_SETTING_KEYS = (
    "smtp_enabled",
    "smtp_host",
    "smtp_port",
    "smtp_encryption",
    "smtp_username",
    "smtp_password",
    "smtp_from_email",
    "smtp_from_name",
    "smtp_login_alerts",
)
SMTP_ENCRYPTION_MODES = ("none", "starttls", "ssl")
