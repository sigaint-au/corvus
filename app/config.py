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
}
TEAM_ROLES = ("owner", "admin", "member", "read-only")
ROLE_RANK = {"owner": 4, "admin": 3, "member": 2, "read-only": 1}
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
