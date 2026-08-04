"""Environment and application constants."""
import os
import re

SECRET_KEY = os.environ.get("SECRET_KEY", "flask-session-secret-change-me")
DATABASE_URL = os.environ["DATABASE_URL"]
DATABASE_ADMIN_URL = os.environ.get(
    "DATABASE_ADMIN_URL",
    os.environ.get("DATABASE_URL", ""),
)
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-jwt-secret-change-me-32chars!!")
MASTER_KEY = os.environ.get("MASTER_KEY", "dev-master-key-change-in-prod!!")
POSTGREST_URL = os.environ.get("POSTGREST_URL", "http://localhost:3000")
GLOBAL_ADMIN_EMAIL = os.environ.get("GLOBAL_ADMIN_EMAIL", "").strip().lower()

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
