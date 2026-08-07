"""Server settings and classification banner."""
from config import DEFAULT_SETTINGS, HEX, bootstrap_admin_email
import db


def truthy(val) -> bool:
    return str(val or "").lower() in ("1", "true", "yes", "on")


def get_settings() -> dict:
    out = dict(DEFAULT_SETTINGS)
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute("SELECT key, value FROM private.server_settings")
            for row in cur.fetchall() or []:
                out[row["key"]] = row["value"]
    except Exception:
        pass
    return out


def set_setting(key: str, value: str):
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO private.server_settings (key, value) VALUES (%s, %s)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """,
            (key, value),
        )


def has_global_admin() -> bool:
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute("SELECT EXISTS (SELECT 1 FROM private.users WHERE is_global_admin) AS ok")
            row = cur.fetchone()
            return bool(row and row.get("ok"))
    except Exception:
        return False


def registration_enabled() -> bool:
    # No global admin and no bootstrap email configured → refuse open registration race
    if not has_global_admin() and not bootstrap_admin_email():
        return False
    return truthy(get_settings().get("registration_enabled", "true"))


def setup_notice() -> str | None:
    """Message when the instance still needs an admin bootstrap."""
    if has_global_admin():
        return None
    boot = bootstrap_admin_email()
    if boot:
        return (
            f"No global admin yet. Register or sign in as {boot} "
            f"(set via GLOBAL_ADMIN_EMAIL / BOOTSTRAP_ADMIN_EMAIL) to become admin."
        )
    return (
        "No global admin configured. Set GLOBAL_ADMIN_EMAIL (or BOOTSTRAP_ADMIN_EMAIL) "
        "and restart, then register that address."
    )


def can_create_team(is_global_admin: bool = False) -> bool:
    return bool(is_global_admin) or truthy(
        get_settings().get("user_team_creation_enabled", "true")
    )


def public_base_url(fallback: str = "") -> str:
    """Configured server URL, or fallback (e.g. request.url_root). No trailing slash."""
    configured = (get_settings().get("server_url") or "").strip().rstrip("/")
    if configured:
        return configured
    return (fallback or "").strip().rstrip("/")


def branding() -> dict:
    """Brand name / tagline and full app_name for titles and mail."""
    from config import APP_NAME, DEFAULT_SETTINGS

    s = get_settings()
    name = (s.get("brand_name") or DEFAULT_SETTINGS.get("brand_name") or "Sigaint").strip()
    name = name or "Sigaint"
    tagline = (s.get("brand_tagline") or DEFAULT_SETTINGS.get("brand_tagline") or "").strip()
    full = f"{name} {tagline}".strip() if tagline else name
    if not full:
        full = APP_NAME
    return {
        "brand_name": name,
        "brand_tagline": tagline,
        "app_name": full,
    }


def classification():
    s = get_settings()
    enabled = truthy(s.get("classification_enabled"))
    text = (s.get("classification_text") or "").strip()
    color = s.get("classification_color") or "#677381"
    fg = s.get("classification_fg") or "#ffffff"
    if not HEX.match(color):
        color = "#677381"
    if not HEX.match(fg):
        fg = "#ffffff"
    return {
        "enabled": enabled and bool(text),
        "text": text,
        "color": color,
        "fg": fg,
    }
