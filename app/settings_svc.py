"""Server settings and classification banner."""
from config import DEFAULT_SETTINGS, HEX
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


def registration_enabled() -> bool:
    return truthy(get_settings().get("registration_enabled", "true"))


def can_create_team(is_global_admin: bool = False) -> bool:
    return bool(is_global_admin) or truthy(
        get_settings().get("user_team_creation_enabled", "true")
    )


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
