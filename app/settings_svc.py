"""Server settings and classification banner."""
from config import DEFAULT_SETTINGS, HEX, bootstrap_admin_email
import db


def truthy(val) -> bool:
    """Return whether a setting value is truthy (1/true/yes/on).

    Args:
        val: Value to interpret as a boolean-like setting (any type).

    Returns:
        True if the string form of val is one of "1", "true", "yes", or "on"
        (case-insensitive); False otherwise, including when val is None.

    Example:
        >>> truthy("yes")
        True
        >>> truthy("0")
        False
    """
    return str(val or "").lower() in ("1", "true", "yes", "on")


def get_settings() -> dict:
    """Load server settings merged over defaults from the database.

    Args:
        None.

    Returns:
        Dict of setting key to string value, starting from DEFAULT_SETTINGS
        and overlaid with rows from private.server_settings. On DB failure,
        returns a copy of the defaults only.

    Example:
        >>> s = get_settings()
        >>> "registration_enabled" in s
        True
    """
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
    """Insert or update a single server setting key.

    Args:
        key: Setting name (primary key in private.server_settings).
        value: New string value to store for that key.

    Returns:
        None.

    Example:
        >>> set_setting("registration_enabled", "false")
    """
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO private.server_settings (key, value) VALUES (%s, %s)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """,
            (key, value),
        )


def has_global_admin() -> bool:
    """Check whether any global admin user exists.

    Args:
        None.

    Returns:
        True if at least one private.users row has is_global_admin set;
        False on empty result or DB error.

    Example:
        >>> if not has_global_admin():
        ...     print("bootstrap required")
    """
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute("SELECT EXISTS (SELECT 1 FROM private.users WHERE is_global_admin) AS ok")
            row = cur.fetchone()
            return bool(row and row.get("ok"))
    except Exception:
        return False


def registration_enabled() -> bool:
    """Return whether open user registration is allowed.

    Args:
        None.

    Returns:
        False if there is no global admin and no bootstrap admin email
        configured (avoids an open registration race). Otherwise the
        truthy form of the registration_enabled setting (default true).

    Example:
        >>> if registration_enabled():
        ...     pass  # show register form
    """
    # No global admin and no bootstrap email configured → refuse open registration race
    if not has_global_admin() and not bootstrap_admin_email():
        return False
    return truthy(get_settings().get("registration_enabled", "true"))


def setup_notice() -> str | None:
    """Message when the instance still needs an admin bootstrap.

    Args:
        None.

    Returns:
        None if a global admin already exists; otherwise a human-readable
        string telling the operator how to bootstrap the first admin.

    Example:
        >>> notice = setup_notice()
        >>> notice is None or isinstance(notice, str)
        True
    """
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
    """Return whether the current user may create a team.

    Args:
        is_global_admin: True if the caller is a global admin (always allowed).

    Returns:
        True if the user is a global admin or the user_team_creation_enabled
        setting is truthy; False otherwise.

    Example:
        >>> can_create_team(is_global_admin=True)
        True
    """
    return bool(is_global_admin) or truthy(
        get_settings().get("user_team_creation_enabled", "true")
    )


def public_base_url(fallback: str = "") -> str:
    """Configured server URL, or fallback (e.g. request.url_root). No trailing slash.

    Args:
        fallback: URL used when server_url is unset (e.g. request.url_root).

    Returns:
        Absolute base URL without a trailing slash, from the server_url
        setting if set, otherwise from fallback (also stripped).

    Example:
        >>> public_base_url("https://example.com/")
        'https://example.com'
    """
    configured = (get_settings().get("server_url") or "").strip().rstrip("/")
    if configured:
        return configured
    return (fallback or "").strip().rstrip("/")


def branding() -> dict:
    """Brand name / tagline and full app_name for titles and mail.

    Args:
        None.

    Returns:
        Dict with keys brand_name, brand_tagline, and app_name (combined
        display name, falling back to APP_NAME if empty).

    Example:
        >>> b = branding()
        >>> "app_name" in b and "brand_name" in b
        True
    """
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
    """Build classification banner display settings.

    Args:
        None.

    Returns:
        Dict with keys enabled (bool), text (str), color (hex bg), and fg
        (hex foreground). enabled is True only when the setting is truthy
        and text is non-empty; invalid hex colors fall back to defaults.

    Example:
        >>> c = classification()
        >>> set(c) >= {"enabled", "text", "color", "fg"}
        True
    """
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
