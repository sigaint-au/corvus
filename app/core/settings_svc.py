"""Server settings and classification banner."""

from core import db
from core.config import DEFAULT_SETTINGS, HEX, MAX_EXPIRY_DAYS, bootstrap_admin_email


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


def token_expiry_policy(kind: str) -> tuple[bool, int]:
    settings = get_settings()
    if kind == "pat":
        require_key = "require_pat_expiry"
        max_key = "max_pat_lifetime_days"
    else:
        require_key = "require_machine_token_expiry"
        max_key = "max_machine_token_lifetime_days"
    raw = (settings.get(max_key) or "").strip()
    try:
        max_days = int(raw) if raw else MAX_EXPIRY_DAYS
    except ValueError:
        max_days = MAX_EXPIRY_DAYS
    if max_days < 1 or max_days > MAX_EXPIRY_DAYS:
        max_days = MAX_EXPIRY_DAYS
    return truthy(settings.get(require_key)), max_days


def int_setting(key: str, default: int) -> int:
    """Return a server setting as a clamped non-negative int (default on garbage)."""
    try:
        return max(0, int(get_settings().get(key) or default))
    except (TypeError, ValueError):
        return default


def reveal_access_grant_minutes() -> int:
    """Return the approved-reveal grant window in minutes."""
    return max(1, int_setting("reveal_access_grant_minutes", 15))


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
    return bool(is_global_admin) or truthy(get_settings().get("user_team_creation_enabled", "true"))


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
    from core.config import APP_NAME

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


def team_classification(row) -> dict:
    """Build classification banner display settings for a team override row.

    ``classification_enabled`` None means "no override" (disabled banner); True
    shows the banner only when text is present; False hides it even if the
    server banner is on. Invalid hex colors fall back to defaults.

    Args:
        row: Team row with classification_enabled / _text / _color / _fg.

    Returns:
        Dict with keys enabled (bool), text (str), color (hex bg), fg (hex).

    Example:
        >>> c = team_classification({"classification_enabled": True,
        ...                          "classification_text": "OFFICIAL",
        ...                          "classification_color": "#000000",
        ...                          "classification_fg": "#ffffff"})
        >>> c["enabled"]
        True
    """
    en = row.get("classification_enabled") if row else None
    if en is None:
        return {"enabled": False, "text": "", "color": "#677381", "fg": "#ffffff"}
    text = (row.get("classification_text") or "").strip()
    color = (row.get("classification_color") or "").strip() or "#677381"
    fg = (row.get("classification_fg") or "").strip() or "#ffffff"
    if not HEX.match(color):
        color = "#677381"
    if not HEX.match(fg):
        fg = "#ffffff"
    return {
        "enabled": bool(en) and bool(text),
        "text": text if en else "",
        "color": color,
        "fg": fg,
    }


def login_banner() -> dict:
    """Build login-banner display settings (DoD / policy compliance banner).

    Shown on the sign-in screen: disclosure text plus an optional link to a
    system-use policy. ``enabled`` is True only when the setting is truthy
    and text is non-empty; plain text is rendered with line breaks preserved.

    Args:
        None.

    Returns:
        Dict with keys ``enabled`` (bool), ``text`` (str), ``link_text``
        (str), ``link_url`` (str), and ``has_link`` (bool).

    Example:
        >>> b = login_banner()
        >>> set(b) >= {"enabled", "text", "link_text", "link_url", "has_link"}
        True
    """
    s = get_settings()
    enabled = truthy(s.get("login_banner_enabled"))
    text = (s.get("login_banner_text") or "").strip()
    link_text = (s.get("login_banner_link_text") or "").strip() or "Policy"
    link_url = (s.get("login_banner_link_url") or "").strip()
    return {
        "enabled": enabled and bool(text),
        "text": text,
        "link_text": link_text,
        "link_url": link_url,
        "has_link": bool(link_url),
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
