"""LDAP authentication and group membership sync."""
import logging

from core.config import DEFAULT_SETTINGS, LDAP_SETTING_KEYS
from crypto import decrypt
from core import db
from core.settings_svc import get_settings, truthy

log = logging.getLogger(__name__)


def ldap_cfg() -> dict:
    """Build the LDAP settings dict from stored server settings.

    Returns:
        Mapping of each LDAP setting key to its configured value, using
        defaults from DEFAULT_SETTINGS when a key is unset.

    Example:
        >>> cfg = ldap_cfg()
        >>> "ldap_url" in cfg
        True
    """
    s = get_settings()
    return {k: s.get(k, DEFAULT_SETTINGS.get(k, "")) for k in LDAP_SETTING_KEYS}


def ldap_tls_required_ok(url: str, start_tls: bool) -> bool:
    """Check that LDAP credentials will not go over cleartext.

    Accepts ldaps:// always, or ldap:// only when StartTLS is enabled.
    Unknown schemes require StartTLS rather than guessing.

    Args:
        url: LDAP server URL (e.g. ``ldaps://ldap.example.com`` or
            ``ldap://ldap.example.com``).
        start_tls: Whether StartTLS is enabled in LDAP settings.

    Returns:
        True if the transport is safe enough for credentials; False if
        the URL is empty, cleartext without StartTLS, or otherwise unsafe.

    Example:
        >>> ldap_tls_required_ok("ldaps://ldap.example.com", False)
        True
        >>> ldap_tls_required_ok("ldap://ldap.example.com", False)
        False
        >>> ldap_tls_required_ok("ldap://ldap.example.com", True)
        True
    """
    u = (url or "").strip().lower()
    if not u:
        return False
    if u.startswith("ldaps://"):
        return True
    if u.startswith("ldap://"):
        return bool(start_tls)
    # Unknown scheme: require StartTLS rather than guess
    return bool(start_tls)


def ldap_password_plain(cfg: dict) -> str:
    """Decrypt the LDAP bind password from encrypted settings.

    Args:
        cfg: LDAP settings mapping that may contain ``ldap_bind_password``
            (encrypted ciphertext).

    Returns:
        Decrypted plaintext bind password, or an empty string if unset
        or decryption fails.

    Example:
        >>> ldap_password_plain({"ldap_bind_password": ""})
        ''
    """
    enc = (cfg.get("ldap_bind_password") or "").strip()
    if not enc:
        return ""
    try:
        return decrypt(enc)
    except Exception:
        log.exception("failed to decrypt ldap_bind_password; refusing ciphertext as bind password")
        return ""


def group_tokens(group: str) -> set:
    """Normalize an LDAP group DN/CN into match tokens (lowercased).

    Args:
        group: Group DN or CN string (e.g. ``CN=Admins,OU=Groups,DC=ex``
            or a bare name like ``admins``).

    Returns:
        Set of lowercased tokens used for membership matching (full DN,
        bare CN, and ``cn=...`` forms as applicable). Empty set if
        ``group`` is blank.

    Example:
        >>> tokens = group_tokens("CN=Admins,OU=Groups,DC=ex")
        >>> "admins" in tokens
        True
    """
    g = (group or "").strip()
    if not g:
        return set()
    low = g.lower()
    tokens = {low}
    if low.startswith("cn="):
        cn = low.split(",", 1)[0][3:]
        tokens.add(cn)
        tokens.add(f"cn={cn}")
    else:
        tokens.add(f"cn={low}")
    return tokens


def group_matches(map_group: str, user_groups: list) -> bool:
    """Return whether any user group matches a configured map group.

    Args:
        map_group: Group name or DN from a role/team map entry.
        user_groups: List of group DNs/CNs belonging to the user.

    Returns:
        True if any entry in ``user_groups`` shares tokens with
        ``map_group``; False if ``map_group`` is empty or no overlap.

    Example:
        >>> group_matches("admins", ["CN=Admins,OU=Groups,DC=ex"])
        True
        >>> group_matches("admins", ["CN=Users,OU=Groups,DC=ex"])
        False
    """
    want = group_tokens(map_group)
    if not want:
        return False
    for ug in user_groups or []:
        if want & group_tokens(ug):
            return True
    return False


def ldap_attr(entry, attr: str, default: str = "") -> str:
    """Read the first value of an LDAP attribute from an entry.

    Args:
        entry: ldap3 entry object with ``entry_attributes_as_dict``, or
            a falsy value when no entry is available.
        attr: Attribute name to read (e.g. ``mail``, ``displayName``).
        default: Value returned when the attribute is missing or empty.

    Returns:
        String form of the first attribute value, or ``default``.

    Example:
        >>> ldap_attr(None, "mail", "nobody@example.com")
        'nobody@example.com'
    """
    if not entry or not attr:
        return default
    try:
        vals = entry.entry_attributes_as_dict.get(attr) or []
        if vals:
            return str(vals[0])
    except Exception:
        pass
    return default


def ldap_escape(value: str) -> str:
    """Escape special characters for use in LDAP filter values.

    Args:
        value: Raw string to embed in an LDAP filter (login, DN, etc.).

    Returns:
        Escaped string safe for LDAP filter interpolation (handles
        ``\\``, ``*``, ``(``, ``)``, and null bytes).

    Example:
        >>> ldap_escape("user*name")
        'user\\\\2aname'
    """
    out = []
    for ch in value or "":
        if ch in r"\*()":
            out.append(f"\\{ord(ch):02x}")
        elif ch == "\x00":
            out.append("\\00")
        else:
            out.append(ch)
    return "".join(out)


def _ldap_bind(server, user=None, password=None, start_tls=False, receive_timeout=10):
    """Open an LDAP connection, optionally StartTLS, then bind.

    Never uses auto_bind so credentials do not go over cleartext when
    StartTLS is required. Order is: open → optional start_tls (fail
    closed) → bind.

    Args:
        server: ldap3 ``Server`` instance to connect to.
        user: Bind DN or username; omit for anonymous open/bind.
        password: Bind password corresponding to ``user``.
        start_tls: If True, negotiate StartTLS after open and before bind.
        receive_timeout: Socket receive timeout in seconds.

    Returns:
        Bound ldap3 ``Connection`` ready for search/operations.

    Example:
        >>> # conn = _ldap_bind(server, user="cn=svc,dc=ex", password="secret", start_tls=True)
        >>> # conn.search(...)
    """
    from ldap3 import Connection

    kwargs = {"receive_timeout": receive_timeout, "auto_bind": False}
    if user is not None:
        kwargs["user"] = user
        kwargs["password"] = password
    conn = Connection(server, **kwargs)
    if not conn.open():
        raise RuntimeError("LDAP open failed")
    if start_tls:
        if not conn.start_tls():
            try:
                conn.unbind()
            except Exception:
                pass
            raise RuntimeError("LDAP StartTLS failed")
    if not conn.bind():
        try:
            conn.unbind()
        except Exception:
            pass
        raise RuntimeError("LDAP bind failed")
    return conn


def ldap_authenticate(login: str, password: str) -> dict | None:
    """Authenticate a user against LDAP and collect profile/group data.

    Binds with service credentials (if configured) to locate the user,
    proves the user's password with a second bind, and resolves groups
    via memberOf and/or a group search.

    Args:
        login: User login identifier used in the user filter (often email).
        password: Plaintext password to verify via user bind.

    Returns:
        Dict with keys ``email``, ``name``, ``groups`` (list of group
        DNs/CNs), and ``dn`` on success; None if LDAP is disabled,
        misconfigured, transport is unsafe, user not found, or auth fails.

    Example:
        >>> result = ldap_authenticate("user@example.com", "secret")
        >>> # result is None or {"email": "...", "name": "...", "groups": [...], "dn": "..."}
    """
    cfg = ldap_cfg()
    if not truthy(cfg.get("ldap_enabled")):
        return None
    url = (cfg.get("ldap_url") or "").strip()
    user_base = (cfg.get("ldap_user_base") or "").strip()
    if not url or not user_base or not login or not password:
        return None

    start_tls_cfg = truthy(cfg.get("ldap_start_tls"))
    if not ldap_tls_required_ok(url, start_tls_cfg):
        log.error(
            "LDAP refused cleartext transport (use ldaps:// or enable StartTLS): %s",
            url.split("?")[0][:80],
        )
        return None
    # StartTLS only applies to plain ldap://; ldaps:// is already TLS
    want_tls = start_tls_cfg and not url.lower().startswith("ldaps://")

    try:
        from ldap3 import ALL, SUBTREE, Server
    except ImportError:
        log.error("ldap3 not installed")
        return None

    user_filter = (cfg.get("ldap_user_filter") or "(mail={login})").replace(
        "{login}", ldap_escape(login)
    )
    email_attr = (cfg.get("ldap_email_attr") or "mail").strip() or "mail"
    name_attr = (cfg.get("ldap_name_attr") or "displayName").strip() or "displayName"
    use_memberof = truthy(cfg.get("ldap_use_memberof"))
    group_base = (cfg.get("ldap_group_base") or "").strip()
    group_filter_tmpl = (cfg.get("ldap_group_filter") or "(member={dn})").strip()

    try:
        server = Server(url, get_info=ALL, connect_timeout=8)
        bind_dn = (cfg.get("ldap_bind_dn") or "").strip()
        bind_pw = ldap_password_plain(cfg)
        if bind_dn:
            svc = _ldap_bind(server, user=bind_dn, password=bind_pw, start_tls=want_tls)
        else:
            svc = _ldap_bind(server, start_tls=want_tls)

        if not svc.search(
            user_base,
            user_filter,
            search_scope=SUBTREE,
            attributes=[email_attr, name_attr, "memberOf", "cn", "uid"],
            size_limit=1,
        ) or not svc.entries:
            svc.unbind()
            return None
        entry = svc.entries[0]
        user_dn = str(entry.entry_dn)
        email = ldap_attr(entry, email_attr, login).strip().lower()
        name = ldap_attr(entry, name_attr) or ldap_attr(entry, "cn") or email
        groups = []
        if use_memberof:
            groups = [str(g) for g in (entry.entry_attributes_as_dict.get("memberOf") or [])]
        svc.unbind()

        # Prove user credentials (same open → StartTLS → bind order)
        uc = _ldap_bind(server, user=user_dn, password=password, start_tls=want_tls)
        uc.unbind()

        if (not groups) and group_base and group_filter_tmpl:
            gfilter = group_filter_tmpl.replace("{dn}", ldap_escape(user_dn)).replace(
                "{login}", ldap_escape(login)
            )
            if bind_dn:
                gc = _ldap_bind(server, user=bind_dn, password=bind_pw, start_tls=want_tls)
            else:
                gc = _ldap_bind(server, start_tls=want_tls)
            if gc.search(group_base, gfilter, search_scope=SUBTREE, attributes=["cn", "distinguishedName"]):
                for ge in gc.entries:
                    groups.append(str(ge.entry_dn))
                    cn = ldap_attr(ge, "cn")
                    if cn:
                        groups.append(cn)
            gc.unbind()

        if not email:
            email = login.strip().lower()
        return {"email": email, "name": name, "groups": groups, "dn": user_dn}
    except Exception as e:
        log.warning("LDAP auth failed for %s: %s", login, e)
        return None


def sync_ldap_user(email: str, name: str, groups: list) -> dict:
    """Upsert an LDAP user and apply role/team membership maps.

    Args:
        email: Normalized user email address.
        name: Display name (empty string allowed).
        groups: List of LDAP group DNs/CNs for map matching.

    Returns:
        User row dict from the database after upsert and map application.

    Example:
        >>> # user = sync_ldap_user("a@b.com", "Ada", ["CN=Admins,DC=ex"])
        >>> # user["email"] == "a@b.com"
    """
    from integrations.dir_sync import (
        apply_global_admin_maps,
        apply_group_membership_maps,
        apply_team_membership_maps,
        fetch_user_row,
    )

    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute("SELECT private.upsert_ldap_user(%s, %s) AS id", (email, name or ""))
        uid = cur.fetchone()["id"]
        cur.execute("SELECT ldap_group, role FROM private.ldap_role_maps")
        apply_global_admin_maps(cur, uid, groups, cur.fetchall() or [], "ldap_group")
        cur.execute("SELECT id, team_id, ldap_group, role FROM api.team_ldap_maps")
        apply_team_membership_maps(
            cur, uid, groups, cur.fetchall() or [], group_key="ldap_group", source="ldap"
        )
        apply_group_membership_maps(cur, uid, groups, source="ldap")
        return fetch_user_row(cur, uid)
