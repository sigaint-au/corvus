"""LDAP authentication and group membership sync."""
import logging

from config import DEFAULT_SETTINGS, LDAP_SETTING_KEYS, ROLE_RANK
from crypto import decrypt
import db
from settings_svc import get_settings, truthy

log = logging.getLogger(__name__)


def ldap_cfg() -> dict:
    s = get_settings()
    return {k: s.get(k, DEFAULT_SETTINGS.get(k, "")) for k in LDAP_SETTING_KEYS}


def ldap_password_plain(cfg: dict) -> str:
    enc = (cfg.get("ldap_bind_password") or "").strip()
    if not enc:
        return ""
    try:
        return decrypt(enc)
    except Exception:
        log.exception("failed to decrypt ldap_bind_password; refusing ciphertext as bind password")
        return ""


def group_tokens(group: str) -> set:
    """Normalize an LDAP group DN/CN into match tokens (lowercased)."""
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
    want = group_tokens(map_group)
    if not want:
        return False
    for ug in user_groups or []:
        if want & group_tokens(ug):
            return True
    return False


def ldap_attr(entry, attr: str, default: str = "") -> str:
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
    """Escape special chars for LDAP filter values."""
    out = []
    for ch in value or "":
        if ch in r"\*()":
            out.append(f"\\{ord(ch):02x}")
        elif ch == "\x00":
            out.append("\\00")
        else:
            out.append(ch)
    return "".join(out)


def ldap_authenticate(login: str, password: str) -> dict | None:
    """
    Bind as user against LDAP. Returns {email, name, groups} or None.
    groups is a list of group DNs/CNs (strings).
    """
    cfg = ldap_cfg()
    if not truthy(cfg.get("ldap_enabled")):
        return None
    url = (cfg.get("ldap_url") or "").strip()
    user_base = (cfg.get("ldap_user_base") or "").strip()
    if not url or not user_base or not login or not password:
        return None

    try:
        from ldap3 import ALL, SUBTREE, Connection, Server
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
            svc = Connection(server, user=bind_dn, password=bind_pw, auto_bind=True, receive_timeout=10)
        else:
            svc = Connection(server, auto_bind=True, receive_timeout=10)
        if truthy(cfg.get("ldap_start_tls")):
            svc.start_tls()

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

        uc = Connection(server, user=user_dn, password=password, auto_bind=True, receive_timeout=10)
        if truthy(cfg.get("ldap_start_tls")):
            try:
                uc.start_tls()
            except Exception:
                pass
        uc.unbind()

        if (not groups) and group_base and group_filter_tmpl:
            gfilter = group_filter_tmpl.replace("{dn}", ldap_escape(user_dn)).replace(
                "{login}", ldap_escape(login)
            )
            if bind_dn:
                gc = Connection(server, user=bind_dn, password=bind_pw, auto_bind=True, receive_timeout=10)
            else:
                gc = Connection(server, auto_bind=True, receive_timeout=10)
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
    """Upsert LDAP user, apply global role maps + team membership maps. Returns user row."""
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute("SELECT private.upsert_ldap_user(%s, %s) AS id", (email, name or ""))
        uid = cur.fetchone()["id"]

        cur.execute("SELECT ldap_group, role FROM private.ldap_role_maps")
        role_maps = cur.fetchall() or []
        if role_maps:
            is_admin = any(
                m["role"] == "global_admin" and group_matches(m["ldap_group"], groups)
                for m in role_maps
            )
            cur.execute(
                "UPDATE private.users SET is_global_admin = %s WHERE id = %s",
                (is_admin, str(uid)),
            )
        cur.execute(
            "SELECT id, email, name, is_global_admin FROM private.users WHERE id = %s",
            (str(uid),),
        )
        user = cur.fetchone()

        cur.execute("SELECT id, team_id, ldap_group, role FROM api.team_ldap_maps")
        tmaps = cur.fetchall() or []
        desired = {}
        for m in tmaps:
            if not group_matches(m["ldap_group"], groups):
                continue
            tid = str(m["team_id"])
            role = m["role"]
            if tid not in desired or ROLE_RANK.get(role, 0) > ROLE_RANK.get(desired[tid], 0):
                desired[tid] = role

        cur.execute(
            """
            DELETE FROM api.team_members
            WHERE user_id = %s AND source = 'ldap'
              AND NOT (team_id = ANY(%s::uuid[]))
            """,
            (str(uid), list(desired.keys()) or []),
        )
        for tid, role in desired.items():
            cur.execute(
                """
                SELECT role, source FROM api.team_members
                WHERE team_id = %s AND user_id = %s
                """,
                (tid, str(uid)),
            )
            existing = cur.fetchone()
            if existing and existing.get("source") == "manual":
                continue
            if existing:
                cur.execute(
                    """
                    UPDATE api.team_members SET role = %s, source = 'ldap'
                    WHERE team_id = %s AND user_id = %s
                    """,
                    (role, tid, str(uid)),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO api.team_members (team_id, user_id, role, source)
                    VALUES (%s, %s, %s, 'ldap')
                    """,
                    (tid, str(uid), role),
                )
        return user
