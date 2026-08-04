"""Sigaint Secret Server: Flask+HTMX UI, PostgREST JWT, OpenShift ESO webhook API."""
import hashlib
import logging
import os
import re
import secrets
import time
from base64 import urlsafe_b64encode
from functools import wraps
from hashlib import sha256

import jwt
import psycopg
from cryptography.fernet import Fernet
from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from psycopg.rows import dict_row

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "flask-session-secret-change-me")

DATABASE_URL = os.environ["DATABASE_URL"]
# Superuser DSN for idempotent schema upgrades (init.sql only runs on empty volume)
DATABASE_ADMIN_URL = os.environ.get(
    "DATABASE_ADMIN_URL",
    os.environ.get("DATABASE_URL", ""),
)
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-jwt-secret-change-me-32chars!!")
MASTER_KEY = os.environ.get("MASTER_KEY", "dev-master-key-change-in-prod!!")
POSTGREST_URL = os.environ.get("POSTGREST_URL", "http://localhost:3000")
GLOBAL_ADMIN_EMAIL = os.environ.get("GLOBAL_ADMIN_EMAIL", "").strip().lower()

log = logging.getLogger(__name__)

APP_NAME = "Sigaint Secret Server"

_HEX = re.compile(r"^#[0-9A-Fa-f]{6}$")
_DEFAULT_SETTINGS = {
    "classification_enabled": "false",
    "classification_text": "OFFICIAL",
    "classification_color": "#677381",
    "classification_fg": "#ffffff",
    "ldap_enabled": "false",
    "ldap_url": "",
    "ldap_start_tls": "false",
    "ldap_bind_dn": "",
    "ldap_bind_password": "",
    "ldap_user_base": "",
    "ldap_user_filter": "(|(mail={login})(uid={login})(sAMAccountName={login}))",
    "ldap_email_attr": "mail",
    "ldap_name_attr": "displayName",
    "ldap_group_base": "",
    "ldap_group_filter": "(member={dn})",
    "ldap_use_memberof": "true",
}
_TEAM_ROLES = ("owner", "admin", "member")
_ROLE_RANK = {"owner": 3, "admin": 2, "member": 1}
_LDAP_SETTING_KEYS = (
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


def _fernet() -> Fernet:
    # Derive 32-byte key from MASTER_KEY
    key = urlsafe_b64encode(sha256(MASTER_KEY.encode()).digest())
    return Fernet(key)


def encrypt(val: str) -> str:
    return _fernet().encrypt(val.encode()).decode()


def decrypt(val: str) -> str:
    return _fernet().decrypt(val.encode()).decode()


def connect(autocommit=False):
    return psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=autocommit)


def connect_admin(autocommit=True):
    return psycopg.connect(DATABASE_ADMIN_URL, row_factory=dict_row, autocommit=autocommit)


def as_user(user_id: str):
    """Connection with JWT claims set so RLS matches PostgREST."""
    conn = connect()
    claims = {"sub": str(user_id), "role": "authenticated"}
    with conn.cursor() as cur:
        cur.execute("SET ROLE authenticated")
        cur.execute("SELECT set_config('request.jwt.claims', %s, false)", (jwt_json(claims),))
    return conn


def jwt_json(claims: dict) -> str:
    import json

    return json.dumps(claims)


def make_jwt(user_id: str, hours=24) -> str:
    return jwt.encode(
        {
            "sub": str(user_id),
            "role": "authenticated",
            "exp": int(time.time()) + hours * 3600,
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def login_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*a, **kw)

    return wrapped


def global_admin_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if not session.get("is_global_admin"):
            flash("Global admin access required", "error")
            return redirect(url_for("projects_list"))
        return f(*a, **kw)

    return wrapped


def htmx():
    return request.headers.get("HX-Request") == "true"


def _is_global_admin(user_id: str) -> bool:
    try:
        with connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT is_global_admin FROM private.users WHERE id = %s::uuid",
                (user_id,),
            )
            row = cur.fetchone()
            return bool(row and row.get("is_global_admin"))
    except Exception:
        return False


def _get_settings() -> dict:
    out = dict(_DEFAULT_SETTINGS)
    try:
        with connect_admin() as conn, conn.cursor() as cur:
            cur.execute("SELECT key, value FROM private.server_settings")
            for row in cur.fetchall() or []:
                out[row["key"]] = row["value"]
    except Exception:
        pass
    return out


def _set_setting(key: str, value: str):
    with connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO private.server_settings (key, value) VALUES (%s, %s)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """,
            (key, value),
        )


def _truthy(val) -> bool:
    return str(val or "").lower() in ("1", "true", "yes", "on")


def _ldap_cfg() -> dict:
    s = _get_settings()
    return {k: s.get(k, _DEFAULT_SETTINGS.get(k, "")) for k in _LDAP_SETTING_KEYS}


def _ldap_password_plain(cfg: dict) -> str:
    enc = (cfg.get("ldap_bind_password") or "").strip()
    if not enc:
        return ""
    try:
        return decrypt(enc)
    except Exception:
        # allow plain storage during migration / empty
        return enc


def _group_tokens(group: str) -> set:
    """Normalize an LDAP group DN/CN into match tokens (lowercased)."""
    g = (group or "").strip()
    if not g:
        return set()
    low = g.lower()
    tokens = {low}
    # CN=foo,OU=... → also match "foo" and "cn=foo"
    if low.startswith("cn="):
        cn = low.split(",", 1)[0][3:]
        tokens.add(cn)
        tokens.add(f"cn={cn}")
    else:
        tokens.add(f"cn={low}")
    return tokens


def _group_matches(map_group: str, user_groups: list) -> bool:
    want = _group_tokens(map_group)
    if not want:
        return False
    for ug in user_groups or []:
        if want & _group_tokens(ug):
            return True
    return False


def _ldap_attr(entry, attr: str, default: str = "") -> str:
    if not entry or not attr:
        return default
    try:
        vals = entry.entry_attributes_as_dict.get(attr) or []
        if vals:
            return str(vals[0])
    except Exception:
        pass
    return default


def ldap_authenticate(login: str, password: str) -> dict | None:
    """
    Bind as user against LDAP. Returns {email, name, groups} or None.
    groups is a list of group DNs/CNs (strings).
    """
    cfg = _ldap_cfg()
    if not _truthy(cfg.get("ldap_enabled")):
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
        "{login}", _ldap_escape(login)
    )
    email_attr = (cfg.get("ldap_email_attr") or "mail").strip() or "mail"
    name_attr = (cfg.get("ldap_name_attr") or "displayName").strip() or "displayName"
    use_memberof = _truthy(cfg.get("ldap_use_memberof"))
    group_base = (cfg.get("ldap_group_base") or "").strip()
    group_filter_tmpl = (cfg.get("ldap_group_filter") or "(member={dn})").strip()

    try:
        server = Server(url, get_info=ALL, connect_timeout=8)
        # service bind (optional) to search for user DN
        bind_dn = (cfg.get("ldap_bind_dn") or "").strip()
        bind_pw = _ldap_password_plain(cfg)
        if bind_dn:
            svc = Connection(server, user=bind_dn, password=bind_pw, auto_bind=True, receive_timeout=10)
        else:
            svc = Connection(server, auto_bind=True, receive_timeout=10)
        if _truthy(cfg.get("ldap_start_tls")):
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
        email = _ldap_attr(entry, email_attr, login).strip().lower()
        name = _ldap_attr(entry, name_attr) or _ldap_attr(entry, "cn") or email
        groups = []
        if use_memberof:
            groups = [str(g) for g in (entry.entry_attributes_as_dict.get("memberOf") or [])]
        svc.unbind()

        # user bind to verify password
        uc = Connection(server, user=user_dn, password=password, auto_bind=True, receive_timeout=10)
        if _truthy(cfg.get("ldap_start_tls")):
            try:
                uc.start_tls()
            except Exception:
                pass
        uc.unbind()

        # group search if not using memberOf or empty
        if (not groups) and group_base and group_filter_tmpl:
            gfilter = group_filter_tmpl.replace("{dn}", _ldap_escape(user_dn)).replace(
                "{login}", _ldap_escape(login)
            )
            if bind_dn:
                gc = Connection(server, user=bind_dn, password=bind_pw, auto_bind=True, receive_timeout=10)
            else:
                gc = Connection(server, auto_bind=True, receive_timeout=10)
            if gc.search(group_base, gfilter, search_scope=SUBTREE, attributes=["cn", "distinguishedName"]):
                for ge in gc.entries:
                    groups.append(str(ge.entry_dn))
                    cn = _ldap_attr(ge, "cn")
                    if cn:
                        groups.append(cn)
            gc.unbind()

        if not email:
            email = login.strip().lower()
        return {"email": email, "name": name, "groups": groups, "dn": user_dn}
    except Exception as e:
        log.warning("LDAP auth failed for %s: %s", login, e)
        return None


def _ldap_escape(value: str) -> str:
    """Escape special chars for LDAP filter values."""
    out = []
    for ch in value or "":
        if ch in r'\*()':
            out.append(f"\\{ord(ch):02x}")
        elif ch == "\x00":
            out.append("\\00")
        else:
            out.append(ch)
    return "".join(out)


def _sync_ldap_user(email: str, name: str, groups: list) -> dict:
    """Upsert LDAP user, apply global role maps + team membership maps. Returns user row."""
    with connect_admin() as conn, conn.cursor() as cur:
        cur.execute("SELECT private.upsert_ldap_user(%s, %s) AS id", (email, name or ""))
        uid = cur.fetchone()["id"]

        # Global admin from LDAP group → role maps (only when maps exist)
        cur.execute("SELECT ldap_group, role FROM private.ldap_role_maps")
        role_maps = cur.fetchall() or []
        if role_maps:
            is_admin = any(
                m["role"] == "global_admin" and _group_matches(m["ldap_group"], groups)
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

        # Team membership from team_ldap_maps
        cur.execute("SELECT id, team_id, ldap_group, role FROM api.team_ldap_maps")
        tmaps = cur.fetchall() or []
        desired = {}  # team_id -> best role
        for m in tmaps:
            if not _group_matches(m["ldap_group"], groups):
                continue
            tid = str(m["team_id"])
            role = m["role"]
            if tid not in desired or _ROLE_RANK.get(role, 0) > _ROLE_RANK.get(desired[tid], 0):
                desired[tid] = role

        # Drop LDAP-sourced memberships no longer mapped
        cur.execute(
            """
            DELETE FROM api.team_members
            WHERE user_id = %s AND source = 'ldap'
              AND NOT (team_id = ANY(%s::uuid[]))
            """,
            (str(uid), list(desired.keys()) or []),
        )
        for tid, role in desired.items():
            # leave manual memberships alone
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


def _classification():
    s = _get_settings()
    enabled = (s.get("classification_enabled") or "").lower() in ("1", "true", "yes", "on")
    text = (s.get("classification_text") or "").strip()
    color = s.get("classification_color") or "#677381"
    fg = s.get("classification_fg") or "#ffffff"
    if not _HEX.match(color):
        color = "#677381"
    if not _HEX.match(fg):
        fg = "#ffffff"
    return {
        "enabled": enabled and bool(text),
        "text": text,
        "color": color,
        "fg": fg,
    }


def _nav_teams(user_id: str):
    with as_user(user_id) as conn, conn.cursor() as cur:
        if session.get("is_global_admin"):
            cur.execute("SELECT t.id, t.name FROM api.teams t ORDER BY t.name")
        else:
            cur.execute(
                """
                SELECT t.id, t.name
                FROM api.teams t
                JOIN api.team_members tm ON tm.team_id = t.id
                WHERE tm.user_id = %s
                ORDER BY t.name
                """,
                (user_id,),
            )
        return cur.fetchall()


def _active_team_id(teams):
    """Session team if still a member, else first team."""
    ids = {str(t["id"]) for t in teams}
    tid = session.get("team_id")
    if tid in ids:
        return tid
    if teams:
        tid = str(teams[0]["id"])
        session["team_id"] = tid
        return tid
    session.pop("team_id", None)
    return None


@app.context_processor
def inject_nav():
    banner = _classification()
    base = {
        "app_name": APP_NAME,
        "classification": banner,
        "is_global_admin": bool(session.get("is_global_admin")),
        "nav_teams": [],
        "nav_team_id": None,
    }
    if not session.get("user_id"):
        return base
    # Refresh admin flag from DB (role can change mid-session)
    if session.get("user_id"):
        session["is_global_admin"] = _is_global_admin(session["user_id"])
        base["is_global_admin"] = session["is_global_admin"]
    try:
        teams = _nav_teams(session["user_id"])
    except Exception:
        teams = []
    base["nav_teams"] = teams
    base["nav_team_id"] = _active_team_id(teams)
    return base


def ensure_schema():
    """Idempotent upgrades for existing volumes (init.sql only runs once)."""
    stmts = [
        """
        ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS is_global_admin boolean NOT NULL DEFAULT false
        """,
        """
        CREATE TABLE IF NOT EXISTS private.server_settings (
          key text PRIMARY KEY,
          value text NOT NULL DEFAULT ''
        )
        """,
        """
        INSERT INTO private.server_settings (key, value) VALUES
          ('classification_enabled', 'false'),
          ('classification_text', 'OFFICIAL'),
          ('classification_color', '#677381'),
          ('classification_fg', '#ffffff'),
          ('ldap_enabled', 'false'),
          ('ldap_url', ''),
          ('ldap_start_tls', 'false'),
          ('ldap_bind_dn', ''),
          ('ldap_bind_password', ''),
          ('ldap_user_base', ''),
          ('ldap_user_filter', '(|(mail={login})(uid={login})(sAMAccountName={login}))'),
          ('ldap_email_attr', 'mail'),
          ('ldap_name_attr', 'displayName'),
          ('ldap_group_base', ''),
          ('ldap_group_filter', '(member={dn})'),
          ('ldap_use_memberof', 'true')
        ON CONFLICT (key) DO NOTHING
        """,
        """
        CREATE OR REPLACE FUNCTION api.is_global_admin() RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT COALESCE(
            (SELECT is_global_admin FROM private.users WHERE id = api.current_user_id()),
            false
          );
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION api.is_team_member(tid uuid) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT api.is_global_admin() OR EXISTS (
            SELECT 1 FROM api.team_members
            WHERE team_id = tid AND user_id = api.current_user_id()
          );
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION api.team_role(tid uuid) RETURNS text
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT CASE
            WHEN api.is_global_admin() THEN 'owner'
            ELSE (SELECT role FROM api.team_members
                  WHERE team_id = tid AND user_id = api.current_user_id())
          END;
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION api.can_read_project(pid uuid) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT api.is_global_admin() OR EXISTS (
            SELECT 1 FROM api.projects p
            JOIN api.team_members tm ON tm.team_id = p.team_id
            WHERE p.id = pid AND tm.user_id = api.current_user_id()
          ) OR EXISTS (
            SELECT 1 FROM api.project_members
            WHERE project_id = pid AND user_id = api.current_user_id()
          );
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION api.can_write_project(pid uuid) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT api.is_global_admin() OR EXISTS (
            SELECT 1 FROM api.projects p
            JOIN api.team_members tm ON tm.team_id = p.team_id
            WHERE p.id = pid AND tm.user_id = api.current_user_id()
          ) OR EXISTS (
            SELECT 1 FROM api.project_members
            WHERE project_id = pid AND user_id = api.current_user_id()
              AND role IN ('admin', 'write')
          );
        $$
        """,
        """
        ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS auth_source text NOT NULL DEFAULT 'local'
        """,
        """
        DO $$ BEGIN
          ALTER TABLE private.users ALTER COLUMN password_hash DROP NOT NULL;
        EXCEPTION WHEN others THEN NULL;
        END $$
        """,
        """
        CREATE OR REPLACE FUNCTION private.register_user(p_email text, p_password text, p_name text)
        RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
        DECLARE uid uuid;
        DECLARE first_user boolean;
        BEGIN
          SELECT NOT EXISTS (SELECT 1 FROM private.users) INTO first_user;
          INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source)
          VALUES (lower(p_email), crypt(p_password, gen_salt('bf')), COALESCE(p_name, ''), first_user, 'local')
          RETURNING id INTO uid;
          RETURN uid;
        END;
        $$
        """,
        "DROP FUNCTION IF EXISTS private.verify_user(text, text)",
        """
        CREATE OR REPLACE FUNCTION private.verify_user(p_email text, p_password text)
        RETURNS TABLE (id uuid, email text, name text, is_global_admin boolean)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
        BEGIN
          RETURN QUERY
          SELECT u.id, u.email, u.name, u.is_global_admin FROM private.users u
          WHERE u.email = lower(p_email)
            AND u.password_hash IS NOT NULL
            AND u.password_hash = crypt(p_password, u.password_hash);
        END;
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.verify_user TO authenticator",
        """
        CREATE OR REPLACE FUNCTION private.upsert_ldap_user(p_email text, p_name text)
        RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
        DECLARE uid uuid;
        DECLARE first_user boolean;
        BEGIN
          SELECT id INTO uid FROM private.users WHERE email = lower(p_email);
          IF uid IS NULL THEN
            SELECT NOT EXISTS (SELECT 1 FROM private.users) INTO first_user;
            INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source)
            VALUES (lower(p_email), NULL, COALESCE(p_name, ''), first_user, 'ldap')
            RETURNING id INTO uid;
          ELSE
            UPDATE private.users
            SET name = CASE WHEN COALESCE(p_name, '') <> '' THEN p_name ELSE name END,
                auth_source = 'ldap'
            WHERE id = uid;
          END IF;
          RETURN uid;
        END;
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.upsert_ldap_user TO authenticator",
        """
        CREATE TABLE IF NOT EXISTS private.ldap_role_maps (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          ldap_group text NOT NULL,
          role text NOT NULL CHECK (role IN ('global_admin')),
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (ldap_group)
        )
        """,
        """
        ALTER TABLE api.team_members
          ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'manual'
        """,
        """
        CREATE TABLE IF NOT EXISTS api.team_ldap_maps (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
          ldap_group text NOT NULL,
          role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (team_id, ldap_group)
        )
        """,
        "ALTER TABLE api.team_ldap_maps ENABLE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS tlm_select ON api.team_ldap_maps",
        """
        CREATE POLICY tlm_select ON api.team_ldap_maps FOR SELECT TO authenticated
          USING (api.is_team_member(team_id))
        """,
        "DROP POLICY IF EXISTS tlm_insert ON api.team_ldap_maps",
        """
        CREATE POLICY tlm_insert ON api.team_ldap_maps FOR INSERT TO authenticated
          WITH CHECK (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "DROP POLICY IF EXISTS tlm_update ON api.team_ldap_maps",
        """
        CREATE POLICY tlm_update ON api.team_ldap_maps FOR UPDATE TO authenticated
          USING (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "DROP POLICY IF EXISTS tlm_delete ON api.team_ldap_maps",
        """
        CREATE POLICY tlm_delete ON api.team_ldap_maps FOR DELETE TO authenticated
          USING (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_ldap_maps TO authenticated",
        "GRANT ALL ON api.team_ldap_maps TO authenticator",
        """
        CREATE OR REPLACE FUNCTION private.get_setting(p_key text)
        RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = private AS $$
          SELECT value FROM private.server_settings WHERE key = p_key;
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION private.set_setting(p_key text, p_value text)
        RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = private AS $$
          INSERT INTO private.server_settings (key, value) VALUES (p_key, p_value)
          ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION private.all_settings()
        RETURNS TABLE (key text, value text)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = private AS $$
          SELECT s.key, s.value FROM private.server_settings s ORDER BY s.key;
        $$
        """,
        "DROP VIEW IF EXISTS api.user_directory",
        """
        CREATE VIEW api.user_directory AS
          SELECT id, email, name, is_global_admin, created_at FROM private.users
        """,
        "GRANT SELECT ON api.user_directory TO authenticated",
        "GRANT ALL ON api.user_directory TO authenticator",
        "GRANT EXECUTE ON FUNCTION private.get_setting TO authenticator",
        "GRANT EXECUTE ON FUNCTION private.set_setting TO authenticator",
        "GRANT EXECUTE ON FUNCTION private.all_settings TO authenticator",
        "GRANT EXECUTE ON FUNCTION api.is_global_admin TO authenticated, anon",
        # teams SELECT for global admin (recreate policy safely)
        "DROP POLICY IF EXISTS teams_select ON api.teams",
        """
        CREATE POLICY teams_select ON api.teams FOR SELECT TO authenticated
          USING (api.is_global_admin() OR api.is_team_member(id))
        """,
        "DROP POLICY IF EXISTS teams_insert ON api.teams",
        """
        CREATE POLICY teams_insert ON api.teams FOR INSERT TO authenticated
          WITH CHECK (created_by = api.current_user_id() OR api.is_global_admin())
        """,
        # Soft-delete for secrets (trash + restore)
        """
        ALTER TABLE api.secrets
          ADD COLUMN IF NOT EXISTS deleted_at timestamptz
        """,
        """
        DO $$ BEGIN
          ALTER TABLE api.secrets DROP CONSTRAINT IF EXISTS secrets_project_id_key_key;
        EXCEPTION WHEN undefined_object THEN NULL;
        END $$
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS secrets_project_key_live
          ON api.secrets (project_id, key) WHERE deleted_at IS NULL
        """,
        """
        CREATE OR REPLACE FUNCTION private.machine_get_enc(p_project uuid, p_hash text, p_key text)
        RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = api AS $$
        BEGIN
          IF NOT private.auth_machine(p_project, p_hash) THEN
            RETURN NULL;
          END IF;
          RETURN (
            SELECT value_enc FROM api.secrets
            WHERE project_id = p_project AND key = p_key AND deleted_at IS NULL
          );
        END;
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION private.machine_list_enc(p_project uuid, p_hash text)
        RETURNS TABLE (key text, value_enc text)
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = api AS $$
        BEGIN
          IF NOT private.auth_machine(p_project, p_hash) THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.key, s.value_enc FROM api.secrets s
            WHERE s.project_id = p_project AND s.deleted_at IS NULL;
        END;
        $$
        """,
    ]
    try:
        with connect_admin(autocommit=True) as conn, conn.cursor() as cur:
            for sql in stmts:
                cur.execute(sql)
            # Bootstrap: first user, or GLOBAL_ADMIN_EMAIL
            cur.execute(
                """
                UPDATE private.users SET is_global_admin = true
                WHERE id = (SELECT id FROM private.users ORDER BY created_at ASC LIMIT 1)
                  AND NOT EXISTS (SELECT 1 FROM private.users WHERE is_global_admin)
                """
            )
            if GLOBAL_ADMIN_EMAIL:
                cur.execute(
                    "UPDATE private.users SET is_global_admin = true WHERE email = %s",
                    (GLOBAL_ADMIN_EMAIL,),
                )
        log.info("schema ensure complete")
    except Exception as e:
        log.warning("ensure_schema failed (db not ready?): %s", e)


_schema_ready = False


@app.before_request
def _bootstrap_schema():
    global _schema_ready
    if _schema_ready:
        return
    ensure_schema()
    _schema_ready = True


@app.post("/select-team")
@login_required
def select_team():
    tid = (request.form.get("team_id") or "").strip()
    session["team_id"] = tid or None
    nxt = request.form.get("next") or request.referrer or url_for("projects_list")
    # only allow relative redirects
    if not nxt.startswith("/"):
        nxt = url_for("projects_list")
    return redirect(nxt)


# ── Auth ──────────────────────────────────────────────────────────


@app.get("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("teams"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    ldap_on = _truthy(_ldap_cfg().get("ldap_enabled"))
    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"]
        user = None
        # 1) Local password accounts (break-glass / non-LDAP users)
        with connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM private.verify_user(%s, %s)", (email, password))
            user = cur.fetchone()
        # 2) LDAP when enabled and local auth failed
        if not user and ldap_on:
            ldap_user = ldap_authenticate(email, password)
            if ldap_user:
                try:
                    user = _sync_ldap_user(
                        ldap_user["email"],
                        ldap_user.get("name") or "",
                        ldap_user.get("groups") or [],
                    )
                except Exception as e:
                    log.exception("LDAP user sync failed")
                    flash(f"LDAP login succeeded but account sync failed: {e}", "error")
                    return render_template("login.html", ldap_enabled=ldap_on), 500
        if not user:
            flash("Invalid email or password", "error")
            return render_template("login.html", ldap_enabled=ldap_on), 401
        session["user_id"] = str(user["id"])
        session["email"] = user["email"]
        session["name"] = user["name"]
        session["is_global_admin"] = bool(user.get("is_global_admin"))
        session["jwt"] = make_jwt(user["id"])
        return redirect(url_for("teams"))
    return render_template("login.html", ldap_enabled=ldap_on)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"]
        name = request.form.get("name", "").strip()
        if len(password) < 8:
            flash("Password must be at least 8 characters", "error")
            return render_template("register.html"), 400
        try:
            with connect(autocommit=True) as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT private.register_user(%s, %s, %s) AS id",
                    (email, password, name),
                )
                uid = cur.fetchone()["id"]
        except psycopg.errors.UniqueViolation:
            flash("Email already registered", "error")
            return render_template("register.html"), 400
        except Exception as e:
            flash(str(e), "error")
            return render_template("register.html"), 400
        session["user_id"] = str(uid)
        session["email"] = email.lower()
        session["name"] = name
        session["is_global_admin"] = _is_global_admin(str(uid))
        session["jwt"] = make_jwt(uid)
        return redirect(url_for("teams"))
    return render_template("register.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Teams ─────────────────────────────────────────────────────────


@app.get("/teams")
@login_required
def teams():
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        if session.get("is_global_admin"):
            cur.execute(
                """
                SELECT t.*,
                  COALESCE(tm.role, 'owner') AS role,
                  (SELECT count(*) FROM api.projects p WHERE p.team_id = t.id) AS project_count
                FROM api.teams t
                LEFT JOIN api.team_members tm
                  ON tm.team_id = t.id AND tm.user_id = %s
                ORDER BY t.name
                """,
                (session["user_id"],),
            )
        else:
            cur.execute(
                """
                SELECT t.*, tm.role,
                  (SELECT count(*) FROM api.projects p WHERE p.team_id = t.id) AS project_count
                FROM api.teams t
                JOIN api.team_members tm ON tm.team_id = t.id
                WHERE tm.user_id = %s
                ORDER BY t.name
                """,
                (session["user_id"],),
            )
        rows = cur.fetchall()
    return render_template("teams.html", teams=rows)


@app.post("/teams")
@login_required
def create_team():
    name = request.form["name"].strip()
    if not name:
        flash("Name required", "error")
        return redirect(url_for("teams"))
    with connect(autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT private.create_team(%s::uuid, %s) AS id",
            (session["user_id"], name),
        )
        tid = cur.fetchone()["id"]
    session["team_id"] = str(tid)
    return redirect(url_for("team_detail", team_id=tid))


@app.get("/teams/<uuid:team_id>")
@login_required
def team_detail(team_id):
    session["team_id"] = str(team_id)
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM api.teams WHERE id = %s", (str(team_id),))
        team = cur.fetchone()
        if not team:
            return "Not found", 404
        cur.execute(
            """
            SELECT tm.role, tm.source, u.id AS user_id, u.email, u.name
            FROM api.team_members tm
            JOIN api.user_directory u ON u.id = tm.user_id
            WHERE tm.team_id = %s ORDER BY tm.role, u.email
            """,
            (str(team_id),),
        )
        members = cur.fetchall()
        cur.execute(
            "SELECT * FROM api.projects WHERE team_id = %s ORDER BY name",
            (str(team_id),),
        )
        projects = cur.fetchall()
        cur.execute(
            "SELECT role FROM api.team_members WHERE team_id = %s AND user_id = %s",
            (str(team_id), session["user_id"]),
        )
        my = cur.fetchone()
        my_role = my["role"] if my else None
        if session.get("is_global_admin") and not my_role:
            my_role = "owner"
        cur.execute(
            """
            SELECT id, ldap_group, role, created_at
            FROM api.team_ldap_maps
            WHERE team_id = %s
            ORDER BY ldap_group
            """,
            (str(team_id),),
        )
        ldap_maps = cur.fetchall()
    return render_template(
        "team.html",
        team=team,
        members=members,
        projects=projects,
        my_role=my_role,
        ldap_maps=ldap_maps,
        ldap_enabled=_truthy(_ldap_cfg().get("ldap_enabled")),
    )


@app.post("/teams/<uuid:team_id>/members")
@login_required
def add_team_member(team_id):
    email = request.form["email"].strip().lower()
    role = request.form.get("role", "member")
    if role not in _TEAM_ROLES:
        role = "member"
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM api.user_directory WHERE email = %s", (email,))
        u = cur.fetchone()
        if not u:
            flash("User not found — they must register or sign in via LDAP first", "error")
            return redirect(url_for("team_detail", team_id=team_id))
        try:
            cur.execute(
                """
                INSERT INTO api.team_members (team_id, user_id, role, source)
                VALUES (%s, %s, %s, 'manual')
                ON CONFLICT (team_id, user_id) DO UPDATE
                  SET role = EXCLUDED.role, source = 'manual'
                """,
                (str(team_id), str(u["id"]), role),
            )
            conn.commit()
        except Exception as e:
            flash(str(e), "error")
    return redirect(url_for("team_detail", team_id=team_id))


@app.post("/teams/<uuid:team_id>/ldap-maps")
@login_required
def add_team_ldap_map(team_id):
    ldap_group = (request.form.get("ldap_group") or "").strip()
    role = request.form.get("role", "member")
    if role not in _TEAM_ROLES:
        role = "member"
    if not ldap_group:
        flash("LDAP group required", "error")
        return redirect(url_for("team_detail", team_id=team_id))
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                """
                INSERT INTO api.team_ldap_maps (team_id, ldap_group, role)
                VALUES (%s, %s, %s)
                ON CONFLICT (team_id, ldap_group) DO UPDATE SET role = EXCLUDED.role
                """,
                (str(team_id), ldap_group, role),
            )
            conn.commit()
            flash("LDAP group mapping saved — applies on next LDAP login", "ok")
        except Exception as e:
            flash(str(e), "error")
    return redirect(url_for("team_detail", team_id=team_id))


@app.post("/teams/<uuid:team_id>/ldap-maps/<uuid:map_id>/delete")
@login_required
def delete_team_ldap_map(team_id, map_id):
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM api.team_ldap_maps WHERE id = %s AND team_id = %s",
            (str(map_id), str(team_id)),
        )
        conn.commit()
    return redirect(url_for("team_detail", team_id=team_id))


@app.post("/teams/<uuid:team_id>/projects")
@login_required
def create_project(team_id):
    name = request.form["name"].strip()
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                "INSERT INTO api.projects (team_id, name) VALUES (%s, %s) RETURNING id",
                (str(team_id), name),
            )
            pid = cur.fetchone()["id"]
            conn.commit()
        except Exception as e:
            flash(str(e), "error")
            return redirect(url_for("team_detail", team_id=team_id))
    return redirect(url_for("project_detail", project_id=pid))


# ── Projects / Secrets ─────────────────────────────────────────────


@app.get("/projects")
@login_required
def projects_list():
    tid = session.get("team_id")
    team, projects = None, []
    if tid:
        with as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
            team = cur.fetchone()
            if team:
                cur.execute(
                    "SELECT * FROM api.projects WHERE team_id = %s ORDER BY name",
                    (tid,),
                )
                projects = cur.fetchall()
    return render_template("projects.html", team=team, projects=projects)


@app.get("/secrets")
@login_required
def secrets_list():
    tid = session.get("team_id")
    team, secrets = None, []
    if tid:
        with as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
            team = cur.fetchone()
            if team:
                cur.execute(
                    """
                    SELECT s.id, s.key, s.note, s.updated_at,
                           p.id AS project_id, p.name AS project_name
                    FROM api.secrets s
                    JOIN api.projects p ON p.id = s.project_id
                    WHERE p.team_id = %s AND s.deleted_at IS NULL
                    ORDER BY p.name, s.key
                    """,
                    (tid,),
                )
                secrets = cur.fetchall()
    return render_template("secrets.html", team=team, secrets=secrets)


@app.get("/machines")
@login_required
def machines_list():
    tid = session.get("team_id")
    team, tokens = None, []
    if tid:
        with as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
            team = cur.fetchone()
            if team:
                cur.execute(
                    """
                    SELECT mt.id, mt.name, mt.token_prefix, mt.created_at,
                           p.id AS project_id, p.name AS project_name
                    FROM api.machine_tokens mt
                    JOIN api.projects p ON p.id = mt.project_id
                    WHERE p.team_id = %s
                    ORDER BY p.name, mt.name
                    """,
                    (tid,),
                )
                tokens = cur.fetchall()
    return render_template("machines.html", team=team, tokens=tokens)


@app.get("/trash")
@login_required
def trash():
    tid = session.get("team_id")
    team, items = None, []
    if tid:
        with as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
            team = cur.fetchone()
            if team:
                cur.execute(
                    """
                    SELECT s.id, s.key, s.note, s.deleted_at, s.project_id,
                           p.name AS project_name,
                           api.can_write_project(s.project_id) AS can_write
                    FROM api.secrets s
                    JOIN api.projects p ON p.id = s.project_id
                    WHERE p.team_id = %s AND s.deleted_at IS NOT NULL
                    ORDER BY s.deleted_at DESC
                    """,
                    (tid,),
                )
                items = cur.fetchall()
    return render_template("trash.html", team=team, items=items)


@app.post("/trash/secrets/<uuid:secret_id>/restore")
@login_required
def restore_secret(secret_id):
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                """
                UPDATE api.secrets
                SET deleted_at = NULL, updated_at = now()
                WHERE id = %s AND deleted_at IS NOT NULL
                  AND api.can_write_project(project_id)
                """,
                (str(secret_id),),
            )
            if cur.rowcount == 0:
                flash("Could not restore — missing permission or key already exists", "error")
            else:
                flash("Secret restored", "ok")
            conn.commit()
        except Exception as e:
            conn.rollback()
            flash(str(e), "error")
    return redirect(url_for("trash"))


@app.post("/trash/secrets/<uuid:secret_id>/purge")
@login_required
def purge_secret(secret_id):
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM api.secrets
            WHERE id = %s AND deleted_at IS NOT NULL
              AND api.can_write_project(project_id)
            """,
            (str(secret_id),),
        )
        conn.commit()
    return redirect(url_for("trash"))


@app.get("/projects/<uuid:project_id>")
@login_required
def project_detail(project_id):
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT p.*, t.name AS team_name, t.id AS team_id
            FROM api.projects p JOIN api.teams t ON t.id = p.team_id
            WHERE p.id = %s
            """,
            (str(project_id),),
        )
        project = cur.fetchone()
        if not project:
            return "Not found", 404
        session["team_id"] = str(project["team_id"])
        cur.execute(
            """
            SELECT id, key, note, created_at, updated_at FROM api.secrets
            WHERE project_id = %s AND deleted_at IS NULL
            ORDER BY key
            """,
            (str(project_id),),
        )
        secret_rows = cur.fetchall()
        cur.execute(
            "SELECT id, name, token_prefix, created_at FROM api.machine_tokens WHERE project_id = %s ORDER BY created_at DESC",
            (str(project_id),),
        )
        tokens = cur.fetchall()
        can_write = False
        cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
        can_write = cur.fetchone()["w"]
    return render_template(
        "project.html",
        project=project,
        project_id=project_id,
        secrets=secret_rows,
        tokens=tokens,
        can_write=can_write,
        new_token=session.pop("new_token", None),
    )


@app.post("/projects/<uuid:project_id>/secrets")
@login_required
def create_secret(project_id):
    key = request.form["key"].strip()
    value = request.form["value"]
    note = request.form.get("note", "").strip()
    if not key or value is None:
        flash("Key and value required", "error")
        return redirect(url_for("project_detail", project_id=project_id))
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                """
                INSERT INTO api.secrets (project_id, key, value_enc, note)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
                  SET value_enc = EXCLUDED.value_enc, note = EXCLUDED.note, updated_at = now()
                """,
                (str(project_id), key, encrypt(value), note),
            )
            conn.commit()
        except Exception as e:
            flash(str(e), "error")
    if htmx():
        return _secrets_partial(project_id)
    return redirect(url_for("project_detail", project_id=project_id))


@app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/delete")
@login_required
def delete_secret(project_id, secret_id):
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE api.secrets SET deleted_at = now()
            WHERE id = %s AND project_id = %s AND deleted_at IS NULL
            """,
            (str(secret_id), str(project_id)),
        )
        conn.commit()
    if htmx():
        return _secrets_partial(project_id)
    return redirect(url_for("project_detail", project_id=project_id))


@app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/reveal")
@login_required
def reveal_secret(project_id, secret_id):
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT value_enc FROM api.secrets
            WHERE id = %s AND project_id = %s AND deleted_at IS NULL
            """,
            (str(secret_id), str(project_id)),
        )
        row = cur.fetchone()
        if not row:
            return "Not found", 404
    return render_template(
        "partials/reveal.html",
        value=decrypt(row["value_enc"]),
        secret_id=secret_id,
        project_id=project_id,
    )


def _secrets_partial(project_id):
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, key, note, created_at, updated_at FROM api.secrets
            WHERE project_id = %s AND deleted_at IS NULL
            ORDER BY key
            """,
            (str(project_id),),
        )
        rows = cur.fetchall()
        cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
        can_write = cur.fetchone()["w"]
    return render_template(
        "partials/secrets.html",
        secrets=rows,
        project_id=project_id,
        can_write=can_write,
    )


@app.post("/projects/<uuid:project_id>/tokens")
@login_required
def create_token(project_id):
    name = request.form.get("name", "machine").strip() or "machine"
    raw = "ss_" + secrets.token_urlsafe(32)
    thash = hashlib.sha256(raw.encode()).hexdigest()
    prefix = raw[:11]
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                """
                INSERT INTO api.machine_tokens (project_id, name, token_hash, token_prefix)
                VALUES (%s, %s, %s, %s)
                """,
                (str(project_id), name, thash, prefix),
            )
            conn.commit()
        except Exception as e:
            flash(str(e), "error")
            return redirect(url_for("project_detail", project_id=project_id))
    session["new_token"] = raw  # shown once
    return redirect(url_for("project_detail", project_id=project_id))


@app.post("/projects/<uuid:project_id>/tokens/<uuid:token_id>/delete")
@login_required
def delete_token(project_id, token_id):
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM api.machine_tokens WHERE id = %s AND project_id = %s",
            (str(token_id), str(project_id)),
        )
        conn.commit()
    return redirect(url_for("project_detail", project_id=project_id))


# ── Server settings (global admin only) ────────────────────────────


@app.route("/settings", methods=["GET", "POST"])
@global_admin_required
def server_settings():
    if request.method == "POST":
        action = request.form.get("action") or "classification"
        if action == "classification":
            text = (request.form.get("classification_text") or "").strip()[:120]
            color = (request.form.get("classification_color") or "").strip()
            fg = (request.form.get("classification_fg") or "").strip()
            enabled = "true" if request.form.get("classification_enabled") else "false"
            if not _HEX.match(color):
                flash("Banner colour must be a hex value like #677381", "error")
            elif not _HEX.match(fg):
                flash("Text colour must be a hex value like #ffffff", "error")
            else:
                _set_setting("classification_enabled", enabled)
                _set_setting("classification_text", text)
                _set_setting("classification_color", color)
                _set_setting("classification_fg", fg)
                flash("Classification banner saved", "ok")
        elif action == "ldap":
            enabled = "true" if request.form.get("ldap_enabled") else "false"
            _set_setting("ldap_enabled", enabled)
            _set_setting("ldap_url", (request.form.get("ldap_url") or "").strip())
            _set_setting(
                "ldap_start_tls",
                "true" if request.form.get("ldap_start_tls") else "false",
            )
            _set_setting("ldap_bind_dn", (request.form.get("ldap_bind_dn") or "").strip())
            new_pw = request.form.get("ldap_bind_password") or ""
            if new_pw.strip():
                _set_setting("ldap_bind_password", encrypt(new_pw.strip()))
            _set_setting("ldap_user_base", (request.form.get("ldap_user_base") or "").strip())
            filt = (request.form.get("ldap_user_filter") or "").strip()
            _set_setting(
                "ldap_user_filter",
                filt or _DEFAULT_SETTINGS["ldap_user_filter"],
            )
            _set_setting(
                "ldap_email_attr",
                (request.form.get("ldap_email_attr") or "mail").strip() or "mail",
            )
            _set_setting(
                "ldap_name_attr",
                (request.form.get("ldap_name_attr") or "displayName").strip()
                or "displayName",
            )
            _set_setting("ldap_group_base", (request.form.get("ldap_group_base") or "").strip())
            gfilt = (request.form.get("ldap_group_filter") or "").strip()
            _set_setting(
                "ldap_group_filter",
                gfilt or _DEFAULT_SETTINGS["ldap_group_filter"],
            )
            _set_setting(
                "ldap_use_memberof",
                "true" if request.form.get("ldap_use_memberof") else "false",
            )
            flash("LDAP settings saved", "ok")
        elif action == "ldap_role_map_add":
            ldap_group = (request.form.get("ldap_group") or "").strip()
            role = (request.form.get("role") or "global_admin").strip()
            if role != "global_admin":
                flash("Unsupported role for LDAP map", "error")
            elif not ldap_group:
                flash("LDAP group required", "error")
            else:
                with connect_admin() as conn, conn.cursor() as cur:
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
                    except Exception as e:
                        flash(str(e), "error")
        elif action == "ldap_role_map_delete":
            mid = (request.form.get("map_id") or "").strip()
            with connect_admin() as conn, conn.cursor() as cur:
                cur.execute("DELETE FROM private.ldap_role_maps WHERE id = %s::uuid", (mid,))
            flash("LDAP role mapping removed", "ok")
        elif action == "promote":
            email = (request.form.get("email") or "").strip().lower()
            if not email:
                flash("Email required", "error")
            else:
                with connect_admin() as conn, conn.cursor() as cur:
                    cur.execute(
                        "UPDATE private.users SET is_global_admin = true WHERE email = %s RETURNING id",
                        (email,),
                    )
                    row = cur.fetchone()
                if row:
                    flash(f"Promoted {email} to global admin", "ok")
                else:
                    flash("User not found — they must register or sign in via LDAP first", "error")
        elif action == "demote":
            uid = (request.form.get("user_id") or "").strip()
            if uid == session.get("user_id"):
                flash("You cannot remove your own global admin role", "error")
            else:
                with connect_admin() as conn, conn.cursor() as cur:
                    cur.execute(
                        "UPDATE private.users SET is_global_admin = false WHERE id = %s::uuid",
                        (uid,),
                    )
                flash("Global admin removed", "ok")
        return redirect(url_for("server_settings"))

    settings = _get_settings()
    # never show raw bind password in the form
    settings = dict(settings)
    settings["ldap_bind_password_set"] = bool((settings.get("ldap_bind_password") or "").strip())
    settings["ldap_bind_password"] = ""
    with connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, email, name, is_global_admin, auth_source, created_at
            FROM private.users
            ORDER BY is_global_admin DESC, email
            """
        )
        users = cur.fetchall()
        cur.execute(
            "SELECT id, ldap_group, role, created_at FROM private.ldap_role_maps ORDER BY ldap_group"
        )
        ldap_role_maps = cur.fetchall()
    return render_template(
        "settings.html",
        settings=settings,
        users=users,
        ldap_role_maps=ldap_role_maps,
        classification=_classification(),
    )


# ── PostgREST JWT helper ──────────────────────────────────────────


@app.get("/api/token")
@login_required
def api_token():
    """Return JWT for PostgREST (Authorization: Bearer ...)."""
    return jsonify(
        {
            "access_token": make_jwt(session["user_id"]),
            "token_type": "bearer",
            "postgrest": POSTGREST_URL,
        }
    )


# ── OpenShift External Secrets Operator (webhook provider) ─────────


def _bearer_hash():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return hashlib.sha256(auth[7:].strip().encode()).hexdigest()


@app.get("/eso/v1/projects/<uuid:project_id>/secrets/<path:key>")
def eso_get_secret(project_id, key):
    """ESO webhook: single secret. jsonPath: $.value"""
    thash = _bearer_hash()
    if not thash:
        return jsonify({"error": "unauthorized"}), 401
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT private.machine_get_enc(%s::uuid, %s, %s) AS value_enc",
            (str(project_id), thash, key),
        )
        row = cur.fetchone()
    if not row or not row["value_enc"]:
        # distinguish auth fail vs missing key
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT private.auth_machine(%s::uuid, %s) AS ok",
                (str(project_id), thash),
            )
            if not cur.fetchone()["ok"]:
                return jsonify({"error": "unauthorized"}), 401
        return jsonify({"error": "not found"}), 404
    return jsonify({"value": decrypt(row["value_enc"]), "key": key})


@app.get("/eso/v1/projects/<uuid:project_id>/secrets")
def eso_list_secrets(project_id):
    """All secrets as {key: value} map for bulk sync."""
    thash = _bearer_hash()
    if not thash:
        return jsonify({"error": "unauthorized"}), 401
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT private.auth_machine(%s::uuid, %s) AS ok",
            (str(project_id), thash),
        )
        if not cur.fetchone()["ok"]:
            return jsonify({"error": "unauthorized"}), 401
        cur.execute(
            "SELECT * FROM private.machine_list_enc(%s::uuid, %s)",
            (str(project_id), thash),
        )
        rows = cur.fetchall()
    data = {r["key"]: decrypt(r["value_enc"]) for r in rows}
    return jsonify({"secrets": data})


@app.get("/health")
def health():
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 503


if __name__ == "__main__":
    # ponytail: one self-check for crypto round-trip
    assert decrypt(encrypt("ping")) == "ping"
    app.run(host="0.0.0.0", port=8080, debug=True)
