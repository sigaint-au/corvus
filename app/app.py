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
}


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
          ('classification_fg', '#ffffff')
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
        CREATE OR REPLACE FUNCTION private.register_user(p_email text, p_password text, p_name text)
        RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
        DECLARE uid uuid;
        DECLARE first_user boolean;
        BEGIN
          SELECT NOT EXISTS (SELECT 1 FROM private.users) INTO first_user;
          INSERT INTO private.users (email, password_hash, name, is_global_admin)
          VALUES (lower(p_email), crypt(p_password, gen_salt('bf')), COALESCE(p_name, ''), first_user)
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
          WHERE u.email = lower(p_email) AND u.password_hash = crypt(p_password, u.password_hash);
        END;
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.verify_user TO authenticator",
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
    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"]
        with connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM private.verify_user(%s, %s)", (email, password))
            user = cur.fetchone()
        if not user:
            flash("Invalid email or password", "error")
            return render_template("login.html"), 401
        session["user_id"] = str(user["id"])
        session["email"] = user["email"]
        session["name"] = user["name"]
        session["is_global_admin"] = bool(user.get("is_global_admin"))
        session["jwt"] = make_jwt(user["id"])
        return redirect(url_for("teams"))
    return render_template("login.html")


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
            SELECT tm.role, u.id AS user_id, u.email, u.name
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
    return render_template(
        "team.html",
        team=team,
        members=members,
        projects=projects,
        my_role=my_role,
    )


@app.post("/teams/<uuid:team_id>/members")
@login_required
def add_team_member(team_id):
    email = request.form["email"].strip().lower()
    role = request.form.get("role", "member")
    with as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM api.user_directory WHERE email = %s", (email,))
        u = cur.fetchone()
        if not u:
            flash("User not found — they must register first", "error")
            return redirect(url_for("team_detail", team_id=team_id))
        try:
            cur.execute(
                "INSERT INTO api.team_members (team_id, user_id, role) VALUES (%s, %s, %s)",
                (str(team_id), str(u["id"]), role),
            )
            conn.commit()
        except Exception as e:
            flash(str(e), "error")
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
                    flash("User not found — they must register first", "error")
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
    with connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, email, name, is_global_admin, created_at
            FROM private.users
            ORDER BY is_global_admin DESC, email
            """
        )
        users = cur.fetchall()
    return render_template(
        "settings.html",
        settings=settings,
        users=users,
        classification=_classification(),
    )


# ── PostgREST JWT helper ──────────────────────────────────────────


@app.get("/api/token")
@login_required
def api_token():
    """Return JWT for PostgREST (Authorization: Bearer …)."""
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
