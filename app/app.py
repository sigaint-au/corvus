"""Secret store: Flask+HTMX UI, PostgREST JWT, OpenShift ESO webhook API."""
import hashlib
import os
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
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-jwt-secret-change-me-32chars!!")
MASTER_KEY = os.environ.get("MASTER_KEY", "dev-master-key-change-in-prod!!")
POSTGREST_URL = os.environ.get("POSTGREST_URL", "http://localhost:3000")


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


def htmx():
    return request.headers.get("HX-Request") == "true"


def _nav_teams(user_id: str):
    with as_user(user_id) as conn, conn.cursor() as cur:
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
    if not session.get("user_id"):
        return {"nav_teams": [], "nav_team_id": None}
    try:
        teams = _nav_teams(session["user_id"])
    except Exception:
        teams = []
    return {"nav_teams": teams, "nav_team_id": _active_team_id(teams)}


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
    return render_template(
        "team.html",
        team=team,
        members=members,
        projects=projects,
        my_role=my["role"] if my else None,
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
                    WHERE p.team_id = %s
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
    # ponytail: hard-delete only today; soft-delete + restore when needed
    return render_template("trash.html")


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
            "SELECT id, key, note, created_at, updated_at FROM api.secrets WHERE project_id = %s ORDER BY key",
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
                ON CONFLICT (project_id, key) DO UPDATE
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
            "DELETE FROM api.secrets WHERE id = %s AND project_id = %s",
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
            "SELECT value_enc FROM api.secrets WHERE id = %s AND project_id = %s",
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
            "SELECT id, key, note, created_at, updated_at FROM api.secrets WHERE project_id = %s ORDER BY key",
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
