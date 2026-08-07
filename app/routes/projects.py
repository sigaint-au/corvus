"""Projects, secrets, machine tokens, trash."""

import csv
import hashlib
import io
import json
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import (
    Response,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import audit
import authz
import config
import crypto
import db
import paging
import pins

log = logging.getLogger(__name__)

_SOON_DAYS = 14
_ENV_LINE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$"
)
_KV_LINE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$"
)
_PEM_BLOCK = re.compile(
    r"(-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----)",
    re.DOTALL,
)
_DB_URL = re.compile(
    r"^(?P<scheme>postgresql|postgres|mysql|mongodb|redis|amqp|http|https)://",
    re.I,
)
# Kinds that open a dedicated view window instead of inline reveal
_STRUCTURED_VIEW_KINDS = frozenset({"kv", "certificate", "ssh", "database"})


def detect_secret_kind(value: str, note: str = "") -> str:
    """Infer secret shape from note tag and/or value content."""
    note_l = (note or "").lower()
    for kind in ("certificate", "kv", "ssh", "database", "plain"):
        if f"type:{kind}" in note_l:
            return kind
    v = value or ""
    if "BEGIN CERTIFICATE" in v:
        return "certificate"
    if re.search(
        r"BEGIN (?:OPENSSH |RSA |EC |DSA |ED25519 )?PRIVATE KEY",
        v,
    ):
        return "ssh"
    stripped = v.strip()
    if stripped and _DB_URL.match(stripped) and "\n" not in stripped:
        return "database"
    lines = [
        ln.strip()
        for ln in v.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if len(lines) >= 2 and sum(1 for ln in lines if _KV_LINE.match(ln)) >= 2:
        return "kv"
    if len(lines) == 1 and _KV_LINE.match(lines[0]) and "\n" in v:
        return "kv"
    return "plain"


def parse_kv_lines(value: str) -> list[tuple[str, str]]:
    """Parse KEY=value lines into pairs (keeps empty values)."""
    pairs: list[tuple[str, str]] = []
    for line in (value or "").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        m = _KV_LINE.match(raw)
        if m:
            pairs.append((m.group(1), m.group(2)))
        elif "=" in raw:
            k, _, rest = raw.partition("=")
            pairs.append((k.strip(), rest))
    return pairs


def parse_pem_blocks(value: str) -> list[dict]:
    """Split PEM material into labeled blocks for display."""
    blocks = []
    for m in _PEM_BLOCK.finditer(value or ""):
        block = m.group(1).strip()
        header = block.splitlines()[0] if block else ""
        label = header.replace("-----BEGIN ", "").replace("-----", "").strip().title()
        if "CERTIFICATE" in header.upper():
            kind = "certificate"
        elif "PRIVATE KEY" in header.upper() or "OPENSSH" in header.upper():
            kind = "private_key"
        else:
            kind = "pem"
        blocks.append({"label": label or "PEM", "kind": kind, "text": block})
    if not blocks and (value or "").strip():
        blocks.append(
            {"label": "Value", "kind": "text", "text": (value or "").strip()}
        )
    return blocks


def parse_database_url(value: str) -> dict:
    """Break a DB URL into display fields (password kept separate)."""
    from urllib.parse import unquote, urlparse

    raw = (value or "").strip()
    try:
        u = urlparse(raw)
    except Exception:
        return {"raw": raw}
    return {
        "raw": raw,
        "scheme": u.scheme or "",
        "user": unquote(u.username) if u.username else "",
        "password": unquote(u.password) if u.password else "",
        "host": u.hostname or "",
        "port": str(u.port) if u.port else "",
        "database": (u.path or "").lstrip("/"),
        "query": u.query or "",
    }


def note_with_kind(note: str, kind_label: str) -> str:
    """Ensure non-plain secrets keep a type: tag for later reveal detection."""
    kind_label = (kind_label or "plain").strip().lower()
    note = note_without_kind(note)
    if kind_label == "plain":
        return note
    tag = f"type:{kind_label}"
    return f"{note} ({tag})".strip() if note else tag


def note_without_kind(note: str) -> str:
    """Strip type: tags so the user-facing note field stays clean."""
    note = (note or "").strip()
    note = re.sub(r"\s*\(\s*type:[a-z]+\s*\)\s*", " ", note, flags=re.I)
    note = re.sub(r"\btype:[a-z]+\b", "", note, flags=re.I)
    return re.sub(r"\s{2,}", " ", note).strip(" -|,")


def split_cert_and_key(value: str) -> tuple[str, str]:
    """Pull certificate and private key PEM blocks out of a combined value."""
    cert = ""
    key = ""
    for block in parse_pem_blocks(value):
        if block["kind"] == "certificate" and not cert:
            cert = block["text"]
        elif block["kind"] == "private_key" and not key:
            key = block["text"]
    if not cert and not key and (value or "").strip():
        # Single non-PEM blob — treat as cert field for editing
        cert = (value or "").strip()
    return cert, key


def _as_utc(dt):
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def expires_status(expires_at, soon_days=_SOON_DAYS):
    """Return 'overdue', 'soon', or None for a single expiry timestamp."""
    due = _as_utc(expires_at)
    if due is None:
        return None
    now = datetime.now(timezone.utc)
    if due <= now:
        return "overdue"
    if due <= now + timedelta(days=soon_days):
        return "soon"
    return None


def secret_due_status(row, soon_days=_SOON_DAYS):
    """Return 'overdue', 'soon', or None from expires_at."""
    return expires_status(row.get("expires_at"), soon_days=soon_days)


def _annotate_token_expiry(rows):
    for r in rows:
        r["due"] = expires_status(r.get("expires_at"))
    return rows


def parse_secret_pairs(text: str) -> list[tuple[str, str]]:
    """Parse .env, JSON object/list, or CSV (key,value) into (key, value) pairs."""
    text = (text or "").strip()
    if not text:
        return []
    # JSON
    if text[0] in "{[":
        data = json.loads(text)
        if isinstance(data, dict):
            out = []
            for k, v in data.items():
                if isinstance(v, dict) and "value" in v:
                    out.append((str(k), str(v["value"])))
                elif isinstance(v, dict) and "value_enc" in v:
                    out.append((str(k), {"_enc": v["value_enc"], "note": v.get("note", "")}))
                else:
                    out.append((str(k), "" if v is None else str(v)))
            return out
        if isinstance(data, list):
            out = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                k = item.get("key") or item.get("name")
                if not k:
                    continue
                if "value_enc" in item and "value" not in item:
                    out.append((str(k), {"_enc": item["value_enc"], "note": item.get("note", "")}))
                else:
                    out.append((str(k), "" if item.get("value") is None else str(item.get("value"))))
            return out
        raise ValueError("JSON must be object or array of {key,value}")
    # CSV with header key,value
    first = text.splitlines()[0].lower()
    if "key" in first and "value" in first and ("," in first or "\t" in first):
        delim = "\t" if "\t" in first and first.count("\t") >= first.count(",") else ","
        reader = csv.DictReader(io.StringIO(text), delimiter=delim)
        out = []
        for row in reader:
            k = (row.get("key") or row.get("KEY") or "").strip()
            if k:
                out.append((k, row.get("value") or row.get("VALUE") or ""))
        return out
    # .env
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _ENV_LINE.match(line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out.append((k, v))
    return out


def _load_secrets_page(cur, project_id, page, q):
    """Count + page live secrets for a project. Returns (rows, pager)."""
    where = "project_id = %s AND deleted_at IS NULL"
    params = [str(project_id)]
    if q:
        where += " AND (key ILIKE %s OR note ILIKE %s)"
        like = f"%{q}%"
        params.extend([like, like])
    cur.execute(f"SELECT count(*) AS n FROM api.secrets WHERE {where}", params)
    total = int((cur.fetchone() or {}).get("n") or 0)
    pager = paging.page_window(total, page)
    pager.update(
        endpoint="project_detail",
        project_id=project_id,
        tab="secrets",
        q=q,
    )
    cur.execute(
        f"""
        SELECT id, key, note, created_at, updated_at, expires_at
        FROM api.secrets
        WHERE {where}
        ORDER BY key
        LIMIT %s OFFSET %s
        """,
        (*params, pager["limit"], pager["offset"]),
    )
    rows = cur.fetchall()
    # Mark favorites for this page (single query)
    ids = [str(r["id"]) for r in rows]
    pinned = set()
    if ids:
        cur.execute(
            """
            SELECT secret_id FROM api.secret_pins
            WHERE user_id = api.current_user_id()
              AND secret_id = ANY(%s::uuid[])
            """,
            (ids,),
        )
        pinned = {str(x["secret_id"]) for x in (cur.fetchall() or [])}
    for r in rows:
        r["due"] = secret_due_status(r)
        r["is_pinned"] = str(r["id"]) in pinned
    return rows, pager


def _parse_expires_at(form, *, allow_clear: bool = True):
    """
    Return expires_at datetime or None from form (capped at MAX_EXPIRY_DAYS).
    Empty / clear_expires → None (no expiry).
    """
    if allow_clear and form.get("clear_expires") in ("1", "true", "on", "yes"):
        return None
    raw = (form.get("expires_at") or "").strip()
    if not raw:
        return None
    try:
        expires_at = datetime.fromisoformat(raw)
    except ValueError:
        raise ValueError("expires_at must be YYYY-MM-DD or ISO datetime")
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    cap = datetime.now(timezone.utc) + timedelta(days=config.MAX_EXPIRY_DAYS)
    if expires_at > cap:
        raise ValueError(f"expires_at must be within {config.MAX_EXPIRY_DAYS} days")
    return expires_at


def _upsert_secret(
    cur,
    project_id,
    key,
    value_or_enc,
    note="",
    expires_at=None,
    *,
    already_enc=False,
    touch_meta=True,
):
    """Insert/update one secret; returns (id, was_new)."""
    enc = value_or_enc if already_enc else crypto.encrypt(str(value_or_enc))
    cur.execute(
        """
        SELECT id FROM api.secrets
        WHERE project_id = %s AND key = %s AND deleted_at IS NULL
        """,
        (str(project_id), key),
    )
    existing = cur.fetchone()
    if touch_meta:
        cur.execute(
            """
            INSERT INTO api.secrets
              (project_id, key, value_enc, note, expires_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
              SET value_enc = EXCLUDED.value_enc,
                  note = EXCLUDED.note,
                  expires_at = EXCLUDED.expires_at
            RETURNING id
            """,
            (str(project_id), key, enc, note or "", expires_at),
        )
    else:
        cur.execute(
            """
            INSERT INTO api.secrets (project_id, key, value_enc, note)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
              SET value_enc = EXCLUDED.value_enc,
                  note = CASE WHEN EXCLUDED.note = '' THEN api.secrets.note
                              ELSE EXCLUDED.note END
            RETURNING id
            """,
            (str(project_id), key, enc, note or ""),
        )
    row = cur.fetchone()
    return (row["id"] if row else None), (existing is None)


def register(app):
    # ── Projects / Secrets ─────────────────────────────────────────────


    @app.get("/search")
    @authz.login_required
    def global_search():
        """Search teams, projects, and secrets the user can access."""
        q = (request.args.get("q") or "").strip()
        teams, projects, secrets = [], [], []
        if q:
            like = f"%{q}%"
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, name FROM api.teams
                    WHERE name ILIKE %s
                    ORDER BY name
                    LIMIT 25
                    """,
                    (like,),
                )
                teams = cur.fetchall()
                cur.execute(
                    """
                    SELECT p.id, p.name, t.name AS team_name, t.id AS team_id
                    FROM api.projects p
                    JOIN api.teams t ON t.id = p.team_id
                    WHERE p.name ILIKE %s
                    ORDER BY t.name, p.name
                    LIMIT 40
                    """,
                    (like,),
                )
                projects = cur.fetchall()
                cur.execute(
                    """
                    SELECT s.id, s.key, s.note, s.project_id,
                           p.name AS project_name, t.name AS team_name
                    FROM api.secrets s
                    JOIN api.projects p ON p.id = s.project_id
                    JOIN api.teams t ON t.id = p.team_id
                    WHERE s.deleted_at IS NULL
                      AND (s.key ILIKE %s OR s.note ILIKE %s OR p.name ILIKE %s)
                    ORDER BY t.name, p.name, s.key
                    LIMIT 50
                    """,
                    (like, like, like),
                )
                secrets = cur.fetchall()
        return render_template(
            "search.html",
            search_q=q,
            teams=teams,
            projects=projects,
            secrets=secrets,
        )


    @app.get("/projects")
    @authz.login_required
    def projects_list():
        tid = session.get("team_id")
        team, projects = None, []
        if tid:
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
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
    @authz.login_required
    def secrets_list():
        tid = session.get("team_id")
        q = (request.args.get("q") or "").strip()
        team, secrets = None, []
        if tid:
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
                team = cur.fetchone()
                if team:
                    sql = """
                        SELECT s.id, s.key, s.note, s.updated_at,
                               p.id AS project_id, p.name AS project_name
                        FROM api.secrets s
                        JOIN api.projects p ON p.id = s.project_id
                        WHERE p.team_id = %s AND s.deleted_at IS NULL
                    """
                    params = [tid]
                    if q:
                        like = f"%{q}%"
                        sql += " AND (s.key ILIKE %s OR s.note ILIKE %s OR p.name ILIKE %s)"
                        params.extend([like, like, like])
                    cur.execute(sql + " ORDER BY p.name, s.key", params)
                    secrets = cur.fetchall()
        return render_template("secrets.html", team=team, secrets=secrets, search_q=q)


    @app.get("/machines")
    @authz.login_required
    def machines_list():
        tid = session.get("team_id")
        team, tokens = None, []
        if tid:
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
                team = cur.fetchone()
                if team:
                    cur.execute(
                        """
                        SELECT mt.id, mt.name, mt.token_prefix, mt.role,
                               mt.created_at, mt.expires_at,
                               p.id AS project_id, p.name AS project_name
                        FROM api.machine_tokens mt
                        JOIN api.projects p ON p.id = mt.project_id
                        WHERE p.team_id = %s
                        ORDER BY p.name, mt.name
                        """,
                        (tid,),
                    )
                    tokens = _annotate_token_expiry(cur.fetchall())
        return render_template("machines.html", team=team, tokens=tokens)


    @app.get("/trash")
    @authz.login_required
    def trash():
        tid = session.get("team_id")
        team, items = None, []
        q = (request.args.get("q") or "").strip()
        if tid:
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
                team = cur.fetchone()
                if team:
                    if q:
                        like = f"%{q}%"
                        cur.execute(
                            """
                            SELECT s.id, s.key, s.note, s.deleted_at, s.project_id,
                                   p.name AS project_name,
                                   api.can_write_project(s.project_id) AS can_write
                            FROM api.secrets s
                            JOIN api.projects p ON p.id = s.project_id
                            WHERE p.team_id = %s AND s.deleted_at IS NOT NULL
                              AND (
                                s.key ILIKE %s OR s.note ILIKE %s
                                OR p.name ILIKE %s
                              )
                            ORDER BY s.deleted_at DESC
                            """,
                            (tid, like, like, like),
                        )
                    else:
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
        return render_template(
            "trash.html", team=team, items=items, search_q=q
        )


    @app.post("/trash/secrets/<uuid:secret_id>/restore")
    @authz.login_required
    def restore_secret(secret_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    SELECT id, project_id, key FROM api.secrets
                    WHERE id = %s AND deleted_at IS NOT NULL
                      AND api.can_write_project(project_id)
                    """,
                    (str(secret_id),),
                )
                row = cur.fetchone()
                if not row:
                    flash("Could not restore — missing permission or key already exists", "error")
                    conn.commit()
                    return redirect(url_for("trash", q=request.args.get("q") or None))
                cur.execute(
                    """
                    UPDATE api.secrets
                    SET deleted_at = NULL
                    WHERE id = %s AND deleted_at IS NOT NULL
                    """,
                    (str(secret_id),),
                )
                if cur.rowcount == 0:
                    flash("Could not restore — missing permission or key already exists", "error")
                else:
                    audit.log_secret(
                        cur,
                        project_id=row["project_id"],
                        secret_id=row["id"],
                        secret_key=row["key"],
                        action="restored",
                    )
                    flash("Secret restored", "ok")
                conn.commit()
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("trash", q=request.args.get("q") or None))


    @app.post("/trash/secrets/<uuid:secret_id>/purge")
    @authz.login_required
    def purge_secret(secret_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, project_id, key FROM api.secrets
                WHERE id = %s AND deleted_at IS NOT NULL
                  AND api.can_write_project(project_id)
                """,
                (str(secret_id),),
            )
            row = cur.fetchone()
            if row:
                audit.log_secret(
                    cur,
                    project_id=row["project_id"],
                    secret_id=row["id"],
                    secret_key=row["key"],
                    action="purged",
                )
                cur.execute(
                    """
                    DELETE FROM api.secrets
                    WHERE id = %s AND deleted_at IS NOT NULL
                    """,
                    (str(secret_id),),
                )
            conn.commit()
        return redirect(url_for("trash", q=request.args.get("q") or None))


    @app.get("/projects/<uuid:project_id>")
    @authz.login_required
    def project_detail(project_id):
        tab = (request.args.get("tab") or "secrets").strip().lower()
        if tab not in ("secrets", "audit", "tokens", "import", "settings"):
            tab = "secrets"
        page = paging.page_arg("page")
        q = paging.list_state_q()
        audit_actor = (request.args.get("actor") or "").strip()
        audit_action = (request.args.get("action") or "").strip()
        audit_since = (request.args.get("since") or "").strip()
        audit_until = (request.args.get("until") or "").strip()
        secrets_pager = None
        audit_pager = None
        secret_rows = []
        audit_rows = []
        tokens = []
        project_members = []
        default_token_days = None
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT p.*, t.name AS team_name, t.id AS team_id,
                       t.default_token_days
                FROM api.projects p JOIN api.teams t ON t.id = p.team_id
                WHERE p.id = %s
                """,
                (str(project_id),),
            )
            project = cur.fetchone()
            if not project:
                return "Not found", 404
            session["team_id"] = str(project["team_id"])
            default_token_days = project.get("default_token_days")
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = cur.fetchone()["w"]
            cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
            can_admin = cur.fetchone()["a"]
            cur.execute("SELECT api.team_role(%s) AS r", (str(project["team_id"]),))
            team_role = (cur.fetchone() or {}).get("r")
            # Project delete: team owner/admin (matches projects_delete RLS)
            can_delete = team_role in ("owner", "admin")
            # Settings: project admins manage members; team owner/admin also see danger zone
            can_settings = bool(can_admin or can_delete)

            if tab == "settings" and not can_settings:
                tab = "secrets"
            due_overdue, due_soon = [], []
            if tab == "secrets":
                secret_rows, secrets_pager = _load_secrets_page(cur, project_id, page, q)
                # Expiry dashboard: scan live secrets for this project (capped)
                cur.execute(
                    """
                    SELECT id, key, expires_at FROM api.secrets
                    WHERE project_id = %s AND deleted_at IS NULL
                      AND expires_at IS NOT NULL
                    ORDER BY expires_at
                    LIMIT 200
                    """,
                    (str(project_id),),
                )
                for r in cur.fetchall() or []:
                    st = secret_due_status(r)
                    if st == "overdue":
                        due_overdue.append(r)
                    elif st == "soon":
                        due_soon.append(r)
            elif tab == "audit":
                total = audit.count_for_project(
                    cur,
                    project_id,
                    q=q,
                    actor=audit_actor,
                    action=audit_action,
                    since=audit_since,
                    until=audit_until,
                )
                audit_pager = paging.page_window(total, page)
                audit_pager["endpoint"] = "project_detail"
                audit_pager["project_id"] = project_id
                audit_pager["tab"] = "audit"
                audit_pager["q"] = q
                audit_pager["actor"] = audit_actor
                audit_pager["action"] = audit_action
                audit_pager["since"] = audit_since
                audit_pager["until"] = audit_until
                audit_rows = audit.list_for_project(
                    cur,
                    project_id,
                    limit=audit_pager["limit"],
                    offset=audit_pager["offset"],
                    q=q,
                    actor=audit_actor,
                    action=audit_action,
                    since=audit_since,
                    until=audit_until,
                )
            elif tab == "tokens":
                cur.execute(
                    """
                    SELECT id, name, token_prefix, role, created_at, expires_at
                    FROM api.machine_tokens
                    WHERE project_id = %s
                    ORDER BY created_at DESC
                    """,
                    (str(project_id),),
                )
                tokens = _annotate_token_expiry(cur.fetchall())
            elif tab == "settings":
                cur.execute(
                    "SELECT * FROM private.project_member_rows(%s::uuid)",
                    (str(project_id),),
                )
                project_members = cur.fetchall()
            # import: no extra queries
        return render_template(
            "project.html",
            project=project,
            project_id=project_id,
            secrets=secret_rows,
            tokens=tokens,
            audit_log=audit_rows,
            secrets_pager=secrets_pager,
            audit_pager=audit_pager,
            project_members=project_members,
            project_roles=config.PROJECT_ROLES,
            default_token_days=default_token_days,
            can_write=can_write,
            can_admin=can_admin,
            can_delete=can_delete,
            can_settings=can_settings,
            active_tab=tab,
            search_q=q,
            audit_actor=audit_actor,
            audit_action=audit_action,
            audit_since=audit_since,
            audit_until=audit_until,
            audit_actions=audit.ACTIONS,
            new_token=session.pop("new_token", None),
            due_overdue=due_overdue if tab == "secrets" else [],
            due_soon=due_soon if tab == "secrets" else [],
            soon_days=_SOON_DAYS,
        )


    @app.post("/projects/<uuid:project_id>/delete")
    @authz.login_required
    def delete_project(project_id):
        """Delete project (and secrets/tokens via CASCADE). Team owner/admin only."""
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT p.team_id, api.team_role(p.team_id) AS r
                FROM api.projects p WHERE p.id = %s
                """,
                (str(project_id),),
            )
            row = cur.fetchone()
            if not row:
                flash("Project not found", "error")
                return redirect(url_for("projects_list"))
            team_id = row["team_id"]
            if row["r"] not in ("owner", "admin"):
                flash("Only team owners or admins can delete projects", "error")
                return redirect(url_for("project_detail", project_id=project_id))
            cur.execute("DELETE FROM api.projects WHERE id = %s", (str(project_id),))
            if cur.rowcount == 0:
                flash("You don't have permission to do that", "error")
                conn.rollback()
                return redirect(url_for("project_detail", project_id=project_id))
            conn.commit()
        flash("Project deleted", "ok")
        return redirect(url_for("team_detail", team_id=team_id))


    @app.post("/projects/<uuid:project_id>/secrets")
    @authz.login_required
    def create_secret(project_id):
        key = request.form["key"].strip()
        value = request.form["value"]
        note = request.form.get("note", "").strip()
        if not key or value is None:
            flash("Key and value required", "error")
            return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))
        try:
            expires_at = _parse_expires_at(request.form)
        except (ValueError, TypeError) as e:
            flash(str(e), "error")
            return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                sid, was_new = _upsert_secret(
                    cur,
                    project_id,
                    key,
                    value,
                    note=note,
                    expires_at=expires_at,
                )
                if not sid:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    audit.log_secret(
                        cur,
                        project_id=project_id,
                        secret_id=sid,
                        secret_key=key,
                        action="created" if was_new else "updated",
                    )
                    conn.commit()
            except Exception as e:
                flash(str(e), "error")
        if authz.htmx():
            return _secrets_partial(project_id)
        return redirect(
            url_for(
                "project_detail",
                project_id=project_id,
                tab="secrets",
                page=paging.page_arg("page"),
                q=paging.list_state_q() or None,
            )
        )


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/delete")
    @authz.login_required
    def delete_secret(project_id, secret_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, key FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                flash("Secret not found", "error")
            else:
                cur.execute(
                    """
                    UPDATE api.secrets SET deleted_at = now()
                    WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                    """,
                    (str(secret_id), str(project_id)),
                )
                if cur.rowcount == 0:
                    # SELECT allowed (read), UPDATE blocked (write) — e.g. read-only role
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    audit.log_secret(
                        cur,
                        project_id=project_id,
                        secret_id=row["id"],
                        secret_key=row["key"],
                        action="deleted",
                    )
                    conn.commit()
        if authz.htmx():
            return _secrets_partial(project_id)
        return redirect(
            url_for(
                "project_detail",
                project_id=project_id,
                tab="secrets",
                page=paging.page_arg("page"),
                q=paging.list_state_q() or None,
            )
        )


    def _reveal_cell_ids(secret_id, cell: str | None = None, version_id=None):
        """Return (cell_id, toggle_id) for HTMX reveal/hide targets."""
        if version_id is not None:
            return f"reveal-v-{version_id}", f"reveal-toggle-v-{version_id}"
        if (cell or "").strip().lower() == "current":
            return (
                f"reveal-current-{secret_id}",
                f"reveal-toggle-current-{secret_id}",
            )
        return f"reveal-{secret_id}", f"reveal-toggle-{secret_id}"

    def _reveal_toggle_html(
        project_id,
        secret_id,
        *,
        revealed: bool,
        cell: str | None = None,
        version_id=None,
    ):
        cell_id, toggle_id = _reveal_cell_ids(secret_id, cell, version_id)
        if version_id is not None:
            reveal_url = url_for(
                "reveal_secret_version",
                project_id=project_id,
                secret_id=secret_id,
                version_id=version_id,
            )
            hide_url = url_for(
                "hide_secret_version",
                project_id=project_id,
                secret_id=secret_id,
                version_id=version_id,
            )
        else:
            kwargs = {"project_id": project_id, "secret_id": secret_id}
            if cell:
                kwargs["cell"] = cell
            reveal_url = url_for("reveal_secret", **kwargs)
            hide_url = url_for("hide_secret", **kwargs)
        return render_template(
            "partials/reveal_toggle.html",
            toggle_id=toggle_id,
            cell_id=cell_id,
            reveal_url=reveal_url,
            hide_url=hide_url,
            revealed=revealed,
            oob=True,
        )

    @app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/reveal")
    @authz.login_required
    def reveal_secret(project_id, secret_id):
        cell = (request.args.get("cell") or "").strip() or None
        force_inline = (request.args.get("inline") or "").strip() in ("1", "true", "yes")
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, key, value_enc, note, expires_at FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = bool(cur.fetchone()["w"])
            try:
                pins.touch_recent(cur, session["user_id"], secret_id)
            except Exception:
                pass
            is_fav = False
            try:
                is_fav = pins.is_pinned(cur, session["user_id"], secret_id)
            except Exception:
                pass
            plaintext = crypto.decrypt(row["value_enc"])
            kind = detect_secret_kind(plaintext, row.get("note") or "")
            if kind in _STRUCTURED_VIEW_KINDS and not force_inline:
                # Audit on the view page; navigate in the current window.
                conn.commit()
                view_url = url_for(
                    "secret_view",
                    project_id=project_id,
                    secret_id=secret_id,
                )
                if authz.htmx():
                    resp = make_response("", 204)
                    resp.headers["HX-Redirect"] = view_url
                    return resp
                return redirect(view_url)
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=row["id"],
                secret_key=row["key"],
                action="revealed",
            )
            conn.commit()
        exp = row.get("expires_at")
        exp_date = ""
        if exp is not None:
            try:
                exp_date = _as_utc(exp).date().isoformat()
            except Exception:
                exp_date = str(exp)[:10]
        body = render_template(
            "partials/reveal.html",
            value=plaintext,
            secret_id=secret_id,
            project_id=project_id,
            editable=True,
            can_write=can_write,
            is_pinned=is_fav,
            expires_at=exp_date,
            clipboard_clear_seconds=config.CLIPBOARD_CLEAR_SECONDS,
        )
        if authz.htmx():
            body += _reveal_toggle_html(
                project_id, secret_id, revealed=True, cell=cell
            )
        return body

    def _render_secret_view(
        *,
        project_id,
        secret_id,
        row,
        plaintext: str,
        kind: str,
        can_write: bool,
        is_version: bool = False,
        status: int = 200,
    ):
        exp = row.get("expires_at")
        exp_date = ""
        if exp is not None:
            try:
                exp_date = _as_utc(exp).date().isoformat()
            except Exception:
                exp_date = str(exp)[:10]
        cert_pem, cert_key = ("", "")
        if kind == "certificate":
            cert_pem, cert_key = split_cert_and_key(plaintext)
        return (
            render_template(
                "secret_view.html",
                project_id=project_id,
                project_name=row.get("project_name") or "",
                secret_id=secret_id,
                secret_key=row["key"],
                note=note_without_kind(row.get("note") or ""),
                kind=kind,
                value=plaintext,
                is_version=is_version,
                kv_pairs=parse_kv_lines(plaintext) if kind == "kv" else [("", "")],
                pem_blocks=parse_pem_blocks(plaintext)
                if kind in ("certificate", "ssh")
                else [],
                cert_pem=cert_pem,
                cert_key=cert_key,
                db_parts=parse_database_url(plaintext) if kind == "database" else {},
                expires_at=exp_date,
                can_write=can_write and not is_version,
                clipboard_clear_seconds=config.CLIPBOARD_CLEAR_SECONDS,
            ),
            status,
        )

    @app.route(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/view",
        methods=["GET", "POST"],
    )
    @authz.login_required
    def secret_view(project_id, secret_id):
        """Type-specific view/edit page (KV, cert, SSH, database URL)."""
        version_id = (request.args.get("version_id") or "").strip() or None
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT s.id, s.key, s.value_enc, s.note, s.expires_at,
                       p.name AS project_name
                FROM api.secrets s
                JOIN api.projects p ON p.id = s.project_id
                WHERE s.id = %s AND s.project_id = %s AND s.deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            value_enc = row["value_enc"]
            is_version = False
            if version_id:
                cur.execute(
                    """
                    SELECT value_enc FROM api.secret_versions
                    WHERE id = %s::uuid AND secret_id = %s::uuid
                    """,
                    (version_id, str(secret_id)),
                )
                ver = cur.fetchone()
                if not ver:
                    return "Not found", 404
                value_enc = ver["value_enc"]
                is_version = True
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = bool(cur.fetchone()["w"])

            if request.method == "POST":
                if is_version or not can_write:
                    flash("You don't have permission to do that", "error")
                    return redirect(
                        url_for(
                            "secret_view",
                            project_id=project_id,
                            secret_id=secret_id,
                        )
                    )
                kind = (request.form.get("kind") or "plain").strip().lower()
                if kind not in config.SECRET_KINDS:
                    kind = detect_secret_kind(
                        crypto.decrypt(row["value_enc"]), row.get("note") or ""
                    )
                value, kind_label = _compose_secret_value(kind, request.form)
                if kind == "plain":
                    value = request.form.get("plain_value") or value or ""
                if kind == "ssh" and not value:
                    value = (request.form.get("ssh_key") or "").strip()
                note_in = (request.form.get("note") or "").strip()
                note = note_with_kind(note_in, kind_label)
                row_view = dict(row)
                row_view["note"] = note_in
                row_view["project_name"] = row.get("project_name") or ""
                if not value:
                    flash("Value is required", "error")
                    body, code = _render_secret_view(
                        project_id=project_id,
                        secret_id=secret_id,
                        row=row_view,
                        plaintext=crypto.decrypt(row["value_enc"]),
                        kind=kind,
                        can_write=True,
                        status=400,
                    )
                    return body, code
                try:
                    expires_at = _parse_expires_at(request.form, allow_clear=True)
                except (ValueError, TypeError) as e:
                    flash(str(e), "error")
                    body, code = _render_secret_view(
                        project_id=project_id,
                        secret_id=secret_id,
                        row=row_view,
                        plaintext=value,
                        kind=kind,
                        can_write=True,
                        status=400,
                    )
                    return body, code
                cur.execute(
                    """
                    UPDATE api.secrets
                    SET value_enc = %s, note = %s, expires_at = %s
                    WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                    """,
                    (
                        crypto.encrypt(value),
                        note,
                        expires_at,
                        str(secret_id),
                        str(project_id),
                    ),
                )
                if cur.rowcount == 0:
                    conn.rollback()
                    flash("You don't have permission to do that", "error")
                    return redirect(
                        url_for("project_detail", project_id=project_id, tab="secrets")
                    )
                audit.log_secret(
                    cur,
                    project_id=project_id,
                    secret_id=row["id"],
                    secret_key=row["key"],
                    action="updated",
                )
                conn.commit()
                flash("Secret updated", "ok")
                return redirect(
                    url_for(
                        "secret_view",
                        project_id=project_id,
                        secret_id=secret_id,
                    )
                )

            try:
                pins.touch_recent(cur, session["user_id"], secret_id)
            except Exception:
                pass
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=row["id"],
                secret_key=row["key"],
                action="revealed",
            )
            conn.commit()
        plaintext = crypto.decrypt(value_enc)
        kind = detect_secret_kind(plaintext, row.get("note") or "")
        body, code = _render_secret_view(
            project_id=project_id,
            secret_id=secret_id,
            row=row,
            plaintext=plaintext,
            kind=kind,
            can_write=can_write,
            is_version=is_version,
        )
        return body, code

    @app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/hide")
    @authz.login_required
    def hide_secret(project_id, secret_id):
        """Mask a revealed secret (client re-mask; no audit)."""
        cell = (request.args.get("cell") or "").strip() or None
        body = render_template("partials/secret_masked.html")
        if authz.htmx():
            body += _reveal_toggle_html(
                project_id, secret_id, revealed=False, cell=cell
            )
        return body


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/pin")
    @authz.login_required
    def toggle_secret_pin(project_id, secret_id):
        """Pin or unpin a secret for the current user."""
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            if not cur.fetchone():
                return "Not found", 404
            if pins.is_pinned(cur, session["user_id"], secret_id):
                pins.unpin(cur, session["user_id"], secret_id)
                pinned = False
            else:
                pins.pin(cur, session["user_id"], secret_id)
                pinned = True
            pin_rows = pins.list_pins(cur, session["user_id"])
            conn.commit()
        if authz.htmx():
            btn = render_template(
                "partials/pin_button.html",
                project_id=project_id,
                secret_id=secret_id,
                is_pinned=pinned,
            )
            oob = render_template(
                "partials/side_pins.html",
                nav_pins=pin_rows,
                oob=True,
            )
            return btn + oob
        return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/value")
    @authz.login_required
    def update_secret_value(project_id, secret_id):
        """In-place update after reveal (archives prior value via trigger)."""
        value = request.form.get("value")
        if value is None:
            return "Value required", 400
        try:
            # Always accept expires fields from edit form
            if request.form.get("clear_expires") or "expires_at" in request.form:
                expires_at = _parse_expires_at(request.form, allow_clear=True)
                set_expires = True
            else:
                expires_at = None
                set_expires = False
        except (ValueError, TypeError) as e:
            if authz.htmx():
                return str(e), 400
            flash(str(e), "error")
            return redirect(
                url_for("project_detail", project_id=project_id, tab="secrets")
            )
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                return "Forbidden", 403
            cur.execute(
                """
                SELECT id, key FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            if set_expires:
                cur.execute(
                    """
                    UPDATE api.secrets SET value_enc = %s, expires_at = %s
                    WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                    """,
                    (
                        crypto.encrypt(value),
                        expires_at,
                        str(secret_id),
                        str(project_id),
                    ),
                )
            else:
                cur.execute(
                    """
                    UPDATE api.secrets SET value_enc = %s
                    WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                    """,
                    (crypto.encrypt(value), str(secret_id), str(project_id)),
                )
            if cur.rowcount == 0:
                conn.rollback()
                return "Forbidden", 403
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=row["id"],
                secret_key=row["key"],
                action="updated",
            )
            conn.commit()
        if authz.htmx():
            # Hide value again; show brief confirmation and restore Reveal control
            body = render_template("partials/reveal_saved.html")
            body += _reveal_toggle_html(
                project_id, secret_id, revealed=False, cell=None
            )
            return body
        flash("Secret updated", "ok")
        return redirect(url_for("project_detail", project_id=project_id, tab="secrets"))


    def _secrets_partial(project_id):
        page = paging.page_arg("page")
        q = paging.list_state_q()
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            rows, secrets_pager = _load_secrets_page(cur, project_id, page, q)
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = cur.fetchone()["w"]
        return render_template(
            "partials/secrets.html",
            secrets=rows,
            project_id=project_id,
            can_write=can_write,
            secrets_pager=secrets_pager,
            search_q=q,
        )


    @app.get("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/history")
    @authz.login_required
    def secret_history(project_id, secret_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, key, note, updated_at, expires_at
                FROM api.secrets
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (str(secret_id), str(project_id)),
            )
            secret = cur.fetchone()
            if not secret:
                return "Not found", 404
            cur.execute(
                """
                SELECT id, note, created_at
                FROM api.secret_versions
                WHERE secret_id = %s
                ORDER BY created_at DESC
                LIMIT 50
                """,
                (str(secret_id),),
            )
            versions = cur.fetchall()
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            can_write = cur.fetchone()["w"]
            cur.execute(
                """
                SELECT p.name, p.id, t.name AS team_name, t.id AS team_id
                FROM api.projects p JOIN api.teams t ON t.id = p.team_id
                WHERE p.id = %s
                """,
                (str(project_id),),
            )
            project = cur.fetchone()
        return render_template(
            "secret_history.html",
            project=project,
            secret=secret,
            versions=versions,
            can_write=can_write,
            project_id=project_id,
        )


    @app.get(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/versions/<uuid:version_id>/reveal"
    )
    @authz.login_required
    def reveal_secret_version(project_id, secret_id, version_id):
        force_inline = (request.args.get("inline") or "").strip() in ("1", "true", "yes")
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT v.value_enc, s.key, s.note, s.id AS secret_id
                FROM api.secret_versions v
                JOIN api.secrets s ON s.id = v.secret_id
                WHERE v.id = %s AND s.id = %s AND s.project_id = %s
                  AND s.deleted_at IS NULL
                """,
                (str(version_id), str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                return "Not found", 404
            audit.log_secret(
                cur,
                project_id=project_id,
                secret_id=row["secret_id"],
                secret_key=row["key"],
                action="revealed",
            )
            conn.commit()
        plaintext = crypto.decrypt(row["value_enc"])
        kind = detect_secret_kind(plaintext, row.get("note") or "")
        if kind in _STRUCTURED_VIEW_KINDS and not force_inline:
            view_url = url_for(
                "secret_view",
                project_id=project_id,
                secret_id=secret_id,
                version_id=version_id,
            )
            if authz.htmx():
                resp = make_response("", 204)
                resp.headers["HX-Redirect"] = view_url
                return resp
            return redirect(view_url)
        body = render_template(
            "partials/reveal.html",
            value=plaintext,
            secret_id=secret_id,
            project_id=project_id,
            editable=False,
            can_write=False,
            is_pinned=False,
            clipboard_clear_seconds=config.CLIPBOARD_CLEAR_SECONDS,
        )
        if authz.htmx():
            body += _reveal_toggle_html(
                project_id,
                secret_id,
                revealed=True,
                version_id=version_id,
            )
        return body

    @app.get(
        "/projects/<uuid:project_id>/secrets/<uuid:secret_id>/versions/<uuid:version_id>/hide"
    )
    @authz.login_required
    def hide_secret_version(project_id, secret_id, version_id):
        body = render_template("partials/secret_masked.html")
        if authz.htmx():
            body += _reveal_toggle_html(
                project_id,
                secret_id,
                revealed=False,
                version_id=version_id,
            )
        return body


    @app.post("/projects/<uuid:project_id>/secrets/<uuid:secret_id>/rollback/<uuid:version_id>")
    @authz.login_required
    def rollback_secret(project_id, secret_id, version_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT s.id, s.key, v.value_enc, v.note
                FROM api.secret_versions v
                JOIN api.secrets s ON s.id = v.secret_id
                WHERE v.id = %s AND s.id = %s AND s.project_id = %s
                  AND s.deleted_at IS NULL
                """,
                (str(version_id), str(secret_id), str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                flash("Version not found", "error")
                return redirect(
                    url_for("secret_history", project_id=project_id, secret_id=secret_id)
                )
            cur.execute(
                """
                UPDATE api.secrets
                SET value_enc = %s, note = %s
                WHERE id = %s AND project_id = %s AND deleted_at IS NULL
                """,
                (row["value_enc"], row["note"] or "", str(secret_id), str(project_id)),
            )
            if cur.rowcount == 0:
                flash("You don't have permission to do that", "error")
                conn.rollback()
            else:
                audit.log_secret(
                    cur,
                    project_id=project_id,
                    secret_id=secret_id,
                    secret_key=row["key"],
                    action="updated",
                )
                conn.commit()
                flash("Rolled back to selected version", "ok")
        return redirect(url_for("secret_history", project_id=project_id, secret_id=secret_id))


    @app.get("/projects/<uuid:project_id>/export")
    @authz.login_required
    def export_secrets(project_id):
        fmt = (request.args.get("format") or "env").strip().lower()
        mode = (request.args.get("mode") or "plain").strip().lower()
        if fmt not in ("env", "json", "csv"):
            fmt = "env"
        if mode not in ("plain", "enc"):
            mode = "plain"
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_read_project(%s) AS r", (str(project_id),))
            if not (cur.fetchone() or {}).get("r"):
                return "Not found", 404
            cur.execute(
                """
                SELECT key, value_enc, note FROM api.secrets
                WHERE project_id = %s AND deleted_at IS NULL
                ORDER BY key
                """,
                (str(project_id),),
            )
            rows = cur.fetchall()
            # Bulk exfil must leave an audit trail (especially plaintext)
            audit.log_secret(
                cur,
                project_id=project_id,
                action="exported",
                secret_key=f"{mode}/{fmt} n={len(rows)}",
            )
            conn.commit()
        if mode == "enc":
            payload = {
                r["key"]: {"value_enc": r["value_enc"], "note": r["note"]} for r in rows
            }
            body = json.dumps(payload, indent=2)
            return Response(
                body,
                mimetype="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="secrets-{project_id}-enc.json"'
                },
            )
        pairs = [(r["key"], crypto.decrypt(r["value_enc"])) for r in rows]
        if fmt == "json":
            body = json.dumps({k: v for k, v in pairs}, indent=2)
            mime, name = "application/json", f"secrets-{project_id}.json"
        elif fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["key", "value"])
            w.writerows(pairs)
            body = buf.getvalue()
            mime, name = "text/csv", f"secrets-{project_id}.csv"
        else:
            body = "\n".join(f"{k}={v}" for k, v in pairs) + ("\n" if pairs else "")
            mime, name = "text/plain", f"secrets-{project_id}.env"
        return Response(
            body,
            mimetype=mime,
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )


    def _read_import_payload():
        """Return (raw_text, error_message)."""
        raw = request.form.get("payload") or ""
        f = request.files.get("file")
        if f and f.filename:
            blob = f.read(config.MAX_IMPORT_BYTES + 1)
            if len(blob) > config.MAX_IMPORT_BYTES:
                return (
                    None,
                    f"Import file too large (max {config.MAX_IMPORT_BYTES // 1024} KiB)",
                )
            raw = blob.decode("utf-8", errors="replace")
        if len(raw.encode("utf-8")) > config.MAX_IMPORT_BYTES:
            return (
                None,
                f"Import payload too large (max {config.MAX_IMPORT_BYTES // 1024} KiB)",
            )
        if not raw.strip():
            return None, "Paste secrets or choose a file"
        return raw, None

    @app.post("/projects/<uuid:project_id>/import/preview")
    @authz.login_required
    def import_preview(project_id):
        back = url_for("project_detail", project_id=project_id, tab="import")
        raw, err = _read_import_payload()
        if err:
            flash(err, "error")
            return redirect(back)
        try:
            pairs = parse_secret_pairs(raw)
        except Exception as e:
            flash(f"Parse error: {e}", "error")
            return redirect(back)
        if not pairs:
            flash("No key/value pairs found", "error")
            return redirect(back)
        # Normalize for session: store serializable list
        pending = []
        for key, val in pairs:
            if isinstance(val, dict) and "_enc" in val:
                pending.append(
                    {
                        "key": key,
                        "enc": True,
                        "value_enc": val["_enc"],
                        "note": val.get("note") or "",
                    }
                )
            else:
                pending.append(
                    {"key": key, "enc": False, "value": str(val), "note": ""}
                )
        creates, updates = [], []
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(back)
            cur.execute(
                """
                SELECT key FROM api.secrets
                WHERE project_id = %s AND deleted_at IS NULL
                """,
                (str(project_id),),
            )
            existing = {r["key"] for r in (cur.fetchall() or [])}
            cur.execute(
                """
                SELECT p.name, p.id, t.name AS team_name
                FROM api.projects p JOIN api.teams t ON t.id = p.team_id
                WHERE p.id = %s
                """,
                (str(project_id),),
            )
            project = cur.fetchone()
        if not project:
            return "Not found", 404
        for item in pending:
            row = {"key": item["key"], "note": item.get("note") or ""}
            if item["key"] in existing:
                updates.append(row)
            else:
                creates.append(row)
        session["import_pending"] = {"project_id": str(project_id), "items": pending}
        return render_template(
            "import_preview.html",
            project=project,
            creates=creates,
            updates=updates,
        )

    @app.post("/projects/<uuid:project_id>/import")
    @authz.login_required
    def import_secrets(project_id):
        """Legacy direct import — prefer preview + commit."""
        return import_preview(project_id)

    @app.post("/projects/<uuid:project_id>/import/commit")
    @authz.login_required
    def import_commit(project_id):
        back = url_for("project_detail", project_id=project_id, tab="import")
        pending = session.pop("import_pending", None)
        if not pending or pending.get("project_id") != str(project_id):
            flash("Import preview expired — upload again", "error")
            return redirect(back)
        items = pending.get("items") or []
        n_ok = 0
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(back)
            try:
                for item in items:
                    key = item["key"]
                    if item.get("enc"):
                        sid, was_new = _upsert_secret(
                            cur,
                            project_id,
                            key,
                            item["value_enc"],
                            note=item.get("note") or "",
                            already_enc=True,
                            touch_meta=False,
                        )
                    else:
                        sid, was_new = _upsert_secret(
                            cur,
                            project_id,
                            key,
                            item.get("value") or "",
                            note=item.get("note") or "",
                            touch_meta=False,
                        )
                    if sid:
                        audit.log_secret(
                            cur,
                            project_id=project_id,
                            secret_id=sid,
                            secret_key=key,
                            action="created" if was_new else "updated",
                        )
                        n_ok += 1
                conn.commit()
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
                return redirect(back)
        flash(f"Imported {n_ok} secret(s)", "ok")
        return redirect(back)

    @app.post("/projects/<uuid:project_id>/secrets/bulk")
    @authz.login_required
    def bulk_secrets(project_id):
        action = (request.form.get("bulk_action") or "").strip()
        ids = request.form.getlist("secret_ids")
        back = url_for("project_detail", project_id=project_id, tab="secrets")
        if not ids:
            flash("Select at least one secret", "error")
            return redirect(back)
        if action != "delete":
            flash("Unknown bulk action", "error")
            return redirect(back)
        n = 0
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(back)
            for sid in ids:
                cur.execute(
                    """
                    SELECT id, key FROM api.secrets
                    WHERE id = %s::uuid AND project_id = %s AND deleted_at IS NULL
                    """,
                    (sid, str(project_id)),
                )
                row = cur.fetchone()
                if not row:
                    continue
                cur.execute(
                    """
                    UPDATE api.secrets SET deleted_at = now()
                    WHERE id = %s::uuid AND project_id = %s AND deleted_at IS NULL
                    """,
                    (sid, str(project_id)),
                )
                if cur.rowcount:
                    audit.log_secret(
                        cur,
                        project_id=project_id,
                        secret_id=row["id"],
                        secret_key=row["key"],
                        action="deleted",
                    )
                    n += 1
            conn.commit()
        flash(f"Moved {n} secret(s) to trash", "ok")
        return redirect(back)

    @app.post("/projects/<uuid:project_id>/export/bulk")
    @authz.login_required
    def bulk_export(project_id):
        fmt = (request.args.get("format") or request.form.get("format") or "env").strip().lower()
        if fmt not in ("env", "json", "csv"):
            fmt = "env"
        ids = request.form.getlist("secret_ids")
        if not ids:
            flash("Select at least one secret", "error")
            return redirect(
                url_for("project_detail", project_id=project_id, tab="secrets")
            )
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_read_project(%s) AS r", (str(project_id),))
            if not (cur.fetchone() or {}).get("r"):
                return "Not found", 404
            cur.execute(
                """
                SELECT key, value_enc FROM api.secrets
                WHERE project_id = %s AND deleted_at IS NULL
                  AND id = ANY(%s::uuid[])
                ORDER BY key
                """,
                (str(project_id), ids),
            )
            rows = cur.fetchall() or []
            audit.log_secret(
                cur,
                project_id=project_id,
                action="exported",
                secret_key=f"bulk/{fmt} n={len(rows)}",
            )
            conn.commit()
        pairs = [(r["key"], crypto.decrypt(r["value_enc"])) for r in rows]
        if fmt == "json":
            body = json.dumps({k: v for k, v in pairs}, indent=2)
            mime, name = "application/json", f"secrets-selected.json"
        elif fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["key", "value"])
            w.writerows(pairs)
            body = buf.getvalue()
            mime, name = "text/csv", "secrets-selected.csv"
        else:
            body = "\n".join(f"{k}={v}" for k, v in pairs) + ("\n" if pairs else "")
            mime, name = "text/plain", "secrets-selected.env"
        return Response(
            body,
            mimetype=mime,
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )

    @app.post("/trash/bulk")
    @authz.login_required
    def bulk_trash():
        action = (request.form.get("bulk_action") or "").strip()
        ids = request.form.getlist("secret_ids")
        q = (request.form.get("q") or request.args.get("q") or "").strip() or None
        if not ids:
            flash("Select at least one secret", "error")
            return redirect(url_for("trash", q=q))
        n = 0
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            for sid in ids:
                cur.execute(
                    """
                    SELECT id, key, project_id FROM api.secrets
                    WHERE id = %s::uuid AND deleted_at IS NOT NULL
                    """,
                    (sid,),
                )
                row = cur.fetchone()
                if not row:
                    continue
                cur.execute(
                    "SELECT api.can_write_project(%s) AS w", (str(row["project_id"]),)
                )
                if not (cur.fetchone() or {}).get("w"):
                    continue
                if action == "restore":
                    cur.execute(
                        """
                        UPDATE api.secrets SET deleted_at = NULL
                        WHERE id = %s::uuid AND deleted_at IS NOT NULL
                        """,
                        (sid,),
                    )
                    if cur.rowcount:
                        audit.log_secret(
                            cur,
                            project_id=row["project_id"],
                            secret_id=row["id"],
                            secret_key=row["key"],
                            action="restored",
                        )
                        n += 1
                elif action == "purge":
                    cur.execute(
                        "DELETE FROM api.secrets WHERE id = %s::uuid AND deleted_at IS NOT NULL",
                        (sid,),
                    )
                    if cur.rowcount:
                        audit.log_secret(
                            cur,
                            project_id=row["project_id"],
                            secret_id=row["id"],
                            secret_key=row["key"],
                            action="purged",
                        )
                        n += 1
            conn.commit()
        if action == "restore":
            flash(f"Restored {n} secret(s)", "ok")
        else:
            flash(f"Permanently deleted {n} secret(s)", "ok")
        return redirect(url_for("trash", q=q))

    def _compose_secret_value(kind: str, form) -> tuple[str, str]:
        """Build (value, kind_label) from advanced form fields."""
        kind = (kind or "plain").strip().lower()
        if kind == "database":
            scheme = (form.get("db_scheme") or "postgresql").strip()
            host = (form.get("db_host") or "").strip()
            port = (form.get("db_port") or "").strip()
            user = (form.get("db_user") or "").strip()
            password = form.get("db_password") or ""
            dbname = (form.get("db_name") or "").strip()
            auth = ""
            if user:
                from urllib.parse import quote

                auth = quote(user, safe="")
                if password:
                    auth += ":" + quote(password, safe="")
                auth += "@"
            hostpart = host or "localhost"
            if port:
                hostpart += f":{port}"
            path = f"/{dbname}" if dbname else ""
            return f"{scheme}://{auth}{hostpart}{path}", "database"
        if kind == "certificate":
            cert = (form.get("cert_pem") or "").strip()
            key = (form.get("cert_key") or "").strip()
            parts = [p for p in (cert, key) if p]
            return "\n\n".join(parts), "certificate"
        if kind == "ssh":
            return (form.get("ssh_key") or "").strip(), "ssh"
        if kind == "kv":
            keys = form.getlist("kv_keys")
            values = form.getlist("kv_values")
            lines = []
            if keys:
                for i, k in enumerate(keys):
                    k = (k or "").strip()
                    if not k:
                        continue
                    v = values[i] if i < len(values) else ""
                    lines.append(f"{k}={v}")
            if lines:
                return "\n".join(lines), "kv"
            # Back-compat: single textarea paste
            return (form.get("kv_block") or "").strip(), "kv"
        return form.get("plain_value") or "", "plain"

    @app.route("/projects/<uuid:project_id>/secrets/new", methods=["GET", "POST"])
    @authz.login_required
    def secret_new(project_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT p.*, t.name AS team_name
                FROM api.projects p JOIN api.teams t ON t.id = p.team_id
                WHERE p.id = %s
                """,
                (str(project_id),),
            )
            project = cur.fetchone()
            if not project:
                return "Not found", 404
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(
                    url_for("project_detail", project_id=project_id, tab="secrets")
                )
        if request.method == "GET":
            return render_template(
                "secret_new.html",
                project=project,
                kind="plain",
                key="",
                note="",
                expires_at="",
                kv_pairs=[("", "")],
            )
        kind = (request.form.get("kind") or "plain").strip().lower()
        if kind not in config.SECRET_KINDS:
            kind = "plain"
        key = (request.form.get("key") or "").strip()
        note = (request.form.get("note") or "").strip()
        value, kind_label = _compose_secret_value(kind, request.form)
        kv_pairs = parse_kv_lines(value) if kind == "kv" else []
        if not key or not value:
            flash("Key and value are required", "error")
            return render_template(
                "secret_new.html",
                project=project,
                kind=kind,
                key=key,
                note=note,
                expires_at=request.form.get("expires_at") or "",
                kv_pairs=kv_pairs or [("", "")],
            ), 400
        note = note_with_kind(note, kind_label)
        try:
            expires_at = _parse_expires_at(request.form)
        except (ValueError, TypeError) as e:
            flash(str(e), "error")
            return render_template(
                "secret_new.html",
                project=project,
                kind=kind,
                key=key,
                note=note,
                expires_at=request.form.get("expires_at") or "",
                kv_pairs=kv_pairs or [("", "")],
            ), 400
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                sid, was_new = _upsert_secret(
                    cur, project_id, key, value, note=note, expires_at=expires_at
                )
                if not sid:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    audit.log_secret(
                        cur,
                        project_id=project_id,
                        secret_id=sid,
                        secret_key=key,
                        action="created" if was_new else "updated",
                    )
                    conn.commit()
                    flash(
                        "Secret created" if was_new else "Secret updated",
                        "ok",
                    )
            except Exception as e:
                flash(str(e), "error")
                return render_template(
                    "secret_new.html",
                    project=project,
                    kind=kind,
                    key=key,
                    note=note,
                    expires_at=request.form.get("expires_at") or "",
                    kv_pairs=kv_pairs or [("", "")],
                ), 400
        return redirect(
            url_for("project_detail", project_id=project_id, tab="secrets")
        )


    @app.post("/projects/<uuid:project_id>/tokens")
    @authz.login_required
    def create_token(project_id):
        name = request.form.get("name", "machine").strip() or "machine"
        role = (request.form.get("role") or "read-only").strip()
        if role not in config.MACHINE_TOKEN_ROLES:
            role = "read-only"
        expires_at = None
        days_raw = (request.form.get("expires_days") or "").strip()
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            # Explicit write gate (read-only can list tokens, not create them)
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))
            if not days_raw:
                cur.execute(
                    """
                    SELECT t.default_token_days
                    FROM api.projects p JOIN api.teams t ON t.id = p.team_id
                    WHERE p.id = %s
                    """,
                    (str(project_id),),
                )
                row = cur.fetchone() or {}
                if row.get("default_token_days"):
                    days_raw = str(row["default_token_days"])
            if days_raw:
                try:
                    days = int(days_raw)
                except ValueError:
                    flash("Expires days must be a positive integer", "error")
                    return redirect(
                        url_for("project_detail", project_id=project_id, tab="tokens")
                    )
                if days < 1 or days > config.MAX_EXPIRY_DAYS:
                    flash(
                        f"Expires days must be between 1 and {config.MAX_EXPIRY_DAYS}",
                        "error",
                    )
                    return redirect(
                        url_for("project_detail", project_id=project_id, tab="tokens")
                    )
                expires_at = datetime.now(timezone.utc) + timedelta(days=days)
            raw = "ss_" + secrets.token_urlsafe(32)
            thash = hashlib.sha256(raw.encode()).hexdigest()
            prefix = raw[:11]
            try:
                cur.execute(
                    """
                    INSERT INTO api.machine_tokens
                      (project_id, name, token_hash, token_prefix, role, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (str(project_id), name, thash, prefix, role, expires_at),
                )
                if cur.rowcount == 0:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                    return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))
                conn.commit()
            except Exception as e:
                flash(str(e), "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))
        session["new_token"] = raw  # shown once
        return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))


    @app.post("/projects/<uuid:project_id>/tokens/<uuid:token_id>/delete")
    @authz.login_required
    def delete_token(project_id, token_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
            if not cur.fetchone()["w"]:
                flash("You don't have permission to do that", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))
            cur.execute(
                "DELETE FROM api.machine_tokens WHERE id = %s AND project_id = %s",
                (str(token_id), str(project_id)),
            )
            if cur.rowcount == 0:
                flash("You don't have permission to do that", "error")
            conn.commit()
        return redirect(url_for("project_detail", project_id=project_id, tab="tokens"))


    @app.post("/projects/<uuid:project_id>/members")
    @authz.login_required
    def add_project_member(project_id):
        email = (request.form.get("email") or "").strip().lower()
        role = (request.form.get("role") or "read").strip()
        if role not in config.PROJECT_ROLES:
            role = "read"
        if not email:
            flash("Email required", "error")
            return redirect(url_for("project_detail", project_id=project_id, tab="settings"))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
            if not cur.fetchone()["a"]:
                flash("You don't have permission to do that", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="settings"))
            cur.execute("SELECT private.lookup_user(%s) AS id", (email,))
            u = cur.fetchone()
            if not u or not u.get("id"):
                flash("User not found — they must register or sign in via LDAP first", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="settings"))
            cur.execute("SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),))
            proj = cur.fetchone()
            try:
                cur.execute(
                    """
                    SELECT role FROM api.project_members
                    WHERE project_id = %s AND user_id = %s
                    """,
                    (str(project_id), str(u["id"])),
                )
                prev = cur.fetchone()
                cur.execute(
                    """
                    INSERT INTO api.project_members (project_id, user_id, role)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role
                    """,
                    (str(project_id), str(u["id"]), role),
                )
                if cur.rowcount == 0:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    action = (
                        audit.ORG_PROJECT_MEMBER_ROLE if prev else audit.ORG_PROJECT_MEMBER_ADD
                    )
                    detail = (
                        f"{email} → {role}"
                        if not prev
                        else f"{email}: {prev['role']} → {role}"
                    )
                    audit.log_org(
                        cur,
                        team_id=proj["team_id"] if proj else None,
                        project_id=project_id,
                        action=action,
                        detail=detail,
                    )
                    conn.commit()
                    flash("Project member saved", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("project_detail", project_id=project_id, tab="settings"))


    @app.post("/projects/<uuid:project_id>/members/<uuid:user_id>/remove")
    @authz.login_required
    def remove_project_member(project_id, user_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
            if not cur.fetchone()["a"]:
                flash("You don't have permission to do that", "error")
                return redirect(url_for("project_detail", project_id=project_id, tab="settings"))
            cur.execute("SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),))
            proj = cur.fetchone()
            cur.execute(
                """
                DELETE FROM api.project_members
                WHERE project_id = %s AND user_id = %s
                """,
                (str(project_id), str(user_id)),
            )
            if cur.rowcount == 0:
                flash("Member not found or not permitted", "error")
            else:
                audit.log_org(
                    cur,
                    team_id=proj["team_id"] if proj else None,
                    project_id=project_id,
                    action=audit.ORG_PROJECT_MEMBER_REMOVE,
                    detail=str(user_id),
                )
                conn.commit()
                flash("Project member removed", "ok")
        return redirect(url_for("project_detail", project_id=project_id, tab="settings"))

