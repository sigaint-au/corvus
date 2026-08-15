"""Project machine tokens and team machine list."""

import logging
import secrets
from datetime import datetime, timedelta, timezone

from flask import flash, redirect, render_template, request, session, url_for

from auth import authz
from core import config
from core import db
from ui import nav
from crypto import sha256_hex
from secret_svc.secret_kinds import annotate_token_expiry

log = logging.getLogger(__name__)


def parse_token_scope_lines(raw: str) -> list[tuple[str, str]]:
    """Parse scope lines into (kind, value) pairs: kind is ``key`` or ``pattern``.

    Empty lines and comments (``#``) are ignored. Lines containing ``*`` or ``?``
    become glob patterns; otherwise exact secret keys.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) > 256:
            continue
        kind = "pattern" if (("*" in line) or ("?" in line)) else "key"
        item = (kind, line)
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def insert_token_scopes(cur, token_id: str, scopes: list[tuple[str, str]]) -> None:
    """Insert scope rows for a newly created machine token."""
    for kind, val in scopes:
        if kind == "pattern":
            cur.execute(
                """
                INSERT INTO api.machine_token_scope (token_id, key_pattern)
                VALUES (%s::uuid, %s)
                """,
                (token_id, val),
            )
        else:
            cur.execute(
                """
                INSERT INTO api.machine_token_scope (token_id, secret_key)
                VALUES (%s::uuid, %s)
                """,
                (token_id, val),
            )


def register(app):
    """Register machine-token and project-token routes on the Flask app."""
    app.get("/machines")(machines_list)
    app.post("/projects/<uuid:project_id>/tokens")(create_token)
    app.post("/projects/<uuid:project_id>/tokens/<uuid:token_id>/delete")(delete_token)

@authz.login_required
def machines_list():
    """List machine tokens for all projects under the session team.

    Returns:
        Rendered machines list template for the active team.

    Example:
        GET /machines
    """
    tid = nav.ensure_active_team(session["user_id"])
    team, tokens = None, []
    if tid:
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
            team = cur.fetchone()
            if team:
                cur.execute(
                    """
                    SELECT mt.id, mt.name, mt.token_prefix, mt.role,
                           mt.created_at, mt.expires_at, mt.last_used_at,
                           p.id AS project_id, p.name AS project_name
                    FROM api.machine_tokens mt
                    JOIN api.projects p ON p.id = mt.project_id
                    WHERE p.team_id = %s
                    ORDER BY p.name, mt.name
                    """,
                    (tid,),
                )
                tokens = annotate_token_expiry(cur.fetchall())
    return render_template("machines.html", team=team, tokens=tokens)


@authz.login_required
def create_token(project_id):
    """Create a project machine token; raw secret is shown once via session.

    Args:
        project_id: UUID of the project that owns the token.

    Returns:
        Redirect to the project detail page (return_tab or tokens).

    Example:
        POST /projects/<project_id>/tokens with name, role, expires_days form fields
    """
    name = request.form.get("name", "machine").strip() or "machine"
    role = (request.form.get("role") or "service-reveal").strip()
    if role not in config.MACHINE_TOKEN_ROLES:
        role = "service-reveal"
    return_tab = (request.form.get("return_tab") or "tokens").strip().lower()
    if return_tab not in (
        "secrets",
        "audit",
        "tokens",
        "import",
        "integrations",
        "settings",
    ):
        return_tab = "tokens"

    def _token_redirect():
        """Redirect back to project detail using the chosen return tab.

        Returns:
            Flask redirect response to project_detail with return_tab.

        Example:
            return _token_redirect()
        """
        return redirect(
            url_for("project_detail", project_id=project_id, tab=return_tab)
        )

    expires_at = None
    days_raw = (request.form.get("expires_days") or "").strip()
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        # Explicit write gate (read-only can list tokens, not create them)
        cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
        if not cur.fetchone()["w"]:
            flash("You don't have permission to do that", "error")
            return _token_redirect()
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
                return _token_redirect()
            if days < 1 or days > config.MAX_EXPIRY_DAYS:
                flash(
                    f"Expires days must be between 1 and {config.MAX_EXPIRY_DAYS}",
                    "error",
                )
                return _token_redirect()
            expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        raw = "ss_" + secrets.token_urlsafe(32)
        thash = sha256_hex(raw)
        prefix = raw[:11]
        scopes = parse_token_scope_lines(request.form.get("scope_keys") or "")
        try:
            cur.execute(
                """
                INSERT INTO api.machine_tokens
                  (project_id, name, token_hash, token_prefix, role, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (str(project_id), name, thash, prefix, role, expires_at),
            )
            row = cur.fetchone()
            if not row:
                flash("You don't have permission to do that", "error")
                conn.rollback()
                return _token_redirect()
            if scopes:
                insert_token_scopes(cur, str(row["id"]), scopes)
            conn.commit()
        except Exception as e:
            flash(str(e), "error")
            return _token_redirect()
    session["new_token"] = raw  # shown once
    scope_note = (
        f" (scoped to {len(scopes)} key rule{'s' if len(scopes) != 1 else ''})"
        if scopes
        else " (full project access)"
    )
    flash(
        f"Machine account created{scope_note} — copy the token now; it is shown once",
        "ok",
    )
    return _token_redirect()


@authz.login_required
def delete_token(project_id, token_id):
    """Delete a project machine token.

    Args:
        project_id: UUID of the project that owns the token.
        token_id: UUID of the machine token to delete.

    Returns:
        Redirect to the project tokens tab.

    Example:
        POST /projects/<project_id>/tokens/<token_id>/delete
    """
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
