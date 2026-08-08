"""PAT/session management API for CLI: teams, projects, trash, tokens, admin lists.

Mounted under ``/eso/v1/…``. Requires ``Authorization: Bearer pat_…`` (not machine
tokens). Does **not** expose server settings changes.

Docstrings follow the project Args/Returns/Example style.
"""

from __future__ import annotations

import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

from flask import jsonify, request

import audit
import authz
import config
import db
import pats
import settings_svc
from crypto import sha256_hex
from routes.eso import _iso, bearer_raw

log = logging.getLogger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _require_pat():
    """Resolve a PAT (or session) user id for management routes.

    Returns:
        Tuple ``(user_id, None)`` or ``(None, (jsonify, status))``.
    """
    raw = bearer_raw()
    if raw and raw.startswith(pats.PREFIX):
        uid = pats.resolve(raw)
        if not uid:
            return None, (jsonify({"error": "unauthorized"}), 401)
        return uid, None
    # allow session for completeness
    from flask import session

    if session.get("user_id"):
        return str(session["user_id"]), None
    return None, (jsonify({"error": "unauthorized — use a pat_… token"}), 401)


def _require_global_admin(uid: str):
    """Return error response if uid is not a global admin, else None."""
    if not authz.is_global_admin(uid):
        return jsonify({"error": "global admin required"}), 403
    return None


def _is_uuid(s: str) -> bool:
    if not _UUID_RE.match(s or ""):
        return False
    try:
        UUID(s)
        return True
    except ValueError:
        return False


def _row(r: dict | None) -> dict | None:
    if not r:
        return None
    out = {}
    for k, v in r.items():
        if hasattr(v, "isoformat"):
            out[k] = _iso(v)
        elif isinstance(v, UUID):
            out[k] = str(v)
        else:
            out[k] = v
    return out


def _resolve_team(cur, ref: str) -> str | None:
    """Resolve team UUID from id or unique name under RLS."""
    ref = (ref or "").strip()
    if not ref:
        return None
    if _is_uuid(ref):
        cur.execute("SELECT id FROM api.teams WHERE id = %s::uuid", (ref,))
        r = cur.fetchone()
        return str(r["id"]) if r else None
    cur.execute(
        "SELECT id FROM api.teams WHERE name = %s ORDER BY created_at LIMIT 2",
        (ref,),
    )
    rows = cur.fetchall() or []
    return str(rows[0]["id"]) if len(rows) == 1 else None


def _resolve_project(cur, ref: str) -> str | None:
    """Resolve project UUID from id or unique name under RLS."""
    ref = (ref or "").strip()
    if not ref:
        return None
    if _is_uuid(ref):
        cur.execute("SELECT id FROM api.projects WHERE id = %s::uuid", (ref,))
        r = cur.fetchone()
        return str(r["id"]) if r else None
    cur.execute(
        "SELECT id FROM api.projects WHERE name = %s ORDER BY created_at LIMIT 2",
        (ref,),
    )
    rows = cur.fetchall() or []
    return str(rows[0]["id"]) if len(rows) == 1 else None


def _lookup_user_id(cur, email_or_id: str) -> str | None:
    """Resolve user id by UUID or email."""
    ref = (email_or_id or "").strip()
    if not ref:
        return None
    if _is_uuid(ref):
        return ref
    cur.execute("SELECT private.lookup_user(%s) AS id", (ref.lower(),))
    r = cur.fetchone() or {}
    return str(r["id"]) if r.get("id") else None


def register(app):
    """Register PAT management API routes under /eso/v1.

    Args:
        app: Flask application.

    Returns:
        None.
    """

    # ── Teams ──────────────────────────────────────────────────────────

    @app.get("/eso/v1/teams")
    def mgmt_list_teams():
        """List teams the PAT user can access.

        Args:
            None (optional query ``q``).

        Returns:
            JSON ``{"items":[…]}``.
        """
        uid, err = _require_pat()
        if err:
            return err
        q = (request.args.get("q") or "").strip()
        like = f"%{q}%" if q else None
        with db.as_user(uid) as conn, conn.cursor() as cur:
            if authz.is_global_admin(uid):
                sql = """
                    SELECT t.id, t.name, t.created_at,
                      COALESCE(tm.role, 'owner') AS role,
                      (SELECT count(*) FROM api.projects p WHERE p.team_id = t.id) AS project_count
                    FROM api.teams t
                    LEFT JOIN api.team_members tm
                      ON tm.team_id = t.id AND tm.user_id = %s
                """
                params: list = [uid]
                if like:
                    sql += " WHERE t.name ILIKE %s"
                    params.append(like)
            else:
                sql = """
                    SELECT t.id, t.name, t.created_at, tm.role,
                      (SELECT count(*) FROM api.projects p WHERE p.team_id = t.id) AS project_count
                    FROM api.teams t
                    JOIN api.team_members tm ON tm.team_id = t.id
                    WHERE tm.user_id = %s
                """
                params = [uid]
                if like:
                    sql += " AND t.name ILIKE %s"
                    params.append(like)
            cur.execute(sql + " ORDER BY t.name", params)
            rows = [_row(r) for r in (cur.fetchall() or [])]
        return jsonify({"items": rows})

    @app.post("/eso/v1/teams")
    def mgmt_create_team():
        """Create a team. Body: ``{"name":"…"}``.

        Returns:
            JSON team id/name or error.
        """
        uid, err = _require_pat()
        if err:
            return err
        if not settings_svc.can_create_team(authz.is_global_admin(uid)):
            return jsonify({"error": "not allowed to create teams"}), 403
        body = request.get_json(silent=True) or {}
        name = (body.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name required"}), 400
        with db.connect(autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT private.create_team(%s::uuid, %s) AS id",
                (uid, name),
            )
            tid = str(cur.fetchone()["id"])
        return jsonify({"ok": True, "id": tid, "name": name}), 201

    @app.get("/eso/v1/teams/<team_ref>")
    def mgmt_get_team(team_ref):
        """Get team detail including members and projects."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            tid = _resolve_team(cur, team_ref)
            if not tid:
                return jsonify({"error": "not found"}), 404
            cur.execute("SELECT * FROM api.teams WHERE id = %s::uuid", (tid,))
            team = _row(cur.fetchone())
            cur.execute(
                "SELECT * FROM private.team_member_rows(%s::uuid)",
                (tid,),
            )
            members = [_row(r) for r in (cur.fetchall() or [])]
            cur.execute(
                """
                SELECT id, name, created_at FROM api.projects
                 WHERE team_id = %s::uuid ORDER BY name
                """,
                (tid,),
            )
            projects = [_row(r) for r in (cur.fetchall() or [])]
        return jsonify({"team": team, "members": members, "projects": projects})

    @app.delete("/eso/v1/teams/<team_ref>")
    def mgmt_delete_team(team_ref):
        """Delete a team (owner/admin)."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            tid = _resolve_team(cur, team_ref)
            if not tid:
                return jsonify({"error": "not found"}), 404
            cur.execute("DELETE FROM api.teams WHERE id = %s::uuid", (tid,))
            if cur.rowcount == 0:
                return jsonify({"error": "forbidden"}), 403
            conn.commit()
        return jsonify({"ok": True, "id": tid})

    @app.get("/eso/v1/teams/<team_ref>/members")
    def mgmt_list_team_members(team_ref):
        """List team members."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            tid = _resolve_team(cur, team_ref)
            if not tid:
                return jsonify({"error": "not found"}), 404
            cur.execute("SELECT * FROM private.team_member_rows(%s::uuid)", (tid,))
            items = [_row(r) for r in (cur.fetchall() or [])]
        return jsonify({"items": items})

    @app.post("/eso/v1/teams/<team_ref>/members")
    def mgmt_add_team_member(team_ref):
        """Add/update team member. Body: ``{"email":"…","role":"member"}``."""
        uid, err = _require_pat()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        email = (body.get("email") or "").strip().lower()
        role = (body.get("role") or "member").strip()
        if role not in config.TEAM_ROLES:
            role = "member"
        if not email:
            return jsonify({"error": "email required"}), 400
        with db.as_user(uid) as conn, conn.cursor() as cur:
            tid = _resolve_team(cur, team_ref)
            if not tid:
                return jsonify({"error": "not found"}), 404
            mid = _lookup_user_id(cur, email)
            if not mid:
                return jsonify({"error": "user not found"}), 404
            cur.execute(
                """
                SELECT role FROM api.team_members
                WHERE team_id = %s::uuid AND user_id = %s::uuid
                """,
                (tid, mid),
            )
            prev = cur.fetchone()
            cur.execute(
                """
                INSERT INTO api.team_members (team_id, user_id, role, source)
                VALUES (%s::uuid, %s::uuid, %s, 'manual')
                ON CONFLICT (team_id, user_id) DO UPDATE
                  SET role = EXCLUDED.role, source = 'manual'
                """,
                (tid, mid, role),
            )
            if cur.rowcount == 0:
                return jsonify({"error": "forbidden"}), 403
            action = audit.ORG_MEMBER_ROLE if prev else audit.ORG_MEMBER_ADD
            detail = f"{email} → {role}"
            if prev:
                detail = f"{email}: {prev['role']} → {role}"
            audit.log_org(cur, team_id=tid, action=action, detail=detail)
            conn.commit()
        return jsonify({"ok": True, "email": email, "role": role})

    @app.delete("/eso/v1/teams/<team_ref>/members/<member_ref>")
    def mgmt_remove_team_member(team_ref, member_ref):
        """Remove team member by email or user id."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            tid = _resolve_team(cur, team_ref)
            if not tid:
                return jsonify({"error": "not found"}), 404
            mid = _lookup_user_id(cur, member_ref)
            if not mid:
                return jsonify({"error": "user not found"}), 404
            cur.execute(
                """
                DELETE FROM api.team_members
                WHERE team_id = %s::uuid AND user_id = %s::uuid
                """,
                (tid, mid),
            )
            if cur.rowcount == 0:
                return jsonify({"error": "forbidden or not a member"}), 403
            audit.log_org(
                cur,
                team_id=tid,
                action=audit.ORG_MEMBER_REMOVE,
                detail=member_ref,
            )
            conn.commit()
        return jsonify({"ok": True})

    @app.post("/eso/v1/teams/<team_ref>/transfer")
    def mgmt_transfer_team(team_ref):
        """Transfer team ownership. Body: ``{"email":"…"}``."""
        uid, err = _require_pat()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        email = (body.get("email") or "").strip().lower()
        if not email:
            return jsonify({"error": "email required"}), 400
        with db.as_user(uid) as conn, conn.cursor() as cur:
            tid = _resolve_team(cur, team_ref)
            if not tid:
                return jsonify({"error": "not found"}), 404
            mid = _lookup_user_id(cur, email)
            if not mid:
                return jsonify({"error": "user not found"}), 404
            # demote other owners, set new owner
            cur.execute(
                """
                UPDATE api.team_members SET role = 'admin'
                 WHERE team_id = %s::uuid AND role = 'owner'
                """,
                (tid,),
            )
            cur.execute(
                """
                INSERT INTO api.team_members (team_id, user_id, role, source)
                VALUES (%s::uuid, %s::uuid, 'owner', 'manual')
                ON CONFLICT (team_id, user_id) DO UPDATE SET role = 'owner'
                """,
                (tid, mid),
            )
            if cur.rowcount == 0:
                return jsonify({"error": "forbidden"}), 403
            audit.log_org(
                cur,
                team_id=tid,
                action=audit.ORG_OWNERSHIP,
                detail=f"owner → {email}",
            )
            conn.commit()
        return jsonify({"ok": True, "owner": email})

    @app.post("/eso/v1/teams/<team_ref>/projects")
    def mgmt_create_project(team_ref):
        """Create project under team. Body: ``{"name":"…"}``."""
        uid, err = _require_pat()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        name = (body.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name required"}), 400
        with db.as_user(uid) as conn, conn.cursor() as cur:
            tid = _resolve_team(cur, team_ref)
            if not tid:
                return jsonify({"error": "not found"}), 404
            try:
                cur.execute(
                    """
                    INSERT INTO api.projects (team_id, name)
                    VALUES (%s::uuid, %s)
                    RETURNING id, name, team_id, created_at
                    """,
                    (tid, name),
                )
                row = cur.fetchone()
                if not row:
                    return jsonify({"error": "forbidden"}), 403
                conn.commit()
            except Exception as e:
                return jsonify({"error": str(e)}), 400
        return jsonify({"ok": True, **(_row(row) or {})}), 201

    # ── Projects ───────────────────────────────────────────────────────

    @app.get("/eso/v1/projects/<project_ref>")
    def mgmt_get_project(project_ref):
        """Get project detail with members and machine token metadata."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            cur.execute(
                """
                SELECT p.id, p.name, p.team_id, p.created_at, t.name AS team_name
                  FROM api.projects p
                  JOIN api.teams t ON t.id = p.team_id
                 WHERE p.id = %s::uuid
                """,
                (pid,),
            )
            proj = _row(cur.fetchone())
            cur.execute("SELECT * FROM private.project_member_rows(%s::uuid)", (pid,))
            members = [_row(r) for r in (cur.fetchall() or [])]
            cur.execute(
                """
                SELECT id, name, token_prefix, role, expires_at, created_at
                  FROM api.machine_tokens
                 WHERE project_id = %s::uuid
                 ORDER BY created_at DESC
                """,
                (pid,),
            )
            tokens = [_row(r) for r in (cur.fetchall() or [])]
        return jsonify({"project": proj, "members": members, "tokens": tokens})

    @app.delete("/eso/v1/projects/<project_ref>")
    def mgmt_delete_project(project_ref):
        """Delete a project."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            cur.execute("DELETE FROM api.projects WHERE id = %s::uuid", (pid,))
            if cur.rowcount == 0:
                return jsonify({"error": "forbidden"}), 403
            conn.commit()
        return jsonify({"ok": True, "id": pid})

    @app.get("/eso/v1/projects/<project_ref>/members")
    def mgmt_list_project_members(project_ref):
        """List project-scoped members."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            cur.execute("SELECT * FROM private.project_member_rows(%s::uuid)", (pid,))
            items = [_row(r) for r in (cur.fetchall() or [])]
        return jsonify({"items": items})

    @app.post("/eso/v1/projects/<project_ref>/members")
    def mgmt_add_project_member(project_ref):
        """Add project member. Body: ``{"email":"…","role":"read|write|admin"}``."""
        uid, err = _require_pat()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        email = (body.get("email") or "").strip().lower()
        role = (body.get("role") or "read").strip()
        if role not in config.PROJECT_ROLES:
            role = "read"
        if not email:
            return jsonify({"error": "email required"}), 400
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            mid = _lookup_user_id(cur, email)
            if not mid:
                return jsonify({"error": "user not found"}), 404
            cur.execute(
                """
                INSERT INTO api.project_members (project_id, user_id, role)
                VALUES (%s::uuid, %s::uuid, %s)
                ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role
                """,
                (pid, mid, role),
            )
            if cur.rowcount == 0:
                return jsonify({"error": "forbidden"}), 403
            audit.log_org(
                cur,
                project_id=pid,
                action=audit.ORG_PROJECT_MEMBER_ADD,
                detail=f"{email} → {role}",
            )
            conn.commit()
        return jsonify({"ok": True, "email": email, "role": role})

    @app.delete("/eso/v1/projects/<project_ref>/members/<member_ref>")
    def mgmt_remove_project_member(project_ref, member_ref):
        """Remove project member by email or id."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            mid = _lookup_user_id(cur, member_ref)
            if not mid:
                return jsonify({"error": "user not found"}), 404
            cur.execute(
                """
                DELETE FROM api.project_members
                WHERE project_id = %s::uuid AND user_id = %s::uuid
                """,
                (pid, mid),
            )
            if cur.rowcount == 0:
                return jsonify({"error": "forbidden or not a member"}), 403
            audit.log_org(
                cur,
                project_id=pid,
                action=audit.ORG_PROJECT_MEMBER_REMOVE,
                detail=member_ref,
            )
            conn.commit()
        return jsonify({"ok": True})

    # ── Trash ──────────────────────────────────────────────────────────

    @app.get("/eso/v1/projects/<project_ref>/trash")
    def mgmt_list_trash(project_ref):
        """List soft-deleted secrets in a project."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            cur.execute(
                """
                SELECT id, key, note, kind, deleted_at, updated_at
                  FROM api.secrets
                 WHERE project_id = %s::uuid AND deleted_at IS NOT NULL
                 ORDER BY deleted_at DESC
                """,
                (pid,),
            )
            items = [_row(r) for r in (cur.fetchall() or [])]
        return jsonify({"items": items})

    @app.post("/eso/v1/projects/<project_ref>/trash/<secret_id>/restore")
    def mgmt_restore_trash(project_ref, secret_id):
        """Restore a soft-deleted secret by id."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            cur.execute(
                """
                UPDATE api.secrets SET deleted_at = NULL
                 WHERE id = %s::uuid AND project_id = %s::uuid
                   AND deleted_at IS NOT NULL
                RETURNING id, key
                """,
                (secret_id, pid),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "not found or forbidden"}), 404
            audit.log_secret(
                cur,
                project_id=pid,
                action="restored",
                secret_key=row["key"],
                secret_id=row["id"],
            )
            conn.commit()
        return jsonify({"ok": True, "id": str(row["id"]), "key": row["key"]})

    @app.delete("/eso/v1/projects/<project_ref>/trash/<secret_id>")
    def mgmt_purge_trash(project_ref, secret_id):
        """Permanently purge a soft-deleted secret."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            cur.execute(
                """
                SELECT id, key FROM api.secrets
                 WHERE id = %s::uuid AND project_id = %s::uuid
                   AND deleted_at IS NOT NULL
                """,
                (secret_id, pid),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "not found"}), 404
            cur.execute(
                "DELETE FROM api.secrets WHERE id = %s::uuid",
                (str(row["id"]),),
            )
            if cur.rowcount == 0:
                return jsonify({"error": "forbidden"}), 403
            audit.log_secret(
                cur,
                project_id=pid,
                action="purged",
                secret_key=row["key"],
                secret_id=row["id"],
            )
            conn.commit()
        return jsonify({"ok": True, "id": str(row["id"]), "key": row["key"]})

    # ── Machine tokens ─────────────────────────────────────────────────

    @app.get("/eso/v1/projects/<project_ref>/tokens")
    def mgmt_list_tokens(project_ref):
        """List machine tokens (prefix only; raw secret never stored)."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            cur.execute(
                """
                SELECT id, name, token_prefix, role, expires_at, created_at
                  FROM api.machine_tokens
                 WHERE project_id = %s::uuid
                 ORDER BY created_at DESC
                """,
                (pid,),
            )
            items = [_row(r) for r in (cur.fetchall() or [])]
        return jsonify({"items": items})

    @app.post("/eso/v1/projects/<project_ref>/tokens")
    def mgmt_create_token(project_ref):
        """Create machine token. Body: name, role, expires_days.

        Returns the raw ``token`` once in the JSON body.
        """
        uid, err = _require_pat()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        name = (body.get("name") or "machine").strip() or "machine"
        role = (body.get("role") or "read-only").strip()
        if role not in config.MACHINE_TOKEN_ROLES:
            role = "read-only"
        expires_at = None
        days = body.get("expires_days")
        if days is not None:
            try:
                days = int(days)
            except (TypeError, ValueError):
                return jsonify({"error": "expires_days must be int"}), 400
            if days < 1 or days > config.MAX_EXPIRY_DAYS:
                return jsonify({"error": "expires_days out of range"}), 400
            expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        raw = "ss_" + secrets.token_urlsafe(32)
        thash = sha256_hex(raw)
        prefix = raw[:11]
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            cur.execute("SELECT api.can_write_project(%s) AS w", (pid,))
            if not (cur.fetchone() or {}).get("w"):
                return jsonify({"error": "forbidden"}), 403
            cur.execute(
                """
                INSERT INTO api.machine_tokens
                  (project_id, name, token_hash, token_prefix, role, expires_at)
                VALUES (%s::uuid, %s, %s, %s, %s, %s)
                RETURNING id, name, token_prefix, role, expires_at, created_at
                """,
                (pid, name, thash, prefix, role, expires_at),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "forbidden"}), 403
            conn.commit()
        out = _row(row) or {}
        out["ok"] = True
        out["token"] = raw  # shown once
        return jsonify(out), 201

    @app.delete("/eso/v1/projects/<project_ref>/tokens/<token_id>")
    def mgmt_delete_token(project_ref, token_id):
        """Delete a machine token by id."""
        uid, err = _require_pat()
        if err:
            return err
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            cur.execute(
                """
                DELETE FROM api.machine_tokens
                 WHERE id = %s::uuid AND project_id = %s::uuid
                """,
                (token_id, pid),
            )
            if cur.rowcount == 0:
                return jsonify({"error": "not found or forbidden"}), 404
            conn.commit()
        return jsonify({"ok": True, "id": token_id})

    # ── Secret history ─────────────────────────────────────────────────

    @app.get("/eso/v1/projects/<project_ref>/secrets/<path:key>/history")
    def mgmt_secret_history(project_ref, key):
        """List archived versions for a secret (metadata only)."""
        uid, err = _require_pat()
        if err:
            return err
        key = (key or "").strip()
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            cur.execute(
                """
                SELECT s.id AS secret_id FROM api.secrets s
                 WHERE s.project_id = %s::uuid AND s.key = %s
                   AND s.deleted_at IS NULL
                """,
                (pid, key),
            )
            srow = cur.fetchone()
            if not srow:
                return jsonify({"error": "not found"}), 404
            cur.execute(
                """
                SELECT id, note, created_at
                  FROM api.secret_versions
                 WHERE secret_id = %s::uuid
                 ORDER BY created_at DESC
                 LIMIT 50
                """,
                (str(srow["secret_id"]),),
            )
            items = [_row(r) for r in (cur.fetchall() or [])]
        return jsonify({"key": key, "items": items})

    @app.get("/eso/v1/projects/<project_ref>/audit")
    def mgmt_project_audit(project_ref):
        """List secret audit for a project (member access)."""
        uid, err = _require_pat()
        if err:
            return err
        q = (request.args.get("q") or "").strip()
        actor = (request.args.get("actor") or "").strip()
        action = (request.args.get("action") or "").strip()
        since = (request.args.get("since") or "").strip()
        until = (request.args.get("until") or "").strip()
        limit = min(200, max(1, int(request.args.get("limit") or 50)))
        with db.as_user(uid) as conn, conn.cursor() as cur:
            pid = _resolve_project(cur, project_ref)
            if not pid:
                return jsonify({"error": "not found"}), 404
            rows = audit.list_for_project(
                cur,
                pid,
                limit=limit,
                q=q,
                actor=actor,
                action=action,
                since=since,
                until=until,
            )
            items = [_row(r) for r in rows]
        return jsonify({"items": items})

    # ── Admin (global) ─────────────────────────────────────────────────

    @app.get("/eso/v1/admin/users")
    def mgmt_admin_users():
        """List users (global admin). Optional ``q`` filter."""
        uid, err = _require_pat()
        if err:
            return err
        gerr = _require_global_admin(uid)
        if gerr:
            return gerr
        q = (request.args.get("q") or "").strip()
        like = f"%{q}%" if q else None
        with db.connect_admin() as conn, conn.cursor() as cur:
            if like:
                cur.execute(
                    """
                    SELECT id, email, name, is_global_admin, auth_source,
                           disabled_at, created_at, totp_enabled_at
                      FROM private.users
                     WHERE email ILIKE %s OR name ILIKE %s
                     ORDER BY email
                     LIMIT 200
                    """,
                    (like, like),
                )
            else:
                cur.execute(
                    """
                    SELECT id, email, name, is_global_admin, auth_source,
                           disabled_at, created_at, totp_enabled_at
                      FROM private.users
                     ORDER BY email
                     LIMIT 500
                    """
                )
            items = [_row(r) for r in (cur.fetchall() or [])]
        return jsonify({"items": items})

    @app.get("/eso/v1/admin/audit")
    def mgmt_admin_audit():
        """List org or secret audit (global admin).

        Query: ``source=org|secret|access``, ``q``, ``actor``, ``since``, ``until``.
        """
        uid, err = _require_pat()
        if err:
            return err
        gerr = _require_global_admin(uid)
        if gerr:
            return gerr
        source = (request.args.get("source") or "org").strip().lower()
        q = (request.args.get("q") or "").strip()
        actor = (request.args.get("actor") or "").strip()
        since = (request.args.get("since") or "").strip()
        until = (request.args.get("until") or "").strip()
        limit = min(500, max(1, int(request.args.get("limit") or 100)))
        with db.connect_admin() as conn, conn.cursor() as cur:
            if source == "access":
                items = [_row(r) for r in audit.access_review_rows(cur)]
            elif source == "secret":
                # global secret audit — recent across projects
                extra = []
                params: list = []
                if q:
                    extra.append(
                        "(a.secret_key ILIKE %s OR a.action ILIKE %s OR a.actor_email ILIKE %s)"
                    )
                    params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
                if actor:
                    extra.append("a.actor_email ILIKE %s")
                    params.append(f"%{actor}%")
                where = ("WHERE " + " AND ".join(extra)) if extra else ""
                cur.execute(
                    f"""
                    SELECT a.id, a.project_id, a.secret_key, a.action,
                           a.actor_email, a.created_at
                      FROM api.secret_audit a
                    {where}
                     ORDER BY a.created_at DESC
                     LIMIT %s
                    """,
                    (*params, limit),
                )
                items = [_row(r) for r in (cur.fetchall() or [])]
            else:
                items = [
                    _row(r)
                    for r in audit.list_org_audit(
                        cur,
                        q=q,
                        actor=actor,
                        since=since,
                        until=until,
                        limit=limit,
                    )
                ]
        return jsonify({"source": source, "items": items})
