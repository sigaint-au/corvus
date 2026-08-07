"""Teams, members, invites, LDAP maps, project creation."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from flask import flash, redirect, render_template, request, session, url_for

import audit
import authz
import config
import db
import ldap_auth
import settings_svc


log = __import__("logging").getLogger(__name__)


def register(app):
    # ── Teams ─────────────────────────────────────────────────────────


    @app.get("/teams")
    @authz.login_required
    def teams():
        q = (request.args.get("q") or "").strip()
        like = f"%{q}%" if q else None
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            if session.get("is_global_admin"):
                sql = """
                    SELECT t.*,
                      COALESCE(tm.role, 'owner') AS role,
                      (SELECT count(*) FROM api.projects p WHERE p.team_id = t.id) AS project_count
                    FROM api.teams t
                    LEFT JOIN api.team_members tm
                      ON tm.team_id = t.id AND tm.user_id = %s
                """
                params = [session["user_id"]]
                if like:
                    sql += " WHERE t.name ILIKE %s"
                    params.append(like)
            else:
                sql = """
                    SELECT t.*, tm.role,
                      (SELECT count(*) FROM api.projects p WHERE p.team_id = t.id) AS project_count
                    FROM api.teams t
                    JOIN api.team_members tm ON tm.team_id = t.id
                    WHERE tm.user_id = %s
                """
                params = [session["user_id"]]
                if like:
                    sql += " AND t.name ILIKE %s"
                    params.append(like)
            cur.execute(sql + " ORDER BY t.name", params)
            rows = cur.fetchall()
        return render_template(
            "teams.html",
            teams=rows,
            search_q=q,
            can_create_team=settings_svc.can_create_team(session.get("is_global_admin")),
        )


    @app.post("/teams")
    @authz.login_required
    def create_team():
        if not settings_svc.can_create_team(session.get("is_global_admin")):
            flash("Only global admins can create teams", "error")
            return redirect(url_for("teams"))
        name = request.form["name"].strip()
        if not name:
            flash("Name required", "error")
            return redirect(url_for("teams"))
        with db.connect(autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT private.create_team(%s::uuid, %s) AS id",
                (session["user_id"], name),
            )
            tid = cur.fetchone()["id"]
        session["team_id"] = str(tid)
        return redirect(url_for("team_detail", team_id=tid))


    @app.get("/teams/<uuid:team_id>")
    @authz.login_required
    def team_detail(team_id):
        session["team_id"] = str(team_id)
        tab = (request.args.get("tab") or "projects").strip().lower()
        if tab not in ("projects", "members", "activity", "settings"):
            tab = "projects"
        q = (request.args.get("q") or "").strip()
        members, projects, ldap_maps, oidc_maps = [], [], [], []
        invites, join_requests, org_events = [], [], []
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM api.teams WHERE id = %s", (str(team_id),))
            team = cur.fetchone()
            if not team:
                return "Not found", 404
            cur.execute(
                "SELECT role FROM api.team_members WHERE team_id = %s AND user_id = %s",
                (str(team_id), session["user_id"]),
            )
            my = cur.fetchone()
            my_role = my["role"] if my else None
            if session.get("is_global_admin") and not my_role:
                my_role = "owner"
            is_admin = my_role in ("owner", "admin")
            if tab == "settings" and not is_admin:
                tab = "projects"

            if tab == "projects":
                if q:
                    cur.execute(
                        """
                        SELECT * FROM api.projects
                        WHERE team_id = %s AND name ILIKE %s
                        ORDER BY name
                        """,
                        (str(team_id), f"%{q}%"),
                    )
                else:
                    cur.execute(
                        "SELECT * FROM api.projects WHERE team_id = %s ORDER BY name",
                        (str(team_id),),
                    )
                projects = cur.fetchall()
            elif tab == "members":
                cur.execute(
                    "SELECT * FROM private.team_member_rows(%s::uuid)",
                    (str(team_id),),
                )
                members = cur.fetchall()
                if is_admin:
                    cur.execute(
                        """
                        SELECT id, role, expires_at, created_at, revoked_at
                        FROM api.team_invites
                        WHERE team_id = %s
                        ORDER BY created_at DESC
                        LIMIT 20
                        """,
                        (str(team_id),),
                    )
                    invites = cur.fetchall()
                    cur.execute(
                        """
                        SELECT r.id, r.role, r.user_id, r.created_at
                        FROM api.team_join_requests r
                        WHERE r.team_id = %s AND r.status = 'pending'
                        ORDER BY r.created_at
                        """,
                        (str(team_id),),
                    )
                    join_requests = cur.fetchall() or []
            elif tab == "activity":
                try:
                    org_events = audit.list_org_for_team(cur, team_id)
                except Exception:
                    org_events = []
            elif tab == "settings" and is_admin:
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
                cur.execute(
                    """
                    SELECT id, oidc_group, role, created_at
                    FROM api.team_oidc_maps
                    WHERE team_id = %s
                    ORDER BY oidc_group
                    """,
                    (str(team_id),),
                )
                oidc_maps = cur.fetchall() or []
        if join_requests:
            try:
                with db.connect_admin() as aconn, aconn.cursor() as acur:
                    for jr in join_requests:
                        acur.execute(
                            "SELECT email, name FROM private.users WHERE id = %s",
                            (str(jr["user_id"]),),
                        )
                        u = acur.fetchone() or {}
                        jr["email"] = u.get("email") or str(jr["user_id"])
                        jr["name"] = u.get("name") or ""
            except Exception:
                for jr in join_requests:
                    jr.setdefault("email", str(jr.get("user_id")))
                    jr.setdefault("name", "")
        return render_template(
            "team.html",
            team=team,
            search_q=q,
            members=members,
            projects=projects,
            my_role=my_role,
            ldap_maps=ldap_maps,
            oidc_maps=oidc_maps,
            invites=invites,
            join_requests=join_requests,
            org_events=org_events,
            invite_roles=config.INVITE_ROLES,
            new_invite_url=session.pop("new_invite_url", None),
            ldap_enabled=settings_svc.truthy(ldap_auth.ldap_cfg().get("ldap_enabled")),
            oidc_enabled=settings_svc.truthy(
                settings_svc.get_settings().get("oidc_enabled")
            ),
            active_tab=tab,
            is_admin=is_admin,
        )


    @app.post("/teams/<uuid:team_id>/members")
    @authz.login_required
    def add_team_member(team_id):
        email = request.form["email"].strip().lower()
        role = request.form.get("role", "member")
        if role not in config.TEAM_ROLES:
            role = "member"
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT private.lookup_user(%s) AS id", (email,))
            u = cur.fetchone()
            if not u or not u.get("id"):
                flash("User not found — they must register or sign in via LDAP first", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="members"))
            try:
                cur.execute(
                    """
                    SELECT role FROM api.team_members
                    WHERE team_id = %s AND user_id = %s
                    """,
                    (str(team_id), str(u["id"])),
                )
                prev = cur.fetchone()
                cur.execute(
                    """
                    INSERT INTO api.team_members (team_id, user_id, role, source)
                    VALUES (%s, %s, %s, 'manual')
                    ON CONFLICT (team_id, user_id) DO UPDATE
                      SET role = EXCLUDED.role, source = 'manual'
                    """,
                    (str(team_id), str(u["id"]), role),
                )
                if cur.rowcount == 0:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    action = audit.ORG_MEMBER_ROLE if prev else audit.ORG_MEMBER_ADD
                    detail = f"{email} → {role}"
                    if prev:
                        detail = f"{email}: {prev['role']} → {role}"
                    audit.log_org(cur, team_id=team_id, action=action, detail=detail)
                    conn.commit()
            except Exception as e:
                flash(str(e), "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="members"))


    @app.post("/teams/<uuid:team_id>/members/<uuid:user_id>/remove")
    @authz.login_required
    def remove_team_member(team_id, user_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    SELECT role FROM api.team_members
                    WHERE team_id = %s AND user_id = %s
                    """,
                    (str(team_id), str(user_id)),
                )
                row = cur.fetchone()
                if not row:
                    flash("Member not found", "error")
                    return redirect(url_for("team_detail", team_id=team_id, tab="members"))
                cur.execute(
                    "DELETE FROM api.team_members WHERE team_id = %s AND user_id = %s",
                    (str(team_id), str(user_id)),
                )
                if cur.rowcount == 0:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    audit.log_org(
                        cur,
                        team_id=team_id,
                        action=audit.ORG_MEMBER_REMOVE,
                        detail=f"user {user_id} ({row['role']})",
                    )
                    conn.commit()
                    flash("Member removed", "ok")
            except Exception as e:
                flash(str(e), "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="members"))


    @app.post("/teams/<uuid:team_id>/transfer")
    @authz.login_required
    def transfer_team_ownership(team_id):
        email = (request.form.get("email") or "").strip().lower()
        if not email:
            flash("Email required", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
            if (cur.fetchone() or {}).get("r") != "owner":
                flash("Only owners can transfer ownership", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
            cur.execute("SELECT private.lookup_user(%s) AS id", (email,))
            u = cur.fetchone()
            if not u or not u.get("id"):
                flash("User not found — they must already be registered", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
            new_uid = str(u["id"])
            if new_uid == session["user_id"]:
                flash("Already owner", "ok")
                return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
            try:
                # Promote new owner first (avoids last-owner guard)
                cur.execute(
                    """
                    INSERT INTO api.team_members (team_id, user_id, role, source)
                    VALUES (%s, %s, 'owner', 'manual')
                    ON CONFLICT (team_id, user_id) DO UPDATE
                      SET role = 'owner', source = 'manual'
                    """,
                    (str(team_id), new_uid),
                )
                cur.execute(
                    """
                    UPDATE api.team_members SET role = 'admin'
                    WHERE team_id = %s AND user_id = %s AND role = 'owner'
                    """,
                    (str(team_id), session["user_id"]),
                )
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action=audit.ORG_OWNERSHIP,
                    detail=f"ownership → {email}",
                )
                conn.commit()
                flash(f"Ownership transferred to {email}", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="settings"))


    @app.post("/teams/<uuid:team_id>/invites")
    @authz.login_required
    def create_team_invite(team_id):
        role = request.form.get("role", "member")
        if role not in config.INVITE_ROLES:
            role = "member"
        days = 7
        raw_days = (request.form.get("expires_days") or "7").strip()
        try:
            days = max(1, min(90, int(raw_days)))
        except ValueError:
            days = 7
        raw = secrets.token_urlsafe(24)
        thash = hashlib.sha256(raw.encode()).hexdigest()
        expires = datetime.now(timezone.utc) + timedelta(days=days)
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO api.team_invites
                      (team_id, token_hash, role, expires_at, created_by)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        str(team_id),
                        thash,
                        role,
                        expires,
                        session["user_id"],
                    ),
                )
                row = cur.fetchone()
                if not row:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                    return redirect(url_for("team_detail", team_id=team_id, tab="members"))
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action=audit.ORG_INVITE_CREATE,
                    detail=f"role={role} expires={days}d",
                )
                conn.commit()
            except Exception as e:
                flash(str(e), "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="members"))
        session["new_invite_url"] = url_for("redeem_invite", token=raw, _external=True)
        flash("Invite link created — copy it now (shown once)", "ok")
        return redirect(url_for("team_detail", team_id=team_id, tab="members"))


    @app.post("/teams/<uuid:team_id>/invites/<uuid:invite_id>/revoke")
    @authz.login_required
    def revoke_team_invite(team_id, invite_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE api.team_invites SET revoked_at = now()
                WHERE id = %s AND team_id = %s AND revoked_at IS NULL
                """,
                (str(invite_id), str(team_id)),
            )
            if cur.rowcount:
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action=audit.ORG_INVITE_REVOKE,
                    detail=str(invite_id),
                )
                conn.commit()
                flash("Invite revoked", "ok")
            else:
                flash("Invite not found or already revoked", "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="members"))


    @app.get("/invite/<token>")
    def redeem_invite(token):
        # Preserve invite across login (bearer token in URL is lost if bounced without context)
        if not session.get("user_id"):
            session["invite_token"] = token
            flash("Sign in to accept this team invite", "ok")
            return redirect(url_for("login"))
        thash = hashlib.sha256(token.encode()).hexdigest()
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM private.lookup_invite(%s)", (thash,))
            inv = cur.fetchone()
            if not inv:
                flash("Invite invalid or expired", "error")
                return redirect(url_for("teams"))
            # Already a member?
            cur.execute(
                """
                SELECT role FROM api.team_members
                WHERE team_id = %s AND user_id = %s
                """,
                (str(inv["team_id"]), session["user_id"]),
            )
            if cur.fetchone():
                flash(f"You are already a member of {inv['team_name']}", "ok")
                return redirect(url_for("team_detail", team_id=inv["team_id"]))
            try:
                cur.execute(
                    """
                    INSERT INTO api.team_join_requests
                      (team_id, invite_id, user_id, role, status)
                    SELECT %s, %s, %s, %s, 'pending'
                    WHERE NOT EXISTS (
                      SELECT 1 FROM api.team_join_requests
                      WHERE team_id = %s AND user_id = %s AND status = 'pending'
                    )
                    """,
                    (
                        str(inv["team_id"]),
                        str(inv["invite_id"]),
                        session["user_id"],
                        inv["role"],
                        str(inv["team_id"]),
                        session["user_id"],
                    ),
                )
                audit.log_org(
                    cur,
                    team_id=inv["team_id"],
                    action=audit.ORG_JOIN_REQUEST,
                    detail=f"via invite role={inv['role']}",
                )
                conn.commit()
                flash(
                    f"Join request sent for team “{inv['team_name']}”. "
                    "An owner or admin must approve it.",
                    "ok",
                )
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("teams"))


    @app.post("/teams/<uuid:team_id>/join-requests/<uuid:req_id>/approve")
    @authz.login_required
    def approve_join_request(team_id, req_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
            if (cur.fetchone() or {}).get("r") not in ("owner", "admin"):
                flash("Only owners or admins can approve join requests", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="members"))
            cur.execute(
                """
                SELECT id, user_id, role, status FROM api.team_join_requests
                WHERE id = %s AND team_id = %s
                """,
                (str(req_id), str(team_id)),
            )
            req = cur.fetchone()
            if not req or req["status"] != "pending":
                flash("Request not found", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="members"))
            try:
                cur.execute(
                    """
                    INSERT INTO api.team_members (team_id, user_id, role, source)
                    VALUES (%s, %s, %s, 'manual')
                    ON CONFLICT (team_id, user_id) DO UPDATE
                      SET role = EXCLUDED.role, source = 'manual'
                    """,
                    (str(team_id), str(req["user_id"]), req["role"]),
                )
                cur.execute(
                    """
                    UPDATE api.team_join_requests
                    SET status = 'approved', resolved_at = now(), resolved_by = %s
                    WHERE id = %s
                    """,
                    (session["user_id"], str(req_id)),
                )
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action=audit.ORG_JOIN_APPROVE,
                    detail=f"user={req['user_id']} role={req['role']}",
                )
                conn.commit()
                flash("Join request approved", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="members"))


    @app.post("/teams/<uuid:team_id>/join-requests/<uuid:req_id>/reject")
    @authz.login_required
    def reject_join_request(team_id, req_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
            if (cur.fetchone() or {}).get("r") not in ("owner", "admin"):
                flash("Only owners or admins can reject join requests", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="members"))
            cur.execute(
                """
                UPDATE api.team_join_requests
                SET status = 'rejected', resolved_at = now(), resolved_by = %s
                WHERE id = %s AND team_id = %s AND status = 'pending'
                """,
                (session["user_id"], str(req_id), str(team_id)),
            )
            if cur.rowcount:
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action=audit.ORG_JOIN_REJECT,
                    detail=str(req_id),
                )
                conn.commit()
                flash("Join request rejected", "ok")
            else:
                flash("Request not found", "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="members"))


    @app.post("/teams/<uuid:team_id>/settings")
    @authz.login_required
    def update_team_settings(team_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
            if (cur.fetchone() or {}).get("r") not in ("owner", "admin"):
                flash("Only owners or admins can change team settings", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
            default_token_days = None
            raw = (request.form.get("default_token_days") or "").strip()
            if raw:
                try:
                    default_token_days = int(raw)
                except ValueError:
                    flash("Default token days must be a positive integer", "error")
                    return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
                if default_token_days < 1 or default_token_days > config.MAX_EXPIRY_DAYS:
                    flash(
                        f"Default token days must be between 1 and {config.MAX_EXPIRY_DAYS}",
                        "error",
                    )
                    return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
            # Same fields as server settings; optional override flag
            class_text = (request.form.get("classification_text") or "").strip()[:120]
            class_color = (request.form.get("classification_color") or "").strip()
            class_fg = (request.form.get("classification_fg") or "").strip()
            class_show = bool(request.form.get("classification_enabled"))
            if not request.form.get("use_classification_override"):
                class_on_val = None
                class_text = ""
                class_color = ""
                class_fg = ""
            else:
                # Mirror server_settings validation
                if not class_color:
                    class_color = "#677381"
                if not class_fg:
                    class_fg = "#ffffff"
                if not config.HEX.match(class_color):
                    flash("Banner colour must be a hex value like #677381", "error")
                    return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
                if not config.HEX.match(class_fg):
                    flash("Text colour must be a hex value like #ffffff", "error")
                    return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
                if class_show and not class_text:
                    flash("Banner text is required when the banner is shown", "error")
                    return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
                class_on_val = class_show
            try:
                cur.execute(
                    """
                    UPDATE api.teams SET
                      default_token_days = %s,
                      classification_enabled = %s,
                      classification_text = %s,
                      classification_color = %s,
                      classification_fg = %s
                    WHERE id = %s
                    """,
                    (
                        default_token_days,
                        class_on_val,
                        class_text,
                        class_color,
                        class_fg,
                        str(team_id),
                    ),
                )
                if cur.rowcount == 0:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                else:
                    audit.log_org(
                        cur,
                        team_id=team_id,
                        action=audit.ORG_TEAM_SETTINGS,
                        detail=(
                            f"token_days={default_token_days or 'server'} "
                            f"class_override={class_on_val is not None} "
                            f"class_enabled={class_on_val}"
                        ),
                    )
                    conn.commit()
                    flash("Team settings saved", "ok")
            except Exception as e:
                flash(str(e), "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="settings"))


    @app.post("/teams/<uuid:team_id>/ldap-maps")
    @authz.login_required
    def add_team_ldap_map(team_id):
        ldap_group = (request.form.get("ldap_group") or "").strip()
        role = request.form.get("role", "member")
        if role not in config.TEAM_ROLES:
            role = "member"
        if not ldap_group:
            flash("LDAP group required", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO api.team_ldap_maps (team_id, ldap_group, role)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (team_id, ldap_group) DO UPDATE SET role = EXCLUDED.role
                    """,
                    (str(team_id), ldap_group, role),
                )
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action=audit.ORG_LDAP_MAP_ADD,
                    detail=f"{ldap_group} → {role}",
                )
                conn.commit()
                flash("LDAP group mapping saved — applies on next LDAP login", "ok")
            except Exception as e:
                flash(str(e), "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="settings"))


    @app.post("/teams/<uuid:team_id>/ldap-maps/<uuid:map_id>/delete")
    @authz.login_required
    def delete_team_ldap_map(team_id, map_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM api.team_ldap_maps WHERE id = %s AND team_id = %s",
                (str(map_id), str(team_id)),
            )
            if cur.rowcount:
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action=audit.ORG_LDAP_MAP_DELETE,
                    detail=str(map_id),
                )
            conn.commit()
        return redirect(url_for("team_detail", team_id=team_id, tab="settings"))

    @app.post("/teams/<uuid:team_id>/oidc-maps")
    @authz.login_required
    def add_team_oidc_map(team_id):
        oidc_group = (request.form.get("oidc_group") or "").strip()
        role = request.form.get("role", "member")
        if role not in config.TEAM_ROLES:
            role = "member"
        if not oidc_group:
            flash("OIDC group required", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO api.team_oidc_maps (team_id, oidc_group, role)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (team_id, oidc_group) DO UPDATE SET role = EXCLUDED.role
                    """,
                    (str(team_id), oidc_group, role),
                )
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action=audit.ORG_OIDC_MAP_ADD,
                    detail=f"{oidc_group} → {role}",
                )
                conn.commit()
                flash("OIDC group mapping saved — applies on next SSO login", "ok")
            except Exception as e:
                flash(str(e), "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="settings"))

    @app.post("/teams/<uuid:team_id>/oidc-maps/<uuid:map_id>/delete")
    @authz.login_required
    def delete_team_oidc_map(team_id, map_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM api.team_oidc_maps WHERE id = %s AND team_id = %s",
                (str(map_id), str(team_id)),
            )
            if cur.rowcount:
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action=audit.ORG_OIDC_MAP_DELETE,
                    detail=str(map_id),
                )
            conn.commit()
        return redirect(url_for("team_detail", team_id=team_id, tab="settings"))


    @app.post("/teams/<uuid:team_id>/projects")
    @authz.login_required
    def create_project(team_id):
        name = request.form["name"].strip()
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    "INSERT INTO api.projects (team_id, name) VALUES (%s, %s) RETURNING id",
                    (str(team_id), name),
                )
                row = cur.fetchone()
                if not row:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                    return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
                pid = row["id"]
                conn.commit()
            except Exception as e:
                flash(str(e), "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
        return redirect(url_for("project_detail", project_id=pid))


    @app.post("/teams/<uuid:team_id>/delete")
    @authz.login_required
    def delete_team(team_id):
        """Owner (or global admin via team_role) only — RLS teams_delete enforces."""
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
            row = cur.fetchone()
            if not row or row["r"] != "owner":
                flash("Only team owners can delete a team", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
            try:
                cur.execute("DELETE FROM api.teams WHERE id = %s", (str(team_id),))
                if cur.rowcount == 0:
                    flash("You don't have permission to do that", "error")
                    conn.rollback()
                    return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
                conn.commit()
            except Exception as e:
                conn.rollback()
                log.exception("delete_team failed")
                flash(str(e), "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
        if session.get("team_id") == str(team_id):
            session.pop("team_id", None)
        flash("Team deleted", "ok")
        return redirect(url_for("teams"))


    @app.post("/teams/<uuid:team_id>/projects/<uuid:project_id>/delete")
    @authz.login_required
    def delete_project_from_team(team_id, project_id):
        """Owner/admin only — RLS projects_delete enforces."""
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
            row = cur.fetchone()
            if not row or row["r"] not in ("owner", "admin"):
                flash("Only team owners or admins can delete projects", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="projects"))
            cur.execute(
                "DELETE FROM api.projects WHERE id = %s AND team_id = %s",
                (str(project_id), str(team_id)),
            )
            if cur.rowcount == 0:
                flash("You don't have permission to do that", "error")
                conn.rollback()
            else:
                conn.commit()
                flash("Project deleted", "ok")
        return redirect(url_for("team_detail", team_id=team_id, tab="projects"))


