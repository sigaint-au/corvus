"""Teams, members, invites, LDAP maps, project creation."""

import logging
import secrets
from datetime import datetime, timedelta, timezone

from flask import flash, redirect, render_template, request, session, url_for

import audit
import authz
import config
import db
import ldap_auth
import rbac_sync
import settings_svc
from crypto import sha256_hex

log = logging.getLogger(__name__)


def register(app):
    """Register team, member, invite, and project-creation routes on the app.

    Args:
        app: Flask application instance to attach routes to.

    Returns:
        None.

    Example:
        register(app)
    """
    # ── Teams ─────────────────────────────────────────────────────────


    @app.get("/teams")
    @authz.login_required
    def teams():
        """List teams the current user can access, with optional name search.

        Returns:
            Rendered teams list template (HTML response).

        Example:
            GET /teams?q=ops
        """
        q = (request.args.get("q") or "").strip()
        like = f"%{q}%" if q else None
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            # RLS filters via is_team_member (direct + group team_role)
            sql = """
                SELECT t.*,
                  api.team_role(t.id) AS role,
                  (SELECT count(*) FROM api.projects p WHERE p.team_id = t.id) AS project_count
                FROM api.teams t
            """
            params: list = []
            if like:
                sql += " WHERE t.name ILIKE %s"
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
        """Create a new team and redirect to its detail page.

        Returns:
            Redirect to the new team detail page, or back to the teams list on error.

        Example:
            POST /teams with form field name=My Team
        """
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
        """Show team detail with projects, members, activity, or settings tab.

        Args:
            team_id: UUID of the team to display.

        Returns:
            Rendered team detail template, or a 404 response if the team is missing.

        Example:
            GET /teams/<team_id>?tab=members&q=api
        """
        session["team_id"] = str(team_id)
        tab = (request.args.get("tab") or "projects").strip().lower()
        if tab not in ("projects", "members", "groups", "activity", "access", "settings"):
            tab = "projects"
        q = (request.args.get("q") or "").strip()
        members, projects, ldap_maps, oidc_maps = [], [], [], []
        groups = []
        invites, join_requests, org_events = [], [], []
        access_bindings = []
        access_groups = []
        role_descriptions = {}
        can_edit_access = False
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM api.teams WHERE id = %s", (str(team_id),))
            team = cur.fetchone()
            if not team:
                return "Not found", 404
            cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
            my_role = (cur.fetchone() or {}).get("r")
            cur.execute(
                "SELECT api.can_manage_rbac('team', %s::uuid) AS ok",
                (str(team_id),),
            )
            can_edit_access = bool((cur.fetchone() or {}).get("ok"))
            # Team owner/admin, global admin, or anyone who can manage bindings
            is_admin = (
                my_role in ("owner", "admin")
                or bool(session.get("is_global_admin"))
                or can_edit_access
            )
            if tab in ("settings", "access") and not is_admin:
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
                # User subjects only (people + invites)

                all_b = rbac_sync.list_scope_bindings(cur, "team", team_id)
                rbac_sync.enrich_binding_emails(all_b)
                members = [
                    b
                    for b in all_b
                    if b.get("subject_kind") == "User"
                    and str(b.get("role_name") or "").startswith("team-")
                ]
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
            elif tab == "access" and is_admin:

                # All team-scope bindings (users, groups, service accounts)
                access_bindings = rbac_sync.list_scope_bindings(cur, "team", team_id)
                rbac_sync.enrich_binding_emails(access_bindings)
                cur.execute(
                    "SELECT id, name FROM api.groups WHERE team_id = %s ORDER BY name",
                    (str(team_id),),
                )
                access_groups = list(cur.fetchall() or [])
                can_edit_access = True
                try:
                    cur.execute("SELECT name, description FROM rbac.roles")
                    role_descriptions = {
                        r["name"]: (r.get("description") or "")
                        for r in (cur.fetchall() or [])
                    }
                except Exception:
                    role_descriptions = {}
            elif tab == "groups":
                try:
                    cur.execute(
                        "SELECT * FROM private.team_group_rows(%s::uuid)",
                        (str(team_id),),
                    )
                    groups = list(cur.fetchall() or [])
                except Exception:
                    groups = []
                if q:
                    ql = q.lower()
                    groups = [
                        g
                        for g in groups
                        if ql in (g.get("name") or "").lower()
                        or ql in (g.get("external_key") or "").lower()
                        or ql in (g.get("source") or "").lower()
                    ]
                # Legacy ?group_id= → dedicated group page
                gid = (request.args.get("group_id") or "").strip()
                if gid:
                    return redirect(
                        url_for("team_group_detail", team_id=team_id, group_id=gid)
                    )
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
        if access_bindings:

            rbac_sync.enrich_binding_emails(access_bindings)
        return render_template(
            "team.html",
            team=team,
            search_q=q,
            members=members,
            projects=projects,
            groups=groups,
            my_role=my_role,
            ldap_maps=ldap_maps,
            oidc_maps=oidc_maps,
            invites=invites,
            join_requests=join_requests,
            org_events=org_events,
            access_bindings=access_bindings,
            access_groups=access_groups,
            can_edit_access=can_edit_access or is_admin,
            team_role_dropdown=config.RBAC_TEAM_ROLE_DROPDOWN,
            role_descriptions=role_descriptions,
            subject_kinds=config.RBAC_SUBJECT_KINDS,
            invite_roles=config.INVITE_ROLES,
            new_invite_url=session.pop("new_invite_url", None),
            ldap_enabled=settings_svc.truthy(ldap_auth.ldap_cfg().get("ldap_enabled")),
            oidc_enabled=settings_svc.truthy(
                settings_svc.get_settings().get("oidc_enabled")
            ),
            active_tab=tab,
            is_admin=is_admin,
        )

    @app.post("/teams/<uuid:team_id>/access/bindings")
    @authz.login_required
    def team_access_binding_create(team_id):
        """Create a team-scope role binding (team admin)."""
        access_url = url_for("team_detail", team_id=team_id, tab="access")
        role_name = (request.form.get("role_name") or "").strip()
        subject_kind = (request.form.get("subject_kind") or "User").strip()
        subject_email = (request.form.get("subject_email") or "").strip().lower()
        subject_group = (request.form.get("subject_group") or "").strip()
        subject_sa = (request.form.get("subject_sa") or "").strip()
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT api.can_manage_rbac('team', %s::uuid) AS ok",
                (str(team_id),),
            )
            if not (cur.fetchone() or {}).get("ok"):
                flash("Only team admins can manage role bindings", "error")
                return redirect(access_url)
            try:
                cur.execute("SELECT id FROM rbac.roles WHERE name = %s", (role_name,))
                role = cur.fetchone()
                if not role:
                    flash("Unknown role", "error")
                    return redirect(access_url)
                subject_id = None
                if subject_kind == "User":
                    cur.execute(
                        "SELECT private.lookup_user(%s) AS id", (subject_email,)
                    )
                    u = cur.fetchone()
                    if not u or not u.get("id"):
                        flash("User not found — they must register first", "error")
                        return redirect(access_url)
                    subject_id = str(u["id"])
                elif subject_kind == "Group":
                    cur.execute(
                        """
                        SELECT id FROM api.groups
                        WHERE id = %s::uuid AND team_id = %s::uuid
                        """,
                        (subject_group, str(team_id)),
                    )
                    g = cur.fetchone()
                    if not g:
                        flash("Group not found on this team", "error")
                        return redirect(access_url)
                    subject_id = str(g["id"])
                elif subject_kind == "ServiceAccount":
                    subject_id = subject_sa
                else:
                    flash("Invalid subject kind", "error")
                    return redirect(access_url)
                if not subject_id:
                    flash("Subject required", "error")
                    return redirect(access_url)
                cur.execute(
                    """
                    INSERT INTO rbac.bindings
                      (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                    VALUES (%s::uuid, %s, %s::uuid, 'team', %s::uuid, %s::uuid)
                    """,
                    (
                        str(role["id"]),
                        subject_kind,
                        subject_id,
                        str(team_id),
                        session["user_id"],
                    ),
                )
                conn.commit()
                flash("Binding created", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(access_url)

    @app.post("/teams/<uuid:team_id>/access/bindings/<uuid:binding_id>/delete")
    @authz.login_required
    def team_access_binding_delete(team_id, binding_id):
        """Remove a team-scope role binding (team admin)."""
        access_url = url_for("team_detail", team_id=team_id, tab="access")
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT api.can_manage_rbac('team', %s::uuid) AS ok",
                (str(team_id),),
            )
            if not (cur.fetchone() or {}).get("ok"):
                flash("Only team admins can manage role bindings", "error")
                return redirect(access_url)
            try:
                cur.execute(
                    """
                    DELETE FROM rbac.bindings
                    WHERE id = %s::uuid
                      AND scope_kind = 'team'
                      AND scope_id = %s::uuid
                    """,
                    (str(binding_id), str(team_id)),
                )
                if cur.rowcount:
                    conn.commit()
                    flash("Binding removed", "ok")
                else:
                    conn.rollback()
                    flash("Binding not found or not permitted", "error")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(access_url)


    @app.post("/teams/<uuid:team_id>/members")
    @authz.login_required
    def add_team_member(team_id):
        """Add or update a team member by email and role.

        Args:
            team_id: UUID of the team to modify.

        Returns:
            Redirect to the team members tab.

        Example:
            POST /teams/<team_id>/members with email and role form fields
        """
        email = request.form["email"].strip().lower()
        role = request.form.get("role", "member")
        if role not in config.TEAM_ROLES:
            role = "member"
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            # M1: only team owners may assign owner (admins cannot self-promote)
            cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
            my_role = (cur.fetchone() or {}).get("r")
            if role == "owner" and my_role != "owner":
                flash("Only a team owner can grant the owner role", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="members"))
            cur.execute("SELECT private.lookup_user(%s) AS id", (email,))
            u = cur.fetchone()
            if not u or not u.get("id"):
                flash("User not found — they must register or sign in via LDAP first", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="members"))
            try:
                # Check for existing binding to determine add vs update
                rname = rbac_sync.TEAM_ROLE_TO_RBAC.get(role, "team-member")
                cur.execute("SELECT id FROM rbac.roles WHERE name = %s", (rname,))
                role_row = cur.fetchone()
                if not role_row:
                    flash(f"Built-in role {rname} missing — run schema ensure", "error")
                    return redirect(url_for("team_detail", team_id=team_id, tab="members"))
                # Check existing team binding for this user
                cur.execute(
                    """
                    SELECT b.id, r.name AS role_name
                    FROM rbac.bindings b
                    JOIN rbac.roles r ON r.id = b.role_id
                    WHERE b.subject_kind = 'User' AND b.subject_id = %s::uuid
                      AND b.scope_kind = 'team' AND b.scope_id = %s::uuid
                      AND r.name IN ('team-owner','team-admin','team-member','team-viewer')
                    """,
                    (str(u["id"]), str(team_id)),
                )
                prev = cur.fetchone()
                rbac_sync.sync_user_team_binding(
                    cur,
                    user_id=u["id"],
                    team_id=team_id,
                    role=role,
                    created_by=session["user_id"],
                )
                action = audit.ORG_MEMBER_ROLE if prev else audit.ORG_MEMBER_ADD
                detail = f"{email} → {role}"
                if prev:
                    detail = f"{email}: {prev['role_name']} → {role}"
                audit.log_org(cur, team_id=team_id, action=action, detail=detail)
                conn.commit()
                flash(f"Bound {email} as {role}", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="members"))


    @app.post("/teams/<uuid:team_id>/members/<uuid:user_id>/remove")
    @authz.login_required
    def remove_team_member(team_id, user_id):
        """Remove a member from a team.

        Args:
            team_id: UUID of the team.
            user_id: UUID of the user to remove.

        Returns:
            Redirect to the team members tab.

        Example:
            POST /teams/<team_id>/members/<user_id>/remove
        """
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                # Find existing team binding for this user
                cur.execute(
                    """
                    SELECT b.id, r.name AS role_name
                    FROM rbac.bindings b
                    JOIN rbac.roles r ON r.id = b.role_id
                    WHERE b.subject_kind = 'User' AND b.subject_id = %s::uuid
                      AND b.scope_kind = 'team' AND b.scope_id = %s::uuid
                      AND r.name IN ('team-owner','team-admin','team-member','team-viewer')
                    """,
                    (str(user_id), str(team_id)),
                )
                row = cur.fetchone()
                if not row:
                    flash("Member not found", "error")
                    return redirect(url_for("team_detail", team_id=team_id, tab="members"))
                rbac_sync.sync_user_team_binding(
                    cur, user_id=user_id, team_id=team_id, role=None
                )
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action=audit.ORG_MEMBER_REMOVE,
                    detail=f"user {user_id} ({row['role_name']})",
                )
                conn.commit()
                flash("Member removed", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="members"))


    @app.post("/teams/<uuid:team_id>/transfer")
    @authz.login_required
    def transfer_team_ownership(team_id):
        """Transfer team ownership to another registered user by email.

        Args:
            team_id: UUID of the team whose ownership is transferred.

        Returns:
            Redirect to the team settings tab.

        Example:
            POST /teams/<team_id>/transfer with form field email=newowner@example.com
        """
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
                rbac_sync.sync_user_team_binding(
                    cur,
                    user_id=new_uid,
                    team_id=team_id,
                    role="owner",
                    created_by=session["user_id"],
                )
                rbac_sync.sync_user_team_binding(
                    cur,
                    user_id=session["user_id"],
                    team_id=team_id,
                    role="admin",
                    created_by=session["user_id"],
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
        """Create a single-use team invite link with role and expiry.

        Args:
            team_id: UUID of the team to invite users into.

        Returns:
            Redirect to the team members tab; invite URL is stored once in session.

        Example:
            POST /teams/<team_id>/invites with role and expires_days form fields
        """
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
        thash = sha256_hex(raw)
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
        """Revoke an outstanding team invite.

        Args:
            team_id: UUID of the team that owns the invite.
            invite_id: UUID of the invite to revoke.

        Returns:
            Redirect to the team members tab.

        Example:
            POST /teams/<team_id>/invites/<invite_id>/revoke
        """
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
        """Redeem a team invite token and create a pending join request.

        Args:
            token: Raw invite token from the invite URL.

        Returns:
            Redirect to login (if unauthenticated), team detail (if already a
            member), or the teams list after submitting a join request.

        Example:
            GET /invite/<token>
        """
        # Preserve invite across login (bearer token in URL is lost if bounced without context)
        if not session.get("user_id"):
            session["invite_token"] = token
            flash("Sign in to accept this team invite", "ok")
            return redirect(url_for("login"))
        thash = sha256_hex(token)
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM private.lookup_invite(%s)", (thash,))
            inv = cur.fetchone()
            if not inv:
                flash("Invite invalid or expired", "error")
                return redirect(url_for("teams"))
            # Already a member?
            cur.execute(
                """
                SELECT 1
                FROM rbac.bindings b
                JOIN rbac.roles r ON r.id = b.role_id
                WHERE b.scope_kind = 'team' AND b.scope_id = %s::uuid
                  AND b.subject_kind = 'User' AND b.subject_id = %s::uuid
                  AND r.name IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')
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
        """Approve a pending team join request and add the user as a member.

        Args:
            team_id: UUID of the team.
            req_id: UUID of the join request to approve.

        Returns:
            Redirect to the team members tab.

        Example:
            POST /teams/<team_id>/join-requests/<req_id>/approve
        """
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
                rbac_sync.sync_user_team_binding(
                    cur,
                    user_id=req["user_id"],
                    team_id=team_id,
                    role=req["role"],
                    created_by=session["user_id"],
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
        """Reject a pending team join request.

        Args:
            team_id: UUID of the team.
            req_id: UUID of the join request to reject.

        Returns:
            Redirect to the team members tab.

        Example:
            POST /teams/<team_id>/join-requests/<req_id>/reject
        """
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
        """Update team default token expiry and optional classification banner.

        Args:
            team_id: UUID of the team to update.

        Returns:
            Redirect to the team settings tab.

        Example:
            POST /teams/<team_id>/settings with default_token_days and classification fields
        """
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
        """Add or update an LDAP group to team role mapping.

        Args:
            team_id: UUID of the team to map.

        Returns:
            Redirect to the team settings tab.

        Example:
            POST /teams/<team_id>/ldap-maps with ldap_group and role form fields
        """
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
        """Delete an LDAP group mapping for a team.

        Args:
            team_id: UUID of the team.
            map_id: UUID of the LDAP map row to delete.

        Returns:
            Redirect to the team settings tab.

        Example:
            POST /teams/<team_id>/ldap-maps/<map_id>/delete
        """
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
        """Add or update an OIDC group to team role mapping.

        Args:
            team_id: UUID of the team to map.

        Returns:
            Redirect to the team settings tab.

        Example:
            POST /teams/<team_id>/oidc-maps with oidc_group and role form fields
        """
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
        """Delete an OIDC group mapping for a team.

        Args:
            team_id: UUID of the team.
            map_id: UUID of the OIDC map row to delete.

        Returns:
            Redirect to the team settings tab.

        Example:
            POST /teams/<team_id>/oidc-maps/<map_id>/delete
        """
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
        """Create a project under the given team.

        Args:
            team_id: UUID of the parent team.

        Returns:
            Redirect to the new project detail page, or back to the team on error.

        Example:
            POST /teams/<team_id>/projects with form field name=My Project
        """
        name = request.form["name"].strip()
        description = (request.form.get("description") or "").strip()[:500]
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO api.projects (team_id, name, description)
                    VALUES (%s, %s, %s) RETURNING id
                    """,
                    (str(team_id), name, description),
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
        """Delete a team. Owner (or global admin via team_role) only — RLS teams_delete enforces.

        Args:
            team_id: UUID of the team to delete.

        Returns:
            Redirect to the teams list on success, or team settings on failure.

        Example:
            POST /teams/<team_id>/delete
        """
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
        """Delete a project from a team. Owner/admin only — RLS projects_delete enforces.

        Args:
            team_id: UUID of the parent team.
            project_id: UUID of the project to delete.

        Returns:
            Redirect to the team projects tab.

        Example:
            POST /teams/<team_id>/projects/<project_id>/delete
        """
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

    # ── Groups (team-scoped RBAC principals) ─────────────────────────

    def _group_detail_url(team_id, group_id, **extra):
        return url_for("team_group_detail", team_id=team_id, group_id=group_id, **extra)

    @app.get("/teams/<uuid:team_id>/groups/<uuid:group_id>")
    @authz.login_required
    def team_group_detail(team_id, group_id):
        """Group settings and membership (dedicated page with member search)."""
        session["team_id"] = str(team_id)
        q = (request.args.get("q") or "").strip()
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM api.teams WHERE id = %s", (str(team_id),))
            team = cur.fetchone()
            if not team:
                return "Not found", 404
            cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
            my_role = (cur.fetchone() or {}).get("r")
            is_admin = my_role in ("owner", "admin") or bool(
                session.get("is_global_admin")
            )
            cur.execute(
                """
                SELECT id, name, source, external_key, created_at
                FROM api.groups
                WHERE id = %s AND team_id = %s
                """,
                (str(group_id), str(team_id)),
            )
            group = cur.fetchone()
            if group:
                group["team_role"] = rbac_sync.group_team_roles_map(cur, team_id).get(
                    str(group_id)
                )
            if not group:
                flash("Group not found", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="groups"))
            try:
                cur.execute(
                    "SELECT * FROM private.group_member_rows(%s::uuid)",
                    (str(group_id),),
                )
                members = list(cur.fetchall() or [])
            except Exception:
                members = []
            if q:
                ql = q.lower()
                members = [
                    m
                    for m in members
                    if ql in (m.get("email") or "").lower()
                    or ql in (m.get("name") or "").lower()
                    or ql in (m.get("source") or "").lower()
                ]
        return render_template(
            "team_group.html",
            team=team,
            group=group,
            group_members=members,
            search_q=q,
            my_role=my_role,
            is_admin=is_admin,
        )

    @app.post("/teams/<uuid:team_id>/groups")
    @authz.login_required
    def create_team_group(team_id):
        """Create a team-scoped group (manual or LDAP/OIDC-mapped).

        Group membership only; grant team access via Members (Group subject binding).
        """
        name = (request.form.get("name") or "").strip()
        source = (request.form.get("source") or "manual").strip().lower()
        if source not in ("manual", "ldap", "oidc"):
            source = "manual"
        external_key = (request.form.get("external_key") or "").strip() or None
        if source == "manual":
            external_key = None
        elif not external_key:
            flash("External group key required for LDAP/OIDC groups", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="groups"))
        if not name:
            flash("Group name required", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="groups"))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO api.groups (team_id, name, source, external_key)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                    """,
                    (str(team_id), name, source, external_key),
                )
                gid = cur.fetchone()["id"]
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action="group_add",
                    detail=f"{name} ({source})",
                )
                conn.commit()
                flash(
                    f"Group “{name}” created — bind it under Members as subject Group",
                    "ok",
                )
                return redirect(_group_detail_url(team_id, gid))
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(url_for("team_detail", team_id=team_id, tab="groups"))

    @app.post("/teams/<uuid:team_id>/groups/<uuid:group_id>")
    @authz.login_required
    def update_team_group(team_id, group_id):
        """Update group name or external mapping (not team role — use RBAC binding)."""
        name = (request.form.get("name") or "").strip()
        external_key = (request.form.get("external_key") or "").strip() or None
        if not name:
            flash("Group name required", "error")
            return redirect(_group_detail_url(team_id, group_id))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    UPDATE api.groups
                    SET name = %s,
                        external_key = CASE
                          WHEN source = 'manual' THEN NULL
                          ELSE COALESCE(%s, external_key)
                        END
                    WHERE id = %s AND team_id = %s
                    RETURNING name
                    """,
                    (name, external_key, str(group_id), str(team_id)),
                )
                row = cur.fetchone()
                if not row:
                    flash("Group not found or not permitted", "error")
                    conn.rollback()
                else:
                    audit.log_org(
                        cur,
                        team_id=team_id,
                        action="group_update",
                        detail=name,
                    )
                    conn.commit()
                    flash("Group updated", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(_group_detail_url(team_id, group_id))

    @app.post("/teams/<uuid:team_id>/groups/<uuid:group_id>/delete")
    @authz.login_required
    def delete_team_group(team_id, group_id):
        """Delete a team group and its memberships/grants."""
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM api.groups
                WHERE id = %s AND team_id = %s
                RETURNING name
                """,
                (str(group_id), str(team_id)),
            )
            row = cur.fetchone()
            if not row:
                flash("Group not found or not permitted", "error")
                conn.rollback()
            else:
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action="group_delete",
                    detail=row["name"],
                )
                conn.commit()
                flash(f"Group “{row['name']}” deleted", "ok")
        return redirect(url_for("team_detail", team_id=team_id, tab="groups"))

    @app.post("/teams/<uuid:team_id>/groups/<uuid:group_id>/members")
    @authz.login_required
    def add_group_member(team_id, group_id):
        """Add a manual member to a group."""
        email = (request.form.get("email") or "").strip().lower()
        if not email:
            flash("Email required", "error")
            return redirect(_group_detail_url(team_id, group_id))
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, source FROM api.groups WHERE id = %s AND team_id = %s",
                (str(group_id), str(team_id)),
            )
            g = cur.fetchone()
            if not g:
                flash("Group not found", "error")
                return redirect(url_for("team_detail", team_id=team_id, tab="groups"))
            cur.execute("SELECT private.lookup_user(%s) AS id", (email,))
            u = cur.fetchone()
            if not u or not u.get("id"):
                flash("User not found — they must register or sign in first", "error")
                return redirect(_group_detail_url(team_id, group_id))
            try:
                cur.execute(
                    """
                    INSERT INTO api.group_members (group_id, user_id, source)
                    VALUES (%s, %s, 'manual')
                    ON CONFLICT (group_id, user_id) DO UPDATE
                      SET source = 'manual'
                    """,
                    (str(group_id), str(u["id"])),
                )
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action="group_member_add",
                    detail=email,
                )
                conn.commit()
                flash(f"Added {email}", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(_group_detail_url(team_id, group_id))

    @app.post(
        "/teams/<uuid:team_id>/groups/<uuid:group_id>/members/<uuid:user_id>/remove"
    )
    @authz.login_required
    def remove_group_member(team_id, group_id, user_id):
        """Remove a member from a group."""
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM api.group_members gm
                USING api.groups g
                WHERE gm.group_id = g.id
                  AND g.id = %s AND g.team_id = %s
                  AND gm.user_id = %s
                """,
                (str(group_id), str(team_id), str(user_id)),
            )
            if cur.rowcount:
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action="group_member_remove",
                    detail=str(user_id),
                )
                conn.commit()
                flash("Member removed from group", "ok")
            else:
                flash("Member not found or not permitted", "error")
                conn.rollback()
        return redirect(_group_detail_url(team_id, group_id))
