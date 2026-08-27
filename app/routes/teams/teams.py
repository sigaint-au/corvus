"""Team list, create, detail, settings, and delete routes."""

from __future__ import annotations

import logging
import re

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import audit
from auth import authz, rbac_sync
from core import config, db, settings_svc
from integrations import ldap_auth
from ui import paging

log = logging.getLogger(__name__)


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
    name = request.form.get("name", "").strip()
    if not name:
        flash("Team name is required", "error")
        return redirect(url_for("teams"))
    with db.connect(autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT private.create_team(%s::uuid, %s) AS id",
            (session["user_id"], name),
        )
        tid = cur.fetchone()["id"]
    session["team_id"] = str(tid)
    return redirect(url_for("team_detail", team_id=tid))


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
    if tab not in ("projects", "members", "groups", "activity", "access", "settings", "webhooks"):
        tab = "projects"
    webhooks = []
    team_meta: list = []
    q = (request.args.get("q") or "").strip()
    page = paging.page_arg("page")
    members, projects, ldap_maps, oidc_maps = [], [], [], []
    hsm_count = local_count = managed_count = 0
    groups = []
    invites, join_requests, org_events = [], [], []
    activity_q = q if tab == "activity" else ""
    activity_pager = None
    access_bindings = []
    access_groups = []
    role_descriptions = {}
    can_edit_access = False
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        team = db.team(cur, team_id)
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
            my_role in ("team-owner", "team-admin")
            or bool(session.get("is_global_admin"))
            or can_edit_access
        )
        if tab in ("settings", "access", "webhooks") and not is_admin:
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
            provider_map = {}
            ids = [p["id"] for p in projects]
            if ids:
                try:
                    cur.execute(
                        "SELECT * FROM api.project_key_providers(%s::uuid[])",
                        (ids,),
                    )
                    provider_map = {
                        str(r["project_id"]): r["key_provider"] for r in (cur.fetchall() or [])
                    }
                except Exception:
                    provider_map = {}
            hsm_count = local_count = managed_count = 0
            for p in projects:
                p["key_provider"] = provider_map.get(str(p["id"]))
                if p["key_provider"] == "hsm":
                    hsm_count += 1
                elif p["key_provider"] == "local":
                    local_count += 1
                else:
                    managed_count += 1
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
        elif tab == "webhooks" and is_admin:
            from routes.webhooks_ui import load_scope_webhooks

            webhooks = load_scope_webhooks(cur, "team", team_id)
        elif tab == "access" and is_admin:
            # All team-scope bindings (users, groups, machine accounts)
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
                    r["name"]: (r.get("description") or "") for r in (cur.fetchall() or [])
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
                return redirect(url_for("team_group_detail", team_id=team_id, group_id=gid))
        elif tab == "activity":
            try:
                org_events = audit.list_org_for_team(cur, team_id, limit=1000)
            except Exception:
                org_events = []
            activity_q = (request.args.get("q") or "").strip()
            if activity_q:
                needle = activity_q.casefold()
                org_events = [
                    event
                    for event in org_events
                    if needle
                    in " ".join(
                        str(event.get(key) or "") for key in ("actor_email", "action", "detail")
                    ).casefold()
                ]
            activity_pager = paging.page_window(len(org_events), page)
            activity_pager.update(
                endpoint="team_detail",
                team_id=team_id,
                tab="activity",
                q=activity_q or None,
            )
            start = (page - 1) * activity_pager["per_page"]
            org_events = org_events[start : start + activity_pager["per_page"]]
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
        elif tab == "meta":
            cur.execute(
                "SELECT key, value, updated_at FROM api.team_meta WHERE team_id = %s ORDER BY key",
                (str(team_id),),
            )
            team_meta = cur.fetchall() or []
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
        hsm_count=hsm_count,
        local_count=local_count,
        managed_count=managed_count,
        groups=groups,
        my_role=my_role,
        ldap_maps=ldap_maps,
        oidc_maps=oidc_maps,
        invites=invites,
        join_requests=join_requests,
        org_events=org_events,
        activity_q=activity_q,
        activity_pager=activity_pager,
        access_bindings=access_bindings,
        access_groups=access_groups,
        webhooks=webhooks if tab == "webhooks" else [],
        can_edit_access=can_edit_access or is_admin,
        team_role_dropdown=config.RBAC_TEAM_ROLE_DROPDOWN,
        role_descriptions=role_descriptions,
        subject_kinds=config.RBAC_SUBJECT_KINDS,
        new_invite_url=session.pop("new_invite_url", None),
        ldap_enabled=settings_svc.truthy(ldap_auth.ldap_cfg().get("ldap_enabled")),
        oidc_enabled=settings_svc.truthy(settings_svc.get_settings().get("oidc_enabled")),
        active_tab=tab,
        is_admin=is_admin,
        team_meta=team_meta,
    )


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
        if (cur.fetchone() or {}).get("r") not in ("team-owner", "team-admin"):
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
        allow_reveal_requests = bool(request.form.get("allow_reveal_requests"))
        try:
            cur.execute(
                """
                UPDATE api.teams SET
                  default_token_days = %s,
                  classification_enabled = %s,
                  classification_text = %s,
                  classification_color = %s,
                  classification_fg = %s,
                  allow_reveal_requests = %s
                WHERE id = %s
                """,
                (
                    default_token_days,
                    class_on_val,
                    class_text,
                    class_color,
                    class_fg,
                    allow_reveal_requests,
                    str(team_id),
                ),
            )
            if cur.rowcount == 0:
                flash("Permission denied", "error")
                conn.rollback()
            else:
                audit.log_org(
                    cur,
                    team_id=team_id,
                    action=audit.ORG_TEAM_SETTINGS,
                    detail=(
                        f"token_days={default_token_days or 'server'} "
                        f"class_override={class_on_val is not None} "
                        f"class_enabled={class_on_val} "
                        f"allow_reveal_requests={allow_reveal_requests}"
                    ),
                )
                conn.commit()
                flash("Team settings saved", "ok")
        except Exception:
            flash("Could not update the team. Try again.", "error")
    return redirect(url_for("team_detail", team_id=team_id, tab="settings"))


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
        if not row or row["r"] != "team-owner":
            flash("Only team owners can delete a team", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
        try:
            cur.execute("DELETE FROM api.teams WHERE id = %s", (str(team_id),))
            if cur.rowcount == 0:
                flash("Permission denied", "error")
                conn.rollback()
                return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
            conn.commit()
        except Exception:
            conn.rollback()
            log.exception("delete_team failed")
            flash("Could not update the team. Try again.", "error")
            return redirect(url_for("team_detail", team_id=team_id, tab="settings"))
    if session.get("team_id") == str(team_id):
        session.pop("team_id", None)
    flash("Team deleted", "ok")
    return redirect(url_for("teams"))


@authz.login_required
def upsert_team_meta(team_id):
    """Add or update a team-level metadata field (owners/admins only)."""
    meta_url = url_for("team_detail", team_id=team_id, tab="meta")
    key = (request.form.get("key") or "").strip()
    value = (request.form.get("value") or "").strip()
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", key):
        flash("Metadata key must start with a letter/digit and use only A-Z, a-z, 0-9, ., _, - (max 64)", "error")
        return redirect(meta_url)
    if len(value) > 2000:
        value = value[:2000]
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
        role = (cur.fetchone() or {}).get("r")
        if role not in ("team-owner", "team-admin"):
            flash("Only owners or admins can manage team metadata", "error")
            return redirect(meta_url)
        try:
            cur.execute(
                "INSERT INTO api.team_meta (team_id, key, value, updated_at) VALUES (%s, %s, %s, now()) "
                "ON CONFLICT (team_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
                (str(team_id), key, value),
            )
            audit.log_org(cur, team_id=str(team_id), action="team_meta", detail=f"meta {key}")
            conn.commit()
            flash(f"Metadata \u201c{key}\u201d saved", "ok")
        except Exception as exc:
            conn.rollback()
            if "cannot be overridden" in str(exc):
                flash("Metadata key is defined at team/project level and cannot be overridden.", "error")
            else:
                flash("Could not save the metadata. Try again.", "error")
    return redirect(meta_url)


@authz.login_required
def delete_team_meta(team_id, meta_key):
    """Remove a team-level metadata field (owners/admins only)."""
    meta_url = url_for("team_detail", team_id=team_id, tab="meta")
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
        role = (cur.fetchone() or {}).get("r")
        if role not in ("team-owner", "team-admin"):
            flash("Only owners or admins can manage team metadata", "error")
            return redirect(meta_url)
        try:
            cur.execute(
                "DELETE FROM api.team_meta WHERE team_id = %s AND key = %s RETURNING key",
                (str(team_id), meta_key),
            )
            if not cur.fetchone():
                conn.rollback()
                flash("Field not found or not permitted", "error")
            else:
                audit.log_org(cur, team_id=str(team_id), action="team_meta", detail=f"meta {meta_key}")
                conn.commit()
                flash(f"Metadata \u201c{meta_key}\u201d removed", "ok")
        except Exception:
            conn.rollback()
            flash("Could not remove the metadata. Try again.", "error")
    return redirect(meta_url)
