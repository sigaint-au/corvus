"""Profile, password, and session-management routes."""

from __future__ import annotations

import logging

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from auth import authz, passwords, pats, totp_svc, user_sessions
from core import config, db, settings_svc
from integrations import mailer
from ui import paging, pins

log = logging.getLogger(__name__)

PROFILE_TABS = ("account", "security", "myaccess", "teams", "projects", "activity")


@authz.login_required
def update_login_alerts():
    """Save the current user's login-alert email preference.

    Ignored when server settings disable alerts or force them on.
    """
    uid = session["user_id"]
    smtp = mailer.smtp_cfg()
    if not settings_svc.truthy(smtp.get("smtp_login_alerts")):
        flash("Login alerts are disabled by an administrator", "error")
        return redirect(url_for("profile", tab="account"))
    if mailer.login_alerts_forced(smtp):
        flash("Login alerts are required by server settings", "error")
        return redirect(url_for("profile", tab="account"))
    enabled = bool(request.form.get("login_alerts"))
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE private.users SET login_alerts = %s WHERE id = %s::uuid",
                (enabled, uid),
            )
            conn.commit()
    except Exception:
        log.exception("profile: save login alerts failed")
        flash("Could not save login alert preference", "error")
        return redirect(url_for("profile", tab="account"))
    flash(
        "Login alert emails enabled" if enabled else "Login alert emails disabled",
        "ok",
    )
    return redirect(url_for("profile", tab="account"))


@authz.login_required
def change_password():
    """Change the current user's local password and revoke other sessions.

    Args:
        None (reads form ``current_password``, ``new_password``,
        ``new_password_confirm``; uses session).

    Returns:
        Redirect to profile security tab with status flash.

    Example:
        POST /profile/password
    """
    uid = session["user_id"]
    old = request.form.get("current_password") or ""
    new = request.form.get("new_password") or ""
    conf = request.form.get("new_password_confirm") or ""
    if new != conf:
        flash("New passwords do not match", "error")
        return redirect(url_for("profile", tab="security"))
    ok, err = passwords.change_password(uid, old, new)
    if not ok:
        flash(err or "Password change failed", "error")
        return redirect(url_for("profile", tab="security"))
    # Keep current session; sign out other devices after password change
    sid = session.get("sid")
    if sid:
        n = user_sessions.revoke_other_sessions(uid, sid)
        if n:
            flash(f"Password updated. Signed out {n} other session(s).", "ok")
        else:
            flash("Password updated.", "ok")
    else:
        flash("Password updated.", "ok")
    return redirect(url_for("profile", tab="security"))


@authz.login_required
def revoke_other_sessions():
    """Revoke all of the user's sessions except the current browser.

    Args:
        None (reads ``user_id`` and ``sid`` from session).

    Returns:
        Redirect to profile security tab.

    Example:
        POST /profile/sessions/revoke-others
    """
    uid = session["user_id"]
    sid = session.get("sid")
    if not sid:
        flash("No active session found for this browser", "error")
        return redirect(url_for("profile", tab="security"))
    n = user_sessions.revoke_other_sessions(uid, sid)
    flash(f"Signed out {n} other session(s).", "ok")
    return redirect(url_for("profile", tab="security"))


@authz.login_required
def revoke_session(session_id):
    """Revoke one session; signing out the current session clears cookies.

    Args:
        session_id: UUID of the session to revoke (path parameter).

    Returns:
        Redirect to login if current session was revoked, else profile security.

    Example:
        POST /profile/sessions/<uuid>/revoke
    """
    uid = session["user_id"]
    sid = str(session_id)
    if sid == session.get("sid"):
        user_sessions.revoke_session(sid, uid)
        session.clear()
        flash("Current session signed out", "ok")
        return redirect(url_for("login"))
    if user_sessions.revoke_session(sid, uid):
        flash("Session revoked", "ok")
    else:
        flash("Session not found or already revoked", "error")
    return redirect(url_for("profile", tab="security"))


@authz.login_required
def profile():
    """Render the tabbed profile page (account, security, teams, etc.).

    Args:
        None (reads query ``tab``; uses session ``user_id`` and related data).

    Returns:
        HTML profile template, or redirect if the user cannot be loaded.

    Example:
        GET /profile?tab=security
    """
    tab = (request.args.get("tab") or "account").strip().lower()
    if tab not in PROFILE_TABS:
        tab = "account"

    uid = session["user_id"]
    user = None
    groups = []
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, name, is_global_admin, auth_source, created_at,
                       totp_enabled_at, login_alerts
                FROM private.users
                WHERE id = %s::uuid
                """,
                (uid,),
            )
            user = cur.fetchone()
            if tab == "account":
                cur.execute(
                    """
                    SELECT g.id, g.name, g.source, g.external_key,
                           gm.source AS member_source,
                           t.id AS team_id, t.name AS team_name
                    FROM api.group_members gm
                    JOIN api.groups g ON g.id = gm.group_id
                    JOIN api.teams t ON t.id = g.team_id
                    WHERE gm.user_id = %s::uuid
                    ORDER BY t.name, g.name
                    """,
                    (uid,),
                )
                groups = cur.fetchall() or []
    except Exception:
        log.exception("profile: load user failed")
    if not user:
        flash("Failed to load profile", "error")
        return redirect(url_for("projects_list"))

    totp_on = bool(user.get("totp_enabled_at"))
    recovery_left = totp_svc.recovery_codes_remaining(uid) if totp_on else 0
    totp_enforced = bool(
        user.get("is_global_admin") and totp_svc.enforce_global_admins()
    )

    active_sessions = user_sessions.list_sessions(uid) if tab == "security" else []
    current_sid = session.get("sid")
    personal_tokens = []
    if tab == "security":
        try:
            personal_tokens = pats.list_for_user(uid)
        except Exception:
            log.exception("profile: list PATs failed")
            personal_tokens = []
    teams, projects, pending, pins_list, recent = [], [], [], [], []
    activity_q = (request.args.get("q") or "").strip() if tab == "activity" else ""
    recent_pager = None
    secret_count = pin_count = 0
    my_access = []
    try:
        with db.as_user(uid) as conn, conn.cursor() as cur:
            if tab in ("account", "teams"):
                cur.execute(
                    """
                    SELECT t.id, t.name,
                           api.team_role(t.id) AS role,
                           'rbac' AS source,
                           t.created_at,
                      (SELECT count(*) FROM api.projects p WHERE p.team_id = t.id)
                        AS project_count
                    FROM api.teams t
                    WHERE api.is_team_member(t.id)
                    ORDER BY t.name
                    """,
                    (),
                )
                teams = cur.fetchall() or []

            if tab in ("account", "projects"):
                cur.execute(
                    """
                    SELECT p.id, p.name, p.created_at,
                           t.id AS team_id, t.name AS team_name,
                           api.team_role(t.id) AS team_role,
                           api.project_role(p.id) AS project_role,
                      (SELECT count(*) FROM api.secrets s
                       WHERE s.project_id = p.id AND s.deleted_at IS NULL)
                        AS secret_count
                    FROM api.projects p
                    JOIN api.teams t ON t.id = p.team_id
                    WHERE api.can_read_project(p.id)
                    ORDER BY t.name, p.name
                    """,

                )
                projects = cur.fetchall() or []

            if tab == "account":
                cur.execute(
                    "SELECT count(*) AS n FROM api.secrets WHERE deleted_at IS NULL"
                )
                row = cur.fetchone()
                secret_count = int(row["n"]) if row else 0
                cur.execute(
                    """
                    SELECT count(*) AS n FROM api.secret_pins
                    WHERE user_id = %s
                    """,
                    (uid,),
                )
                row = cur.fetchone()
                pin_count = int(row["n"]) if row else 0

            if tab in ("account", "teams"):
                cur.execute(
                    """
                    SELECT r.id, r.role, r.status, r.created_at,
                           t.id AS team_id, t.name AS team_name
                    FROM api.team_join_requests r
                    JOIN api.teams t ON t.id = r.team_id
                    WHERE r.user_id = %s AND r.status = 'pending'
                    ORDER BY r.created_at DESC
                    """,
                    (uid,),
                )
                pending = cur.fetchall() or []

            if tab == "activity":
                pins_list = pins.list_pins(cur, uid)
                recent = pins.list_recent(cur, uid, limit=1000)
                if activity_q:
                    needle = activity_q.casefold()
                    recent = [
                        row
                        for row in recent
                        if needle in " ".join(
                            str(row.get(key) or "")
                            for key in ("key", "project_name", "team_name", "accessed_at")
                        ).casefold()
                    ]
                page = paging.page_arg("page")
                recent_pager = paging.page_window(len(recent), page)
                recent_pager.update(
                    endpoint="profile", tab="activity", q=activity_q or None
                )
                start = (page - 1) * recent_pager["per_page"]
                recent = recent[start : start + recent_pager["per_page"]]
            if tab == "myaccess":
                try:
                    cur.execute("SELECT * FROM api.my_access_rows()")
                    my_access = list(cur.fetchall() or [])
                except Exception:
                    conn.rollback()
                    log.exception("profile: my access rows failed")
                    my_access = []
    except Exception:
        log.exception("profile: load memberships failed")

    # Prefer DB values for session-display consistency
    session["email"] = user.get("email") or session.get("email")
    session["name"] = user.get("name") or session.get("name") or ""
    session["is_global_admin"] = bool(user.get("is_global_admin"))

    # My access: server-side scope tab + search (data may be large; keep
    # filtering off the client). Cluster rows are skipped: global admins see
    # the alert instead, and no one else can hold a cluster binding.
    _scope_labels = {
        "team": "Team access",
        "project": "Project access",
        "secret": "Secret access",
    }
    _scope_headers = {
        "team": "Team",
        "project": "Project",
        "secret": "Secret",
    }
    my_access_scope = (request.args.get("scope") or "team").strip().lower()
    if my_access_scope not in _scope_labels:
        my_access_scope = "team"
    my_access_q = (request.args.get("q") or "").strip()
    my_access_rows = []
    for row in my_access:
        if row["scope_kind"] != my_access_scope:
            continue
        if my_access_q:
            needle = my_access_q.casefold()
            hay = " ".join(
                str(row.get(k) or "")
                for k in ("scope_label", "role_name", "grant_kind", "grant_subject")
            ).casefold()
            if needle not in hay:
                continue
        my_access_rows.append(row)

    smtp = mailer.smtp_cfg()
    alerts_allowed = settings_svc.truthy(smtp.get("smtp_login_alerts"))
    alerts_forced = mailer.login_alerts_forced(smtp)
    user_alerts = True if user.get("login_alerts") is None else bool(user.get("login_alerts"))

    return render_template(
        "profile.html",
        user=user,
        groups=groups,
        login_alerts={
            "allowed": alerts_allowed,
            "forced": alerts_forced,
            "smtp_ok": mailer.smtp_configured(smtp),
            "user": user_alerts,
            "can_edit": alerts_allowed and not alerts_forced,
        },
        teams=teams if tab == "teams" else [],
        projects=projects if tab == "projects" else [],
        pending_joins=pending if tab == "teams" else [],
        pins=pins_list,
        recent=recent,
        activity_q=activity_q,
        recent_pager=recent_pager,
        active_sessions=active_sessions,
        current_sid=current_sid,
        personal_tokens=personal_tokens,
        new_pat=session.pop("new_pat", None),
        totp_enabled=totp_on,
        totp_recovery_remaining=recovery_left,
        totp_enforced_for_user=totp_enforced,
        active_tab=tab,
        postgrest_url=config.POSTGREST_URL,
        my_access_scope=my_access_scope,
        my_access_q=my_access_q,
        my_access_rows=my_access_rows,
        my_access_scope_label=_scope_labels[my_access_scope],
        my_access_scope_header=_scope_headers[my_access_scope],
        stats={
            "teams": len(teams),
            "projects": len(projects),
            "secrets": secret_count,
            "pins": pin_count,
            "pending_joins": len(pending),
        },
    )
