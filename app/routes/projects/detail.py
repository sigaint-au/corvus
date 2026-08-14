"""Project list, detail, settings, and delete routes."""

from __future__ import annotations

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
import audit
import authz
import config
import db
import hsm
import nav
import paging
from secret_kinds import (
    annotate_token_expiry,
    secret_due_status,
)
from secret_ops import _load_secrets_page


@authz.login_required
def projects_list():
    """List projects for the active team with search and pagination.

    Example:
        GET /projects?q=api&page=2
    """
    tid = nav.ensure_active_team(session["user_id"])
    q = paging.list_state_q()
    page = paging.page_arg()
    team, projects = None, []
    projects_pager = None
    if tid:
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM api.teams WHERE id = %s", (tid,))
            team = cur.fetchone()
            if team:
                where = "p.team_id = %s"
                params: list = [tid]
                if q:
                    like = f"%{q}%"
                    where += " AND (p.name ILIKE %s OR COALESCE(p.description, '') ILIKE %s)"
                    params.extend([like, like])
                cur.execute(
                    f"SELECT count(*) AS n FROM api.projects p WHERE {where}",
                    params,
                )
                total = int((cur.fetchone() or {}).get("n") or 0)
                projects_pager = paging.page_window(total, page)
                projects_pager.update(endpoint="projects_list", q=q or None)
                cur.execute(
                    f"""
                    SELECT p.id, p.name, p.description, p.created_at,
                      (
                        SELECT count(*) FROM api.secrets s
                        WHERE s.project_id = p.id AND s.deleted_at IS NULL
                      ) AS secret_count
                    FROM api.projects p
                    WHERE {where}
                    ORDER BY p.name
                    LIMIT %s OFFSET %s
                    """,
                    (*params, projects_pager["limit"], projects_pager["offset"]),
                )
                projects = cur.fetchall() or []
                provider_map = {}
                ids = [p["id"] for p in projects]
                if ids:
                    try:
                        cur.execute(
                            "SELECT * FROM api.project_key_providers(%s::uuid[])",
                            (ids,),
                        )
                        provider_map = {
                            str(r["project_id"]): r["key_provider"]
                            for r in (cur.fetchall() or [])
                        }
                    except Exception:
                        provider_map = {}
                for p in projects:
                    p["key_provider"] = provider_map.get(str(p["id"]))
    return render_template(
        "projects.html",
        team=team,
        projects=projects,
        search_q=q,
        projects_pager=projects_pager,
    )


@authz.login_required
def project_detail(project_id):
    """Show project detail for secrets, audit, access, tokens, import, integrations, or settings.

    Args:
        project_id: UUID of the project to display.

    Returns:
        Rendered project detail template, or a 404 response if missing.

    Example:
        GET /projects/<project_id>?tab=secrets&page=1&q=API
    """
    tab = (request.args.get("tab") or "secrets").strip().lower()
    # Legacy ?tab=access for reveal requests → requests
    if tab == "access" and request.args.get("legacy") is None:
        # Prefer RBAC Access when admin lands on bare "access" after rename:
        # keep reveal requests under "requests". Old bookmarks to tab=access
        # with pending badges still work if we map only non-admin... Use
        # "requests" for reveal; "access" for RBAC.
        pass
    if tab not in (
        "secrets",
        "audit",
        "access",
        "requests",
        "tokens",
        "import",
        "integrations",
        "settings",
    ):
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
    project_secret_keys = []

    team_groups = []
    access_requests = []
    access_pending_count = 0
    access_bindings = []
    access_groups = []
    effective_access = []
    role_descriptions = {}
    can_edit_access = False
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
        can_delete = team_role in ("team-owner", "team-admin")
        # Key management is an org-level policy: team owner/admin or global admin.
        cur.execute("SELECT api.is_global_admin() AS g", ())
        is_global_admin = bool((cur.fetchone() or {}).get("g"))
        can_manage_keys = bool(is_global_admin or team_role in ("team-owner", "team-admin"))
        # Settings: project admins manage members; team owner/admin also see danger zone
        can_settings = bool(can_admin or can_delete)
        project_crypto = None
        project_master_rows = 0

        if tab == "settings" and not can_settings:
            tab = "secrets"
        if tab == "access" and not can_admin:
            # Old Access tab was reveal requests; non-admins land on Requests
            tab = "requests"
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
        elif tab in ("tokens", "integrations"):
            if tab == "tokens":
                cur.execute(
                    """
                    SELECT id, name, token_prefix, role, created_at, expires_at, last_used_at
                    FROM api.machine_tokens
                    WHERE project_id = %s
                    ORDER BY created_at DESC
                    """,
                    (str(project_id),),
                )
                tokens = annotate_token_expiry(cur.fetchall())
                # Attach scope allow-list summary (empty = unrestricted)
                tids = [str(t["id"]) for t in tokens]
                scope_map: dict = {}
                if tids:
                    try:
                        cur.execute(
                            """
                            SELECT token_id, secret_key, key_pattern
                            FROM api.machine_token_scope
                            WHERE token_id = ANY(%s::uuid[])
                            ORDER BY secret_key NULLS LAST, key_pattern NULLS LAST
                            """,
                            (tids,),
                        )
                        for sc in cur.fetchall() or []:
                            scope_map.setdefault(str(sc["token_id"]), []).append(sc)
                    except Exception:
                        scope_map = {}
                for t in tokens:
                    t["scopes"] = scope_map.get(str(t["id"]), [])
            # Suggest existing keys for the allow-list chip input
            try:
                cur.execute(
                    """
                    SELECT key FROM api.secrets
                    WHERE project_id = %s AND deleted_at IS NULL
                    ORDER BY key
                    LIMIT 200
                    """,
                    (str(project_id),),
                )
                project_secret_keys = [r["key"] for r in (cur.fetchall() or [])]
            except Exception:
                project_secret_keys = []
        elif tab == "settings":
            import project_keys

            project_crypto = project_keys.project_crypto_status(project_id)
            project_master_rows = project_keys.count_master_rows(project_id)
        elif tab == "access" and can_admin:
            import rbac_sync

            cur.execute(
                "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
                (str(project_id),),
            )
            can_edit_access = bool((cur.fetchone() or {}).get("ok")) or bool(
                can_admin
            )
            access_bindings = rbac_sync.list_scope_bindings(
                cur, "project", project_id
            )
            try:
                cur.execute(
                    "SELECT * FROM api.effective_access_rows('project', %s::uuid)",
                    (str(project_id),),
                )
                effective_access = list(cur.fetchall() or [])
            except Exception:
                conn.rollback()
                effective_access = []
            try:
                cur.execute(
                    """
                    SELECT id, name FROM api.groups
                    WHERE team_id = %s ORDER BY name
                    """,
                    (str(project["team_id"]),),
                )
                access_groups = list(cur.fetchall() or [])
            except Exception:
                access_groups = []
            try:
                cur.execute("SELECT name, description FROM rbac.roles")
                role_descriptions = {
                    r["name"]: (r.get("description") or "")
                    for r in (cur.fetchall() or [])
                }
            except Exception:
                role_descriptions = {}
        elif tab == "requests":
            cur.execute(
                "SELECT * FROM private.secret_access_request_rows(%s::uuid)",
                (str(project_id),),
            )
            access_requests = cur.fetchall() or []
        # Pending count for Requests tab badge (admins see all; others their own)
        try:
            if can_admin:
                cur.execute(
                    """
                    SELECT count(*) AS n FROM api.secret_access_requests
                    WHERE project_id = %s AND status = 'pending'
                    """,
                    (str(project_id),),
                )
            else:
                cur.execute(
                    """
                    SELECT count(*) AS n FROM api.secret_access_requests
                    WHERE project_id = %s AND status = 'pending'
                      AND user_id = %s
                    """,
                    (str(project_id), session["user_id"]),
                )
            access_pending_count = int((cur.fetchone() or {}).get("n") or 0)
        except Exception:
            access_pending_count = 0
        # import: no extra queries
    if access_bindings:
        import rbac_sync

        rbac_sync.enrich_binding_emails(access_bindings)
    import settings_svc

    public_base = settings_svc.public_base_url(request.url_root or "")
    return render_template(
        "project.html",
        project=project,
        project_id=project_id,
        secrets=secret_rows,
        tokens=tokens,
        project_secret_keys=project_secret_keys,
        audit_log=audit_rows,
        access_requests=access_requests,
        access_pending_count=access_pending_count,
        access_bindings=access_bindings,
        access_groups=access_groups,
        effective_access=effective_access,
        can_edit_access=can_edit_access,
        project_role_dropdown=config.RBAC_PROJECT_ROLE_DROPDOWN,
        role_descriptions=role_descriptions,
        subject_kinds=config.RBAC_SUBJECT_KINDS,
        secrets_pager=secrets_pager,
        audit_pager=audit_pager,

        team_groups=team_groups,
        default_token_days=default_token_days,
        can_write=can_write,
        can_admin=can_admin,
        can_delete=can_delete,
        can_settings=can_settings,
        can_manage_keys=can_manage_keys,
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
        soon_days=14,
        public_base_url=public_base,
        max_expiry_days=config.MAX_EXPIRY_DAYS,
        grant_minutes=config.REVEAL_ACCESS_GRANT_MINUTES,
        grant_choices=config.REVEAL_ACCESS_GRANT_CHOICES,
        require_reveal_approval=bool(
            project.get("require_reveal_approval")
        )
        if project
        else False,
        access_modes=config.ACCESS_MODES,
        access_mode_labels=config.ACCESS_MODE_LABELS,
        project_crypto=project_crypto,
        project_master_rows=project_master_rows,
        hsm_available=hsm.available(),
    )


@authz.login_required
def delete_project(project_id):
    """Delete project (and secrets/tokens via CASCADE). Team owner/admin only.

    Args:
        project_id: UUID of the project to delete.

    Returns:
        Redirect to the parent team detail on success, or project/list on error.

    Example:
        POST /projects/<project_id>/delete
    """
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
        if row["r"] not in ("team-owner", "team-admin"):
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


@authz.login_required
def update_project_settings(project_id):
    """Update project reveal-approval default and related settings.

    Args:
        project_id: UUID of the project.

    Returns:
        Redirect to the project settings tab.

    Example:
        POST /projects/<project_id>/settings with require_reveal_approval
    """
    require = (request.form.get("require_reveal_approval") or "").strip().lower()
    require_on = require in ("1", "true", "yes", "on")
    description = (request.form.get("description") or "").strip()[:500]
    default_acl = (request.form.get("default_access_mode") or "inherit").strip().lower()
    if default_acl not in ("inherit", "restricted"):
        default_acl = "inherit"
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
        if not (cur.fetchone() or {}).get("a"):
            flash("You don't have permission to do that", "error")
            return redirect(
                url_for("project_detail", project_id=project_id, tab="settings")
            )
        cur.execute(
            """
            UPDATE api.projects
            SET require_reveal_approval = %s, description = %s, default_access_mode = %s
            WHERE id = %s
            """,
            (require_on, description, default_acl, str(project_id)),
        )
        if cur.rowcount == 0:
            flash("Project not found or not permitted", "error")
            conn.rollback()
        else:
            cur.execute(
                "SELECT team_id FROM api.projects WHERE id = %s",
                (str(project_id),),
            )
            proj = cur.fetchone()
            audit.log_org(
                cur,
                team_id=proj["team_id"] if proj else None,
                project_id=project_id,
                action="project_settings",
                detail=f"require_reveal_approval={require_on}, default_access_mode={default_acl}",
            )
            conn.commit()
            flash("Project settings saved", "ok")
    return redirect(url_for("project_detail", project_id=project_id, tab="settings"))


@authz.login_required
def project_crypto_action(project_id):
    """Manage the project's data-encryption key (BYOK).

    Actions:
        - ``adopt``: create the project key if absent, then re-encrypt any
          master-keyed secrets/versions onto it.

    Args:
        project_id: UUID of the project.

    Returns:
        Redirect to the project Settings tab.

    Example:
        POST /projects/<project_id>/crypto with action=adopt
    """
    action = (request.form.get("action") or "").strip().lower()
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),)
        )
        proj = cur.fetchone() or {}
        if not proj:
            flash("Project not found", "error")
            return redirect(
                url_for("project_detail", project_id=project_id, tab="settings")
            )
        team_id = proj.get("team_id")
        cur.execute("SELECT api.is_global_admin() AS g", ())
        is_global_admin = bool((cur.fetchone() or {}).get("g"))
        cur.execute("SELECT api.team_role(%s::uuid) AS r", (str(team_id),))
        team_role = (cur.fetchone() or {}).get("r")
    if not (is_global_admin or team_role in ("team-owner", "team-admin")):
        flash("Only team owners, team admins, or global admins can manage the project key", "error")
        return redirect(
            url_for("project_detail", project_id=project_id, tab="settings")
        )
    if action == "adopt":
        import project_keys

        provider = (request.form.get("provider") or "local").strip().lower()
        if provider not in ("local", "hsm"):
            provider = "local"
        if provider == "hsm" and not hsm.available():
            flash("External HSM is not configured", "error")
            return redirect(
                url_for("project_detail", project_id=project_id, tab="settings")
            )
        try:
            created = project_keys.ensure_project_key(project_id, provider=provider)
            n = project_keys.adopt_project_key(project_id, provider=provider)
        except Exception as e:
            flash(f"Key adoption failed: {e}", "error")
            return redirect(
                url_for("project_detail", project_id=project_id, tab="settings")
            )
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            audit.log_org(
                cur,
                team_id=team_id,
                project_id=project_id,
                action="project_key_adopted",
                detail=f"provider={provider} re-encrypted={n}"
                + (" (key created)" if created else ""),
            )
            conn.commit()
        flash(f"Project key adopted — re-encrypted {n} secret row(s)", "ok")
    elif action == "migrate":
        import project_keys

        new_provider = (request.form.get("provider") or "hsm").strip().lower()
        if new_provider not in ("local", "hsm"):
            new_provider = "hsm"
        if new_provider == "hsm" and not hsm.available():
            flash("External HSM is not configured", "error")
            return redirect(
                url_for("project_detail", project_id=project_id, tab="settings")
            )
        try:
            n = project_keys.migrate_project_key(project_id, new_provider)
        except Exception as e:
            flash(f"Key migration failed: {e}", "error")
            return redirect(
                url_for("project_detail", project_id=project_id, tab="settings")
            )
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            audit.log_org(
                cur,
                team_id=team_id,
                project_id=project_id,
                action="project_key_migrated",
                detail=f"to={new_provider} re-encrypted={n}",
            )
            conn.commit()
        flash(f"Project key migrated to {new_provider} — re-encrypted {n} row(s)", "ok")
    else:
        flash("Unknown encryption action", "error")
    return redirect(url_for("project_detail", project_id=project_id, tab="settings"))
