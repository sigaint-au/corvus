"""Projects list/detail, search, members."""

import logging

from flask import flash, redirect, render_template, request, session, url_for

import audit
import authz
import config
import db
import nav
import paging
from secret_kinds import annotate_token_expiry, expires_status, parse_secret_pairs, secret_due_status
from secret_ops import _load_secrets_page

log = logging.getLogger(__name__)

# Re-exports for tests
__all__ = ["register", "expires_status", "parse_secret_pairs", "secret_due_status"]

def register(app):
    """Register project list, detail, search, and member routes on the app.

    Args:
        app: Flask application instance to attach routes to.

    Returns:
        None.

    Example:
        register(app)
    """
    @app.get("/search")
    @authz.login_required
    def global_search():
        """Search teams, projects, and secrets the user can access.

        Overview mode (default): capped previews per section with totals and
        "view all" links. Scoped mode ``?scope=teams|projects|secrets`` returns
        a paginated single-section result set.

        Example:
            GET /search?q=database
            GET /search?q=prod&scope=secrets&kind=database&page=2
        """
        q = (request.args.get("q") or "").strip()
        scope = (request.args.get("scope") or "").strip().lower() or None
        if scope not in ("teams", "projects", "secrets", None):
            scope = None
        page = paging.page_arg()
        kind = (request.args.get("kind") or "").strip() or None
        if kind and kind not in config.SECRET_KINDS:
            kind = None
        due = (request.args.get("due") or "").strip() or None
        if due not in ("overdue", "soon", "none", None):
            due = None

        teams, projects, secrets = [], [], []
        teams_total = projects_total = secrets_total = 0
        preview = {
            "teams": 25,
            "projects": 40,
            "secrets": 50,
        }
        search_pager = None

        if q:
            like = f"%{q}%"
            with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
                if scope in (None, "teams"):
                    cur.execute(
                        "SELECT count(*) AS n FROM api.teams WHERE name ILIKE %s",
                        (like,),
                    )
                    teams_total = int((cur.fetchone() or {}).get("n") or 0)
                    if scope == "teams":
                        search_pager = paging.page_window(teams_total, page)
                        search_pager.update(
                            endpoint="global_search", q=q, scope="teams"
                        )
                        cur.execute(
                            """
                            SELECT id, name FROM api.teams
                            WHERE name ILIKE %s
                            ORDER BY name
                            LIMIT %s OFFSET %s
                            """,
                            (like, search_pager["limit"], search_pager["offset"]),
                        )
                        teams = cur.fetchall() or []
                    else:
                        cur.execute(
                            """
                            SELECT id, name FROM api.teams
                            WHERE name ILIKE %s
                            ORDER BY name
                            LIMIT %s
                            """,
                            (like, preview["teams"]),
                        )
                        teams = cur.fetchall() or []

                if scope in (None, "projects"):
                    cur.execute(
                        """
                        SELECT count(*) AS n FROM api.projects p
                        WHERE p.name ILIKE %s
                        """,
                        (like,),
                    )
                    projects_total = int((cur.fetchone() or {}).get("n") or 0)
                    if scope == "projects":
                        search_pager = paging.page_window(projects_total, page)
                        search_pager.update(
                            endpoint="global_search", q=q, scope="projects"
                        )
                        cur.execute(
                            """
                            SELECT p.id, p.name, p.description,
                                   t.name AS team_name, t.id AS team_id
                            FROM api.projects p
                            JOIN api.teams t ON t.id = p.team_id
                            WHERE p.name ILIKE %s
                            ORDER BY t.name, p.name
                            LIMIT %s OFFSET %s
                            """,
                            (like, search_pager["limit"], search_pager["offset"]),
                        )
                        projects = cur.fetchall() or []
                    else:
                        cur.execute(
                            """
                            SELECT p.id, p.name, t.name AS team_name, t.id AS team_id
                            FROM api.projects p
                            JOIN api.teams t ON t.id = p.team_id
                            WHERE p.name ILIKE %s
                            ORDER BY t.name, p.name
                            LIMIT %s
                            """,
                            (like, preview["projects"]),
                        )
                        projects = cur.fetchall() or []

                if scope in (None, "secrets"):
                    sec_where = """
                      s.deleted_at IS NULL
                      AND (
                        s.key ILIKE %s OR s.note ILIKE %s OR p.name ILIKE %s
                        OR EXISTS (
                          SELECT 1 FROM api.secret_meta m
                          WHERE m.secret_id = s.id
                            AND (m.key ILIKE %s OR m.value ILIKE %s)
                        )
                      )
                    """
                    sec_params = [like, like, like, like, like]
                    if kind:
                        sec_where += " AND s.kind = %s"
                        sec_params.append(kind)
                    if due == "overdue":
                        sec_where += (
                            " AND s.expires_at IS NOT NULL AND s.expires_at < now()"
                        )
                    elif due == "soon":
                        sec_where += """
                          AND s.expires_at IS NOT NULL
                          AND s.expires_at >= now()
                          AND s.expires_at < now() + interval '14 days'
                        """
                    elif due == "none":
                        sec_where += " AND s.expires_at IS NULL"
                    cur.execute(
                        f"""
                        SELECT count(*) AS n
                        FROM api.secrets s
                        JOIN api.projects p ON p.id = s.project_id
                        WHERE {sec_where}
                        """,
                        sec_params,
                    )
                    secrets_total = int((cur.fetchone() or {}).get("n") or 0)
                    if scope == "secrets":
                        search_pager = paging.page_window(secrets_total, page)
                        search_pager.update(
                            endpoint="global_search",
                            q=q,
                            scope="secrets",
                            kind=kind,
                            due=due,
                        )
                        lim, off = search_pager["limit"], search_pager["offset"]
                    else:
                        lim, off = preview["secrets"], 0
                    cur.execute(
                        f"""
                        SELECT s.id, s.key, s.note, s.kind, s.project_id, s.expires_at,
                               p.name AS project_name, t.name AS team_name
                        FROM api.secrets s
                        JOIN api.projects p ON p.id = s.project_id
                        JOIN api.teams t ON t.id = p.team_id
                        WHERE {sec_where}
                        ORDER BY t.name, p.name, s.key
                        LIMIT %s OFFSET %s
                        """,
                        (*sec_params, lim, off),
                    )
                    secrets = cur.fetchall() or []
                    for s in secrets:
                        s["due"] = secret_due_status(s)

        return render_template(
            "search.html",
            search_q=q,
            scope=scope,
            teams=teams,
            projects=projects,
            secrets=secrets,
            teams_total=teams_total,
            projects_total=projects_total,
            secrets_total=secrets_total,
            preview=preview,
            search_pager=search_pager,
            filter_kind=kind,
            filter_due=due,
            secret_kinds=config.SECRET_KINDS,
        )


    @app.get("/access-requests")
    @authz.login_required
    def access_requests_inbox():
        """List pending secret reveal requests the current user can approve.

        Returns:
            Rendered inbox of pending access requests across projects.

        Example:
            GET /access-requests
        """
        rows = []
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM private.pending_access_requests_for_admin()")
            rows = cur.fetchall() or []
        return render_template(
            "access_requests.html",
            requests=rows,
            grant_minutes=config.REVEAL_ACCESS_GRANT_MINUTES,
            grant_choices=config.REVEAL_ACCESS_GRANT_CHOICES,
        )

    @app.get("/projects")
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
        return render_template(
            "projects.html",
            team=team,
            projects=projects,
            search_q=q,
            projects_pager=projects_pager,
        )


    @app.get("/projects/<uuid:project_id>")
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
            can_delete = team_role in ("owner", "admin")
            # Settings: project admins manage members; team owner/admin also see danger zone
            can_settings = bool(can_admin or can_delete)

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
                # Membership moved to Access tab (RBAC bindings)
                pass
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
            subject_kinds=config.RBAC_SUBJECT_KINDS,
            secrets_pager=secrets_pager,
            audit_pager=audit_pager,

            team_groups=team_groups,
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
            acl_modes=config.SECRET_ACCESS_MODES,
            acl_mode_labels=config.SECRET_ACCESS_MODE_LABELS,
        )


    @app.post("/projects/<uuid:project_id>/delete")
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


    def _project_access_url(project_id):
        return url_for("project_detail", project_id=project_id, tab="access")

    @app.post("/projects/<uuid:project_id>/members")
    @authz.login_required
    def add_project_member(project_id):
        """Add or update a project member via RBAC binding (User + project-* role).

        Body: email + role (admin|write|read). Writes ``rbac.bindings`` only.
        """
        email = (request.form.get("email") or "").strip().lower()
        role = (request.form.get("role") or "read").strip()
        if role not in config.PROJECT_ROLES:
            role = "read"
        dest = _project_access_url(project_id)
        if not email:
            flash("Email required", "error")
            return redirect(dest)
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
                (str(project_id),),
            )
            if not (cur.fetchone() or {}).get("ok"):
                flash("You don't have permission to do that", "error")
                return redirect(dest)
            cur.execute("SELECT private.lookup_user(%s) AS id", (email,))
            u = cur.fetchone()
            if not u or not u.get("id"):
                flash(
                    "User not found — they must register or sign in via LDAP first",
                    "error",
                )
                return redirect(dest)
            cur.execute(
                "SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),)
            )
            proj = cur.fetchone()
            try:
                import rbac_sync

                rbac_sync.sync_user_project_binding(
                    cur,
                    user_id=u["id"],
                    project_id=project_id,
                    role=role,
                    created_by=session["user_id"],
                )
                audit.log_org(
                    cur,
                    team_id=proj["team_id"] if proj else None,
                    project_id=project_id,
                    action=audit.ORG_PROJECT_MEMBER_ADD,
                    detail=f"{email} → {role} (rbac)",
                )
                conn.commit()
                flash(f"Bound {email} as project-{role}", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(dest)

    @app.post("/projects/<uuid:project_id>/members/<uuid:user_id>/remove")
    @authz.login_required
    def remove_project_member(project_id, user_id):
        """Remove a user project-scope RBAC binding."""
        dest = _project_access_url(project_id)
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
                (str(project_id),),
            )
            if not (cur.fetchone() or {}).get("ok"):
                flash("You don't have permission to do that", "error")
                return redirect(dest)
            cur.execute(
                "SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),)
            )
            proj = cur.fetchone()
            try:
                import rbac_sync

                rbac_sync.sync_user_project_binding(
                    cur, user_id=user_id, project_id=project_id, role=None
                )
                audit.log_org(
                    cur,
                    team_id=proj["team_id"] if proj else None,
                    project_id=project_id,
                    action=audit.ORG_PROJECT_MEMBER_REMOVE,
                    detail=str(user_id),
                )
                conn.commit()
                flash("Project binding removed", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(dest)

    @app.post("/projects/<uuid:project_id>/group-roles")
    @authz.login_required
    def add_project_group_role(project_id):
        """Grant a team group a project role via RBAC binding only."""
        group_id = (request.form.get("group_id") or "").strip()
        role = (request.form.get("role") or "read").strip()
        if role not in config.PROJECT_ROLES:
            role = "read"
        dest = _project_access_url(project_id)
        if not group_id:
            flash("Group required", "error")
            return redirect(dest)
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
                (str(project_id),),
            )
            if not (cur.fetchone() or {}).get("ok"):
                flash("You don't have permission to do that", "error")
                return redirect(dest)
            cur.execute(
                """
                SELECT p.team_id, g.name
                FROM api.projects p
                JOIN api.groups g ON g.team_id = p.team_id AND g.id = %s
                WHERE p.id = %s
                """,
                (group_id, str(project_id)),
            )
            row = cur.fetchone()
            if not row:
                flash("Group not found on this team", "error")
                return redirect(dest)
            try:
                import rbac_sync

                rbac_sync.sync_group_project_binding(
                    cur,
                    group_id=group_id,
                    project_id=project_id,
                    role=role,
                    created_by=session["user_id"],
                )
                audit.log_org(
                    cur,
                    team_id=row["team_id"],
                    project_id=project_id,
                    action="project_group_role",
                    detail=f"{row['name']} → {role} (rbac)",
                )
                conn.commit()
                flash(f"Bound group “{row['name']}” as project-{role}", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(dest)

    @app.post("/projects/<uuid:project_id>/group-roles/<uuid:group_id>/remove")
    @authz.login_required
    def remove_project_group_role(project_id, group_id):
        """Remove a group project-scope RBAC binding."""
        dest = _project_access_url(project_id)
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
                (str(project_id),),
            )
            if not (cur.fetchone() or {}).get("ok"):
                flash("You don't have permission to do that", "error")
                return redirect(dest)
            cur.execute(
                "SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),)
            )
            proj = cur.fetchone()
            try:
                import rbac_sync

                rbac_sync.sync_group_project_binding(
                    cur,
                    group_id=group_id,
                    project_id=project_id,
                    role=None,
                    created_by=session.get("user_id"),
                )
                audit.log_org(
                    cur,
                    team_id=proj["team_id"] if proj else None,
                    project_id=project_id,
                    action="project_group_role_remove",
                    detail=str(group_id),
                )
                conn.commit()
                flash("Group project binding removed", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(dest)

    @app.post("/projects/<uuid:project_id>/access/bindings")
    @authz.login_required
    def project_access_binding_create(project_id):
        """Create a project-scope role binding (User / Group / ServiceAccount)."""
        dest = _project_access_url(project_id)
        role_name = (request.form.get("role_name") or "").strip()
        subject_kind = (request.form.get("subject_kind") or "User").strip()
        subject_email = (request.form.get("subject_email") or "").strip().lower()
        subject_group = (request.form.get("subject_group") or "").strip()
        subject_sa = (request.form.get("subject_sa") or "").strip()
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
                (str(project_id),),
            )
            if not (cur.fetchone() or {}).get("ok"):
                flash("Only project admins can manage role bindings", "error")
                return redirect(dest)
            cur.execute(
                "SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),)
            )
            proj = cur.fetchone()
            if not proj:
                flash("Project not found", "error")
                return redirect(url_for("projects"))
            try:
                import rbac_sync

                # Map built-in project-* role names or short admin/write/read
                short = rbac_sync.RBAC_TO_PROJECT_ROLE.get(role_name)
                if short:
                    role_short = short
                    rname = role_name
                elif role_name in rbac_sync.PROJECT_ROLE_TO_RBAC:
                    role_short = role_name
                    rname = rbac_sync.PROJECT_ROLE_TO_RBAC[role_name]
                else:
                    rname = role_name
                    role_short = None

                cur.execute("SELECT id FROM rbac.roles WHERE name = %s", (rname,))
                role = cur.fetchone()
                if not role:
                    flash("Unknown role", "error")
                    return redirect(dest)

                subject_id = None
                detail_who = None
                if subject_kind == "User":
                    cur.execute(
                        "SELECT private.lookup_user(%s) AS id", (subject_email,)
                    )
                    u = cur.fetchone()
                    if not u or not u.get("id"):
                        flash("User not found — they must register first", "error")
                        return redirect(dest)
                    subject_id = str(u["id"])
                    detail_who = subject_email
                    # Prefer family upsert for project-* roles
                    if role_short:
                        rbac_sync.sync_user_project_binding(
                            cur,
                            user_id=subject_id,
                            project_id=project_id,
                            role=role_short,
                            created_by=session["user_id"],
                        )
                    else:
                        cur.execute(
                            """
                            INSERT INTO rbac.bindings
                              (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                            VALUES (%s::uuid, 'User', %s::uuid, 'project', %s::uuid, %s::uuid)
                            """,
                            (
                                str(role["id"]),
                                subject_id,
                                str(project_id),
                                session["user_id"],
                            ),
                        )
                elif subject_kind == "Group":
                    cur.execute(
                        """
                        SELECT id, name FROM api.groups
                        WHERE id = %s::uuid AND team_id = %s::uuid
                        """,
                        (subject_group, str(proj["team_id"])),
                    )
                    g = cur.fetchone()
                    if not g:
                        flash("Group not found on this team", "error")
                        return redirect(dest)
                    subject_id = str(g["id"])
                    detail_who = f"group {g['name']}"
                    if role_short:
                        rbac_sync.sync_group_project_binding(
                            cur,
                            group_id=subject_id,
                            project_id=project_id,
                            role=role_short,
                            created_by=session["user_id"],
                        )
                    else:
                        cur.execute(
                            """
                            INSERT INTO rbac.bindings
                              (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                            VALUES (%s::uuid, 'Group', %s::uuid, 'project', %s::uuid, %s::uuid)
                            """,
                            (
                                str(role["id"]),
                                subject_id,
                                str(project_id),
                                session["user_id"],
                            ),
                        )
                elif subject_kind == "ServiceAccount":
                    subject_id = subject_sa
                    detail_who = f"sa {subject_sa}"
                    if not subject_id:
                        flash("Service account id required", "error")
                        return redirect(dest)
                    cur.execute(
                        """
                        INSERT INTO rbac.bindings
                          (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                        VALUES (%s::uuid, 'ServiceAccount', %s::uuid, 'project', %s::uuid, %s::uuid)
                        """,
                        (
                            str(role["id"]),
                            subject_id,
                            str(project_id),
                            session["user_id"],
                        ),
                    )
                else:
                    flash("Invalid subject kind", "error")
                    return redirect(dest)

                audit.log_org(
                    cur,
                    team_id=proj["team_id"],
                    project_id=project_id,
                    action=audit.ORG_PROJECT_MEMBER_ADD,
                    detail=f"{detail_who} → {rname}",
                )
                conn.commit()
                flash("Binding created", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(dest)

    @app.post("/projects/<uuid:project_id>/access/bindings/<uuid:binding_id>/delete")
    @authz.login_required
    def project_access_binding_delete(project_id, binding_id):
        """Remove a project-scope role binding."""
        dest = _project_access_url(project_id)
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT api.can_manage_rbac('project', %s::uuid) AS ok",
                (str(project_id),),
            )
            if not (cur.fetchone() or {}).get("ok"):
                flash("Only project admins can manage role bindings", "error")
                return redirect(dest)
            cur.execute(
                "SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),)
            )
            proj = cur.fetchone()
            try:
                cur.execute(
                    """
                    DELETE FROM rbac.bindings
                    WHERE id = %s::uuid
                      AND scope_kind = 'project'
                      AND scope_id = %s::uuid
                    RETURNING subject_kind, subject_id
                    """,
                    (str(binding_id), str(project_id)),
                )
                row = cur.fetchone()
                if not row:
                    flash("Binding not found or not permitted", "error")
                    conn.rollback()
                else:
                    audit.log_org(
                        cur,
                        team_id=proj["team_id"] if proj else None,
                        project_id=project_id,
                        action=audit.ORG_PROJECT_MEMBER_REMOVE,
                        detail=f"{row['subject_kind']}:{row['subject_id']}",
                    )
                    conn.commit()
                    flash("Binding removed", "ok")
            except Exception as e:
                conn.rollback()
                flash(str(e), "error")
        return redirect(dest)

    @app.post("/projects/<uuid:project_id>/settings")
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
        default_acl = (request.form.get("default_acl_mode") or "inherit").strip().lower()
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
                SET require_reveal_approval = %s, description = %s, default_acl_mode = %s
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
                    detail=f"require_reveal_approval={require_on}, default_acl_mode={default_acl}",
                )
                conn.commit()
                flash("Project settings saved", "ok")
        return redirect(url_for("project_detail", project_id=project_id, tab="settings"))
