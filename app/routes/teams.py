"""Teams, members, LDAP maps, project creation."""

from flask import flash, redirect, render_template, request, session, url_for

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
        q = (request.args.get("q") or "").strip()
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM api.teams WHERE id = %s", (str(team_id),))
            team = cur.fetchone()
            if not team:
                return "Not found", 404
            cur.execute(
                """
                SELECT tm.role, tm.source, u.id AS user_id, u.email, u.name
                FROM api.team_members tm
                JOIN api.user_directory u ON u.id = tm.user_id
                WHERE tm.team_id = %s ORDER BY tm.role, u.email
                """,
                (str(team_id),),
            )
            members = cur.fetchall()
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
            cur.execute(
                "SELECT role FROM api.team_members WHERE team_id = %s AND user_id = %s",
                (str(team_id), session["user_id"]),
            )
            my = cur.fetchone()
            my_role = my["role"] if my else None
            if session.get("is_global_admin") and not my_role:
                my_role = "owner"
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
        return render_template(
            "team.html",
            team=team,
            search_q=q,
            members=members,
            projects=projects,
            my_role=my_role,
            ldap_maps=ldap_maps,
            ldap_enabled=settings_svc.truthy(ldap_auth.ldap_cfg().get("ldap_enabled")),
        )


    @app.post("/teams/<uuid:team_id>/members")
    @authz.login_required
    def add_team_member(team_id):
        email = request.form["email"].strip().lower()
        role = request.form.get("role", "member")
        if role not in config.TEAM_ROLES:
            role = "member"
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM api.user_directory WHERE email = %s", (email,))
            u = cur.fetchone()
            if not u:
                flash("User not found — they must register or sign in via LDAP first", "error")
                return redirect(url_for("team_detail", team_id=team_id))
            try:
                cur.execute(
                    """
                    INSERT INTO api.team_members (team_id, user_id, role, source)
                    VALUES (%s, %s, %s, 'manual')
                    ON CONFLICT (team_id, user_id) DO UPDATE
                      SET role = EXCLUDED.role, source = 'manual'
                    """,
                    (str(team_id), str(u["id"]), role),
                )
                conn.commit()
            except Exception as e:
                flash(str(e), "error")
        return redirect(url_for("team_detail", team_id=team_id))


    @app.post("/teams/<uuid:team_id>/ldap-maps")
    @authz.login_required
    def add_team_ldap_map(team_id):
        ldap_group = (request.form.get("ldap_group") or "").strip()
        role = request.form.get("role", "member")
        if role not in config.TEAM_ROLES:
            role = "member"
        if not ldap_group:
            flash("LDAP group required", "error")
            return redirect(url_for("team_detail", team_id=team_id))
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
                conn.commit()
                flash("LDAP group mapping saved — applies on next LDAP login", "ok")
            except Exception as e:
                flash(str(e), "error")
        return redirect(url_for("team_detail", team_id=team_id))


    @app.post("/teams/<uuid:team_id>/ldap-maps/<uuid:map_id>/delete")
    @authz.login_required
    def delete_team_ldap_map(team_id, map_id):
        with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM api.team_ldap_maps WHERE id = %s AND team_id = %s",
                (str(map_id), str(team_id)),
            )
            conn.commit()
        return redirect(url_for("team_detail", team_id=team_id))


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
                pid = cur.fetchone()["id"]
                conn.commit()
            except Exception as e:
                flash(str(e), "error")
                return redirect(url_for("team_detail", team_id=team_id))
        return redirect(url_for("project_detail", project_id=pid))


