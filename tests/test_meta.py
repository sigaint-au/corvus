"""Team/project metadata inheritance: schema + routes (DB mocked, no Postgres)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from core import db as core_db

from tests.helpers import REPO_ROOT, mock_conn as _conn

MIGRATION = REPO_ROOT / "db" / "migrations" / "0017_team_project_meta.sql"


def migration_sql() -> str:
    return MIGRATION.read_text()


def _login(client, uid):
    with client.session_transaction() as s:
        s["user_id"] = str(uid)
        s["email"] = "u@example.com"


class TestSchema:
    def test_migration_file_exists(self):
        assert MIGRATION.exists()

    def test_team_meta_table(self):
        sql = migration_sql()
        assert "CREATE TABLE IF NOT EXISTS api.team_meta" in sql
        assert "REFERENCES api.teams(id) ON DELETE CASCADE" in sql
        assert "PRIMARY KEY (team_id, key)" in sql
        assert "key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'" in sql

    def test_project_meta_table(self):
        sql = migration_sql()
        assert "CREATE TABLE IF NOT EXISTS api.project_meta" in sql
        assert "REFERENCES api.projects(id) ON DELETE CASCADE" in sql
        assert "PRIMARY KEY (project_id, key)" in sql

    def test_guard_function_and_triggers(self):
        sql = migration_sql()
        assert "FUNCTION private.guard_meta_precedence()" in sql
        assert "is defined at team level and cannot be overridden" in sql
        assert "is defined at project level and cannot be overridden" in sql
        for table in ("team_meta", "project_meta", "secret_meta"):
            assert f"CREATE TRIGGER {table}_guard BEFORE INSERT OR UPDATE ON api.{table}" in sql

    def test_rls_policies(self):
        sql = migration_sql()
        for frag in (
            "ENABLE ROW LEVEL SECURITY",
            "api.team_role(team_id) IS NOT NULL",
            "api.team_role(team_id) IN ('team-owner', 'team-admin')",
            "api.can_read_project(project_id)",
            "api.can_admin_project(project_id)",
        ):
            assert frag in sql, frag

    def test_grants(self):
        sql = migration_sql()
        assert "GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_meta, api.project_meta TO authenticated" in sql
        assert "GRANT EXECUTE ON FUNCTION private.guard_meta_precedence() TO authenticator, authenticated" in sql

    def test_secret_meta_rows_returns_source(self):
        sql = migration_sql()
        assert "CREATE OR REPLACE FUNCTION private.secret_meta_rows(p_secret uuid)" in sql
        assert "RETURNS TABLE(key text, value text, updated_at timestamptz, source text)" in sql
        assert "source = 'secret'" in sql
        assert "source = 'project'" in sql
        assert "'team' AS source" in sql


class TestTeamMetaRoutes:
    def setup_method(self, method=None):
        import app as store

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.tid = uuid4()
        _login(self.client, uuid4())

    def test_upsert_ok(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"r": "team-owner"}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(
                f"/teams/{self.tid}/meta",
                data={"key": "mark.hahl.team", "value": "team1"},
            )
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.team_meta" in sql
        assert "ON CONFLICT (team_id, key) DO UPDATE" in sql
        conn.commit.assert_called()

    def test_upsert_denied_for_non_admin(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"r": "team-member"}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(
                f"/teams/{self.tid}/meta",
                data={"key": "k", "value": "v"},
            )
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.team_meta" not in sql
        conn.commit.assert_not_called()

    def test_upsert_bad_key_redirects_without_insert(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"r": "team-owner"}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(
                f"/teams/{self.tid}/meta",
                data={"key": "bad key!", "value": "v"},
            )
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.team_meta" not in sql

    def test_delete_ok(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"r": "team-admin"}, {"key": "k"}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(f"/teams/{self.tid}/meta/k/delete")
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "DELETE FROM api.team_meta" in sql
        conn.commit.assert_called()


class TestTeamMetaTemplates:
    def test_team_subnav_has_meta_link(self):
        src = (REPO_ROOT / "app" / "templates" / "team.html").read_text()
        assert "tab='meta'" in src or 'tab="meta"' in src
        assert "upsert_team_meta" in src

    def test_team_meta_registered(self):
        from tests.helpers import routes_module_src

        src = routes_module_src("teams")
        assert '"/teams/<uuid:team_id>/meta"' in src
        assert '"/teams/<uuid:team_id>/meta/<meta_key>/delete"' in src


class TestProjectMetaRoutes:
    def setup_method(self, method=None):
        import app as store

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        _login(self.client, uuid4())

    def test_upsert_ok(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"a": True}, {"team_id": str(uuid4())}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(
                f"/projects/{self.pid}/meta",
                data={"key": "env", "value": "prod"},
            )
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.project_meta" in sql
        conn.commit.assert_called()

    def test_upsert_denied(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"a": False}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(f"/projects/{self.pid}/meta", data={"key": "env", "value": "prod"})
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.project_meta" not in sql
        conn.commit.assert_not_called()

    def test_delete_ok(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"a": True}, {"team_id": str(uuid4())}, {"key": "env"}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(f"/projects/{self.pid}/meta/env/delete")
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "DELETE FROM api.project_meta" in sql
        conn.commit.assert_called()

    def test_project_meta_template_and_registration(self):
        from tests.helpers import routes_module_src

        subnav = (REPO_ROOT / "app" / "templates" / "project.html").read_text()
        assert "tab='meta'" in subnav
        content = (REPO_ROOT / "app" / "templates" / "partials" / "project_content.html").read_text()
        assert "project_meta.html" in content
        assert (REPO_ROOT / "app" / "templates" / "partials" / "project_meta.html").exists()
        src = routes_module_src("projects")
        assert '"/projects/<uuid:project_id>/meta"' in src
        assert '"/projects/<uuid:project_id>/meta/<meta_key>/delete"' in src


class TestSecretMetaOverride:
    def setup_method(self, method=None):
        import app as store

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        self.sid = uuid4()
        _login(self.client, uuid4())

    def test_override_violation_flashes_friendly_error(self):
        conn, cur = _conn()

        def execute(sql, *a, **k):
            if "INSERT INTO api.secret_meta" in sql:
                raise Exception("metadata key mark.hahl.team is defined at team level and cannot be overridden")
            if "api.can_access_secret" in sql:
                cur.fetchone.side_effect = [{"w": True}]
            else:
                cur.fetchone.return_value = {}

        cur.execute.side_effect = execute
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(
                f"/projects/{self.pid}/secrets/{self.sid}/meta",
                data={"key": "mark.hahl.team", "value": "x"},
            )
        assert resp.status_code == 302

    def test_template_shows_source_and_hides_remove_for_inherited(self):
        src = (REPO_ROOT / "app" / "templates" / "secret_view.html").read_text()
        assert "m.source" in src
        assert "inherited" in src.lower()


class TestMgmtSecretMetaOverride:
    def setup_method(self, method=None):
        import app as store
        from auth import pats

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        self.sid = uuid4()
        self.uid = uuid4()
        self.headers = {"Authorization": "Bearer pat_test"}
        self._pats = patch.object(pats, "resolve", return_value=self.uid)

    def test_upsert_override_returns_409(self):
        conn, cur = _conn()

        def execute(sql, *a, **k):
            if "INSERT INTO api.secret_meta" in sql:
                raise Exception("metadata key k is defined at team level and cannot be overridden")
            if "api.can_access_secret" in sql:
                cur.fetchone.side_effect = [{"w": True}]
            else:
                cur.fetchone.return_value = {"id": str(self.sid)}

        cur.execute.side_effect = execute
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.patch(
                f"/api/v1/manage/projects/{self.pid}/secrets/mykey/meta",
                json={"key": "k", "value": "x"},
                headers=self.headers,
            )
        assert resp.status_code == 409


class TestMgmtTeamMeta:
    def setup_method(self, method=None):
        import app as store
        from auth import pats

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.tid = uuid4()
        self.uid = uuid4()
        self.headers = {"Authorization": "Bearer pat_test"}
        self._pats = patch.object(pats, "resolve", return_value=self.uid)

    def test_requires_pat(self):
        with self._pats:
            resp = self.client.patch(
                f"/api/v1/manage/teams/{self.tid}/meta/k",
                json={"value": "v"},
                headers={"Authorization": "Bearer ss_notapat"},
            )
        assert resp.status_code == 401

    def test_upsert_ok(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"id": str(self.tid)}, {"r": "team-owner"}]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.patch(
                f"/api/v1/manage/teams/{self.tid}/meta/mark.hahl.team",
                json={"value": "team1"},
                headers=self.headers,
            )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True and body["meta_key"] == "mark.hahl.team"
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.team_meta" in sql
        conn.commit.assert_called()

    def test_upsert_bad_key_400(self):
        conn, cur = _conn()
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.patch(
                f"/api/v1/manage/teams/{self.tid}/meta/bad%20key",
                json={"value": "v"},
                headers=self.headers,
            )
        assert resp.status_code == 400

    def test_upsert_denied_403(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"id": str(self.tid)}, {"r": "team-member"}]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.patch(
                f"/api/v1/manage/teams/{self.tid}/meta/k",
                json={"value": "v"},
                headers=self.headers,
            )
        assert resp.status_code == 403

    def test_delete_ok(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"id": str(self.tid)}, {"r": "team-owner"}, {"1": 1}]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.delete(f"/api/v1/manage/teams/{self.tid}/meta/k", headers=self.headers)
        assert resp.status_code == 200
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "DELETE FROM api.team_meta" in sql


class TestMgmtProjectMeta:
    def setup_method(self, method=None):
        import app as store
        from auth import pats

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        self.uid = uuid4()
        self.headers = {"Authorization": "Bearer pat_test"}
        self._pats = patch.object(pats, "resolve", return_value=self.uid)

    def test_upsert_ok(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"id": str(self.pid)}, {"a": True}]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.patch(
                f"/api/v1/manage/projects/{self.pid}/meta/env",
                json={"value": "prod"},
                headers=self.headers,
            )
        assert resp.status_code == 200
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.project_meta" in sql
        conn.commit.assert_called()

    def test_upsert_denied_403(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"id": str(self.pid)}, {"a": False}]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.patch(
                f"/api/v1/manage/projects/{self.pid}/meta/env",
                json={"value": "prod"},
                headers=self.headers,
            )
        assert resp.status_code == 403

    def test_delete_ok(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"id": str(self.pid)}, {"a": True}, {"1": 1}]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.delete(f"/api/v1/manage/projects/{self.pid}/meta/env", headers=self.headers)
        assert resp.status_code == 200
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "DELETE FROM api.project_meta" in sql


class TestEsoListMergedMeta:
    def setup_method(self, method=None):
        import app as store
        from auth import pats

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        self.uid = uuid4()
        self.headers = {"Authorization": "Bearer pat_test"}
        self._pats = patch.object(pats, "resolve", return_value=self.uid)

    def test_list_uses_secret_meta_rows(self):
        conn, cur = _conn()
        row = {
            "id": str(uuid4()),
            "key": "svc",
            "note": None,
            "kind": "credential",
            "expires_at": None,
            "rotation_interval_days": None,
            "rotation_owner": None,
            "rotation_next_at": None,
            "rotated_at": None,
            "created_at": None,
            "updated_at": None,
            "last_accessed_at": None,
            "metadata": {"mark.hahl.team": "team1"},
        }
        cur.fetchone.side_effect = [{"id": str(self.pid)}, {}, {}, {}, {}]
        cur.fetchall.return_value = [row]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.get(f"/eso/v1/projects/{self.pid}/secrets?meta=1", headers=self.headers)
        assert resp.status_code == 200
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "FROM private.secret_meta_rows(s.id) m" in sql
        items = resp.get_json()["items"]
        assert items[0]["metadata"]["mark.hahl.team"] == "team1"
