"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import app as store
from core import db, settings_svc
from tests.helpers import REPO_ROOT, migrations_src, routes_module_src
from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestTokens:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'u@ex.com'

    def test_create_token(self):
        conn, cur = _conn(fetchone={'w': True})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn), patch.object(settings_svc, 'token_expiry_policy', return_value=(False, 3650)):
            r = self.client.post(f'/projects/{self.pid}/tokens', data={'name': 'openshift'}, follow_redirects=False)
        assert r.status_code == 302
        with self.client.session_transaction() as s:
            assert s.get('new_token', '').startswith('ss_')
        sql = ' '.join(str(c) for c in cur.execute.call_args_list)
        assert 'reveal' in sql

    def test_create_token_write_role(self):
        conn, cur = _conn(fetchone={'w': True})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn), patch.object(settings_svc, 'token_expiry_policy', return_value=(False, 3650)):
            r = self.client.post(f'/projects/{self.pid}/tokens', data={'name': 'ci-writer', 'role': 'service-write'}, follow_redirects=False)
        assert r.status_code == 302
        insert_calls = [c for c in cur.execute.call_args_list if c.args and 'INSERT INTO api.machine_tokens' in str(c.args[0])]
        assert insert_calls
        assert insert_calls[0].args[1][4] == 'service-write'

    def test_create_token_invalid_role_defaults_reveal(self):
        conn, cur = _conn(fetchone={'w': True})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn), patch.object(settings_svc, 'token_expiry_policy', return_value=(False, 3650)):
            r = self.client.post(f'/projects/{self.pid}/tokens', data={'name': 'x', 'role': 'owner'}, follow_redirects=False)
        assert r.status_code == 302
        insert_calls = [c for c in cur.execute.call_args_list if c.args and 'INSERT INTO api.machine_tokens' in str(c.args[0])]
        assert insert_calls[0].args[1][4] == 'service-reveal'

    def test_create_token_reveal_denied(self):
        conn, _ = _conn(fetchone={'w': False})
        with patch.object(db, 'as_user', return_value=conn), patch.object(settings_svc, 'token_expiry_policy', return_value=(False, 3650)):
            r = self.client.post(f'/projects/{self.pid}/tokens', data={'name': 'openshift'}, follow_redirects=False)
        assert r.status_code == 302
        conn.commit.assert_not_called()
        with self.client.session_transaction() as s:
            assert 'new_token' not in s
            flashes = s.get('_flashes') or []
        assert any(('permission' in msg.lower() for _cat, msg in flashes))

    def test_create_token_requires_expiry_when_policy_enabled(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'w': True}, {}]
        with patch.object(db, 'as_user', return_value=conn), patch.object(settings_svc, 'token_expiry_policy', return_value=(True, 3650)):
            r = self.client.post(f'/projects/{self.pid}/tokens', data={'name': 'openshift'}, follow_redirects=False)
        assert r.status_code == 302
        inserts = [c for c in cur.execute.call_args_list if c.args and 'INSERT INTO api.machine_tokens' in str(c.args[0])]
        assert inserts == []
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('Enter an expiry period.' in msg for _cat, msg in flashes))

    def test_create_token_uses_policy_max(self):
        conn, cur = _conn(fetchone={'w': True})
        with patch.object(db, 'as_user', return_value=conn), patch.object(settings_svc, 'token_expiry_policy', return_value=(False, 30)):
            r = self.client.post(f'/projects/{self.pid}/tokens', data={'name': 'openshift', 'expires_days': '31'}, follow_redirects=False)
        assert r.status_code == 302
        inserts = [c for c in cur.execute.call_args_list if c.args and 'INSERT INTO api.machine_tokens' in str(c.args[0])]
        assert inserts == []

    def test_delete_token(self):
        conn, cur = _conn(fetchone={'w': True})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/tokens/{uuid4()}/delete', follow_redirects=False)
        assert r.status_code == 302

    def test_delete_token_reveal_denied(self):
        conn, _ = _conn(fetchone={'w': False})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/tokens/{uuid4()}/delete', follow_redirects=False)
        assert r.status_code == 302
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('permission' in msg.lower() for _cat, msg in flashes))

    def test_mt_select_policy_allows_readers(self):
        """Reveal-role may list tokens; only writers insert/delete."""
        rbac_sql = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        sel_start = rbac_sql.index('CREATE POLICY mt_select ON api.machine_tokens')
        sel_end = rbac_sql.index(';', sel_start)
        assert 'can_read_project' in rbac_sql[sel_start:sel_end]
        harden = (REPO_ROOT / 'db' / 'migrations' / '0002_rls_authz_hardening.sql').read_text()
        ins_start = harden.rindex('CREATE POLICY mt_insert ON api.machine_tokens')
        ins_end = harden.index(';', ins_start)
        assert 'can_admin_project' in harden[ins_start:ins_end]

    def test_pm_policies_use_can_admin_project(self):
        """RBAC bindings write policy requires can_manage_rbac, not mere write."""
        root = REPO_ROOT
        rbac_sql = (root / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'rbac_bindings_write' in rbac_sql
        assert 'can_manage_rbac' in rbac_sql
        # Legacy project_members policies removed from init.sql
        init_sql = (root / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'CREATE POLICY pm_insert ON api.project_members' not in init_sql

    def test_can_write_project_team_admin_floor(self):
        """can_write_project uses RBAC can() — defined in rbac.sql."""
        rbac_sql = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'CREATE OR REPLACE FUNCTION api.can_write_project' in rbac_sql
        start = rbac_sql.index('CREATE OR REPLACE FUNCTION api.can_write_project')
        end = rbac_sql.index('$$;', start) + 3
        body = rbac_sql[start:end]
        assert "api.can('create', 'secrets', 'project', pid)" in body
        assert "api.can('update', 'secrets', 'project', pid)" in body

    def test_can_read_project_most_specific_wins(self):
        """can_read_project uses RBAC can() — defined in rbac.sql."""
        rbac_sql = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'CREATE OR REPLACE FUNCTION api.can_read_project' in rbac_sql
        start = rbac_sql.index('CREATE OR REPLACE FUNCTION api.can_read_project')
        end = rbac_sql.index('$$;', start) + 3
        body = rbac_sql[start:end]
        assert "api.can('get', 'projects', 'project', pid)" in body
        assert "api.can('list', 'secrets', 'project', pid)" in body

    def test_can_admin_project_defined(self):
        rbac_sql = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'CREATE OR REPLACE FUNCTION api.can_admin_project' in rbac_sql
        start = rbac_sql.index('CREATE OR REPLACE FUNCTION api.can_admin_project')
        end = rbac_sql.index('$$;', start) + 3
        body = rbac_sql[start:end]
        assert "api.can('admin', 'projects', 'project', pid)" in body

    def test_add_project_binding_requires_admin(self):
        """Non-admins cannot add project members (can_manage_rbac gate)."""
        conn, cur = _conn(fetchone={'ok': False, 'a': False})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(
                f'/projects/{self.pid}/members',
                data={'email': 'x@ex.com', 'role': 'project-read'},
                follow_redirects=False,
            )
        assert r.status_code == 302
        sql = ' '.join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        assert 'can_manage_rbac' in sql or 'can_admin_project' in sql
        assert 'insert into api.project_members' not in sql
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('permission' in msg.lower() for _c, msg in flashes))

    def test_add_project_binding_ok_for_admin(self):
        uid = uuid4()
        tid = uuid4()
        rid = uuid4()
        last = {'s': ''}

        def execute(sql, params=None):
            last['s'] = ' '.join(str(sql).lower().split())

        def fetchone():
            s = last['s']
            if 'can_manage_rbac' in s or 'can_admin_project' in s:
                return {'ok': True, 'a': True}
            if 'lookup_user' in s:
                return {'id': uid}
            if 'from api.projects' in s and 'team_id' in s:
                return {'team_id': tid}
            if 'from rbac.roles' in s:
                return {'id': rid}
            if 'from rbac.bindings' in s:
                return None
            return None

        conn, cur = _conn(fetchone=fetchone)
        cur.execute.side_effect = execute
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(
                f'/projects/{self.pid}/members',
                data={'email': 'x@ex.com', 'role': 'project-write'},
                follow_redirects=False,
            )
        assert r.status_code == 302
        sql = ' '.join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        assert 'rbac.bindings' in sql
        assert 'insert into api.project_members' not in sql
        assert 'can_manage_rbac' in sql or 'can_admin_project' in sql

    def test_remove_project_binding_requires_admin(self):
        conn, cur = _conn(fetchone={'ok': False, 'a': False})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(
                f'/projects/{self.pid}/members/{uuid4()}/remove',
                follow_redirects=False,
            )
        assert r.status_code == 302
        sql = ' '.join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        assert 'can_manage_rbac' in sql or 'can_admin_project' in sql
        assert 'delete from api.project_members' not in sql

    def test_secrets_updated_at_trigger_defined(self):
        root = REPO_ROOT
        init_sql = (root / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'CREATE TRIGGER secrets_touch_updated_at' in init_sql
        assert 'api.touch_updated_at' in init_sql
        routes = routes_module_src('projects')
        assert 'updated_at = now()' not in routes
        assert 'updated_at=now()' not in routes

    def test_secret_versions_schema(self):
        root = REPO_ROOT
        init = (root / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'CREATE TABLE api.secret_versions' in init
        assert 'archive_secret_version' in init
        assert 'expires_at' in init
        assert 'rotate_days' not in init
        src = migrations_src()
        assert 'api.secret_versions' in src
        assert 'archive_secret_version' in src
        assert 'rotate_days' not in src

    def test_token_prefix_unique_constraint(self):
        init = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'token_prefix text NOT NULL UNIQUE' in init
        src = migrations_src()
        assert 'machine_tokens_token_prefix_key' in src
        assert 'personal_access_tokens' in src

    def test_init_sql_allows_oidc_auth_source(self):
        init = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert "'local', 'ldap', 'oidc'" in init
        assert 'upsert_oidc_user' in init
        assert 'team_oidc_maps' in init
        assert 'oidc_role_maps' in init
        assert "source IN ('manual', 'ldap', 'oidc')" in init
        src = migrations_src()
        assert 'users_auth_source_check' in src
