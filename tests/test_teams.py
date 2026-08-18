"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import app as store
from core import config, db, settings_svc
from integrations import ldap_auth
from tests.helpers import REPO_ROOT
from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestTeams:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'u@ex.com'

    def test_list_requires_login(self):
        c = store.app.test_client()
        r = c.get('/teams')
        assert r.status_code == 302
        assert '/login' in r.location

    def test_list_teams(self):
        tid = uuid4()
        conn, _ = _conn(fetchall=[{'id': tid, 'name': 'Platform', 'role': 'team-owner', 'project_count': 2}])
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get('/teams')
        assert r.status_code == 200
        assert b'Platform' in r.data
        assert b'sidebar' in r.data

    def test_create_team_empty_name(self):
        with patch.object(settings_svc, 'can_create_team', return_value=True):
            r = self.client.post('/teams', data={'name': '  '}, follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location

    def test_create_team(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={'id': tid})
        with patch.object(db, 'connect', return_value=conn), patch.object(settings_svc, 'can_create_team', return_value=True):
            r = self.client.post('/teams', data={'name': 'Ops'}, follow_redirects=False)
        assert r.status_code == 302
        assert str(tid) in r.location

    def test_create_team_restricted(self):
        with patch.object(settings_svc, 'can_create_team', return_value=False):
            r = self.client.post('/teams', data={'name': 'Ops'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location
        assert 'Ops' not in r.headers.get('Location', '')

    def test_team_detail_404(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/teams/{uuid4()}')
        assert r.status_code == 404

    def test_team_detail_ok(self):
        tid = uuid4()
        last_sql = {'s': ''}

        def execute(sql, params=None):
            last_sql['s'] = ' '.join(str(sql).lower().split())

        def fetchone():
            s = last_sql['s']
            if 'from api.teams' in s and 'where id' in s:
                return {'id': tid, 'name': 'T'}
            if 'api.team_role' in s or 'select role from api.team_members' in s:
                return {'r': 'team-owner', 'role': 'team-owner'}
            return None
        conn, cur = _conn(fetchone=fetchone, fetchall=[])
        cur.execute.side_effect = execute
        with patch.object(db, 'as_user', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}):
            r = self.client.get(f'/teams/{tid}')
        assert r.status_code == 200
        assert b'>T<' in r.data
        assert b'?tab=projects' in r.data
        assert b'?tab=members' in r.data
        assert b'?tab=groups' in r.data
        assert b'?tab=settings' in r.data
        sql = ' '.join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        assert 'from api.projects' in sql

    def test_team_detail_members_tab(self):
        tid = uuid4()
        last_sql = {'s': ''}

        def execute(sql, params=None):
            last_sql['s'] = ' '.join(str(sql).lower().split())

        def fetchone():
            s = last_sql['s']
            if 'from api.teams' in s and 'where id' in s:
                return {'id': tid, 'name': 'T'}
            if 'api.team_role' in s or 'select role from api.team_members' in s:
                return {'r': 'team-owner', 'role': 'team-owner'}
            return None
        conn, cur = _conn(fetchone=fetchone, fetchall=[])
        cur.execute.side_effect = execute
        with patch.object(db, 'as_user', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}):
            r = self.client.get(f'/teams/{tid}?tab=members')
        assert r.status_code == 200
        assert b'Invites' in r.data
        sql = ' '.join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        # Members tab now reads from rbac.bindings (not legacy team_member_rows)
        assert 'rbac.bindings' in sql or 'rbac_sync' in sql.lower() or 'list_scope_bindings' in sql

    def test_add_member_user_missing(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={'id': None})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/members', data={'email': 'nope@x.com', 'role': 'team-member'}, follow_redirects=False)
        assert r.status_code == 302

    def test_add_member_uses_lookup_user(self):
        tid, uid = (uuid4(), uuid4())
        conn, cur = _conn(fetchone={'id': uid})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/members', data={'email': 'u@ex.com', 'role': 'team-member'}, follow_redirects=False)
        assert r.status_code == 302
        sql = ' '.join(str(c.args[0]) for c in cur.execute.call_args_list)
        assert 'private.lookup_user' in sql
        assert 'user_directory' not in sql

    def test_user_directory_not_granted_to_authenticated(self):
        init = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'GRANT SELECT ON api.user_directory TO authenticated' not in init
        assert 'private.lookup_user' in init
        assert 'private.team_member_rows' in (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()

    def test_non_member_cannot_self_join(self):
        """RLS must reject binding insert when the actor cannot manage team RBAC."""
        tid = uuid4()
        role_id = uuid4()
        rls_err = Exception(
            'new row violates row-level security policy for table "rbac.bindings"'
        )
        last = {'s': ''}

        def execute(sql, params=None):
            last['s'] = ' '.join(str(sql).lower().split())
            if 'insert into rbac.bindings' in last['s']:
                raise rls_err

        def fetchone():
            s = last['s']
            if 'team_role' in s:
                return {'r': 'team-member'}
            if 'lookup_user' in s:
                return {'id': self.uid}
            if 'from rbac.roles' in s:
                return {'id': role_id}
            # existing binding / last-owner checks
            return None

        conn, cur = _conn(fetchone=fetchone)
        cur.execute.side_effect = execute
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(
                f'/teams/{tid}/members',
                data={'email': 'u@ex.com', 'role': 'team-member'},
                follow_redirects=False,
            )
        assert r.status_code == 302
        conn.commit.assert_not_called()
        conn.rollback.assert_called()
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any('Could not update team membership. Try again.' in msg for _cat, msg in flashes)

    def test_tm_insert_policy_forbids_self_join(self):
        """RBAC bindings write policy must require can_manage_rbac — no self-join escape hatch."""
        rbac_sql = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'rbac_bindings_write' in rbac_sql
        assert 'can_manage_rbac' in rbac_sql
        assert 'user_id = api.current_user_id()' not in rbac_sql.split('rbac_bindings_write')[1].split('CREATE POLICY')[0]

    def test_team_roles_include_viewer(self):
        assert 'team-viewer' in [n for n, _ in config.RBAC_TEAM_ROLE_DROPDOWN]
        assert not hasattr(config, 'TEAM_ROLES')
        assert 'team-member' in config.INVITE_ROLES

    def test_add_member_viewer_role(self):
        tid, uid = (uuid4(), uuid4())
        conn, cur = _conn(fetchone={'id': uid})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/members', data={'email': 'ro@ex.com', 'role': 'team-viewer'}, follow_redirects=False)
        assert r.status_code == 302
        sql = ' '.join(str(c) for c in cur.execute.call_args_list)
        assert 'viewer' in sql

    def test_create_project(self):
        tid, pid = (uuid4(), uuid4())
        conn, _ = _conn(fetchone={'id': pid})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/projects', data={'name': 'prod'}, follow_redirects=False)
        assert r.status_code == 302
        assert str(pid) in r.location

    def test_create_project_wizard_page(self):
        tid = uuid4()
        cur = MagicMock()
        cur.fetchone.side_effect = [
            {'id': tid, 'name': 'Platform'},
            {'r': 'team-owner'},
        ]
        cur.__enter__.return_value = cur
        cur.__exit__.return_value = False
        conn = MagicMock()
        conn.cursor.return_value = cur
        conn.__enter__.return_value = conn
        conn.__exit__.return_value = False
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/teams/{tid}/projects/new')
        assert r.status_code == 200
        assert b'Encryption' in r.data
        assert b'project key' in r.data.lower()

    def test_create_project_byok_creates_key(self):
        tid, pid = (uuid4(), uuid4())
        conn, _ = _conn(fetchone={'id': pid})
        from crypto import project_keys
        with patch.object(db, 'as_user', return_value=conn), \
             patch.object(project_keys, 'ensure_project_key', return_value=True) as ensure:
            r = self.client.post(
                f'/teams/{tid}/projects',
                data={'name': 'prod', 'encryption': 'byok'},
                follow_redirects=False,
            )
        assert r.status_code == 302
        ensure.assert_called_once()
        assert str(pid) in r.location

    def test_delete_team_owner_ok(self):
        tid = uuid4()
        conn, cur = _conn(fetchone={'r': 'team-owner'})
        cur.rowcount = 1
        with self.client.session_transaction() as s:
            s['team_id'] = str(tid)
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/delete', follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location
        assert str(tid) not in r.location
        conn.commit.assert_called()
        with self.client.session_transaction() as s:
            assert s.get('team_id') != str(tid)

    def test_delete_team_non_owner_denied(self):
        tid = uuid4()
        for role in ('team-admin', 'team-member', 'team-viewer'):
            conn, cur = _conn(fetchone={'r': role})
            with patch.object(db, 'as_user', return_value=conn):
                r = self.client.post(f'/teams/{tid}/delete', follow_redirects=False)
            assert r.status_code == 302
            assert str(tid) in r.location
            conn.commit.assert_not_called()
            with self.client.session_transaction() as s:
                flashes = s.get('_flashes') or []
            assert any(('owner' in msg.lower() for _c, msg in flashes))

    def test_delete_project_admin_ok(self):
        tid, pid = (uuid4(), uuid4())
        conn, cur = _conn(fetchone={'r': 'team-admin'})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/projects/{pid}/delete', follow_redirects=False)
        assert r.status_code == 302
        assert str(tid) in r.location
        conn.commit.assert_called()

    def test_delete_project_member_denied(self):
        tid, pid = (uuid4(), uuid4())
        conn, _ = _conn(fetchone={'r': 'team-member'})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/projects/{pid}/delete', follow_redirects=False)
        assert r.status_code == 302
        conn.commit.assert_not_called()
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('owner' in msg.lower() or 'admin' in msg.lower() for _c, msg in flashes))
