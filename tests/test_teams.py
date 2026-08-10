"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4
from pathlib import Path

import pytest

import app as store
import config
import db
import ldap_auth
import schema as schema_mod
import settings_svc

from tests.helpers import REPO_ROOT, mock_conn as _conn

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
        conn, _ = _conn(fetchall=[{'id': tid, 'name': 'Platform', 'role': 'owner', 'project_count': 2}])
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
                return {'r': 'owner', 'role': 'owner'}
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
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list)).lower()
        assert 'from api.projects' in sql
        assert 'team_member_rows' not in sql

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
                return {'r': 'owner', 'role': 'owner'}
            return None
        conn, cur = _conn(fetchone=fetchone, fetchall=[])
        cur.execute.side_effect = execute
        with patch.object(db, 'as_user', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}):
            r = self.client.get(f'/teams/{tid}?tab=members')
        assert r.status_code == 200
        assert b'Invites' in r.data
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list)).lower()
        # Members tab now reads from rbac.bindings (not legacy team_member_rows)
        assert 'rbac.bindings' in sql or 'rbac_sync' in sql.lower() or 'list_scope_bindings' in sql

    def test_add_member_user_missing(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={'id': None})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/members', data={'email': 'nope@x.com', 'role': 'member'}, follow_redirects=False)
        assert r.status_code == 302

    def test_add_member_uses_lookup_user(self):
        tid, uid = (uuid4(), uuid4())
        conn, cur = _conn(fetchone={'id': uid})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/members', data={'email': 'u@ex.com', 'role': 'member'}, follow_redirects=False)
        assert r.status_code == 302
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
        assert 'private.lookup_user' in sql
        assert 'user_directory' not in sql

    def test_user_directory_not_granted_to_authenticated(self):
        from pathlib import Path
        init = (REPO_ROOT / 'db' / 'init.sql').read_text()
        assert 'GRANT SELECT ON api.user_directory TO authenticated' not in init
        assert 'private.lookup_user' in init
        assert 'private.team_member_rows' in init

    def test_non_member_cannot_self_join(self):
        """RLS must reject self-insert into a team the user does not admin."""
        tid = uuid4()
        rls_err = Exception('new row violates row-level security policy for table "rbac.bindings"')
        state = {'n': 0}

        def execute(sql, params=None):
            if 'INSERT INTO rbac.bindings' in str(sql):
                raise rls_err

        def fetchone():
            state['n'] += 1
            # 1: team_role (non-owner) 2: lookup_user 3: existing membership
            if state['n'] == 1:
                return {'r': 'member'}
            if state['n'] == 2:
                return {'id': self.uid}
            return None

        conn, cur = _conn(fetchone=fetchone)
        cur.execute.side_effect = execute
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(
                f'/teams/{tid}/members',
                data={'email': 'u@ex.com', 'role': 'member'},
                follow_redirects=False,
            )
        assert r.status_code == 302
        conn.commit.assert_not_called()
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('row-level security' in msg for _cat, msg in flashes))

    def test_tm_insert_policy_forbids_self_join(self):
        """Policy must require owner/admin — no user_id = current_user escape hatch."""
        from pathlib import Path
        init_sql = (REPO_ROOT / 'db' / 'init.sql').read_text()
        start = init_sql.index('CREATE POLICY tm_insert ON api.team_members')
        end = init_sql.index(';', start)
        policy = init_sql[start:end]
        assert "api.team_role(team_id) IN ('owner', 'admin')" in policy
        assert 'user_id = api.current_user_id()' not in policy
        src = Path(schema_mod.__file__).read_text()
        assert 'DROP POLICY IF EXISTS tm_insert ON api.team_members' in src
        ensure_start = src.index('DROP POLICY IF EXISTS tm_insert ON api.team_members')
        ensure_chunk = src[ensure_start:ensure_start + 280]
        assert "api.team_role(team_id) IN ('owner', 'admin')" in ensure_chunk
        assert 'user_id = api.current_user_id()' not in ensure_chunk

    def test_team_roles_include_viewer(self):
        assert 'viewer' in config.TEAM_ROLES
        assert config.ROLE_RANK['viewer'] < config.ROLE_RANK['member']

    def test_add_member_viewer_role(self):
        tid, uid = (uuid4(), uuid4())
        conn, cur = _conn(fetchone={'id': uid})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/members', data={'email': 'ro@ex.com', 'role': 'viewer'}, follow_redirects=False)
        assert r.status_code == 302
        sql = ' '.join((str(c) for c in cur.execute.call_args_list))
        assert 'viewer' in sql

    def test_create_project(self):
        tid, pid = (uuid4(), uuid4())
        conn, _ = _conn(fetchone={'id': pid})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/projects', data={'name': 'prod'}, follow_redirects=False)
        assert r.status_code == 302
        assert str(pid) in r.location

    def test_delete_team_owner_ok(self):
        tid = uuid4()
        conn, cur = _conn(fetchone={'r': 'owner'})
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
        for role in ('admin', 'member', 'viewer'):
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
        conn, cur = _conn(fetchone={'r': 'admin'})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/projects/{pid}/delete', follow_redirects=False)
        assert r.status_code == 302
        assert str(tid) in r.location
        conn.commit.assert_called()

    def test_delete_project_member_denied(self):
        tid, pid = (uuid4(), uuid4())
        conn, _ = _conn(fetchone={'r': 'member'})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/projects/{pid}/delete', follow_redirects=False)
        assert r.status_code == 302
        conn.commit.assert_not_called()
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('owner' in msg.lower() or 'admin' in msg.lower() for _c, msg in flashes))

