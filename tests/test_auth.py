"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

import app as store
import authz
import config
import db
import ldap_auth
import settings_svc

from tests.helpers import REPO_ROOT, mock_conn as _conn

store.app.config["TESTING"] = True

class TestAuth:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        store.app.config['CSRF_TESTING'] = False
        self.client = store.app.test_client()

    def test_index_anon_to_login(self):
        r = self.client.get('/')
        assert r.status_code == 302
        assert '/login' in r.location

    def test_index_authed_to_teams(self):
        with self.client.session_transaction() as s:
            s['user_id'] = str(uuid4())
        r = self.client.get('/')
        assert r.status_code == 302
        assert '/teams' in r.location

    def test_login_get(self):
        with patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch.object(settings_svc, 'setup_notice', return_value=None), patch.object(settings_svc, 'registration_enabled', return_value=True):
            r = self.client.get('/login')
        assert r.status_code == 200
        assert b'Sign in' in r.data

    def test_login_bad_creds(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, 'connect', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch('lockout.record_failure'), patch('lockout.is_locked', return_value=False):
            r = self.client.post('/login', data={'email': 'a@b.c', 'password': 'nope'})
        assert r.status_code == 401
        assert b'Invalid' in r.data

    def test_login_locked(self):
        with patch('lockout.is_locked', return_value=True), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}):
            r = self.client.post('/login', data={'email': 'a@b.c', 'password': 'x'})
        assert r.status_code == 429

    def test_login_ok(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={'id': uid, 'email': 'a@b.c', 'name': 'A'})
        with patch.object(db, 'connect', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch('lockout.is_locked', return_value=False), patch('lockout.clear_failures'), patch.object(authz, 'is_global_admin', return_value=False), patch.object(settings_svc, 'setup_notice', return_value=None), patch('totp_svc.needs_challenge', return_value=None), patch('mailer.login_alerts_enabled', return_value=False):
            r = self.client.post('/login', data={'email': 'a@b.c', 'password': 'secret12'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location
        with self.client.session_transaction() as s:
            assert s['user_id'] == str(uid)
            assert s['email'] == 'a@b.c'
            assert 'jwt' in s

    def test_login_clears_session_first(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={'id': uid, 'email': 'a@b.c', 'name': 'A'})
        with self.client.session_transaction() as s:
            s['stale'] = 'should-be-gone'
            s['_csrf'] = 'old'
        with patch.object(db, 'connect', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch('lockout.is_locked', return_value=False), patch('lockout.clear_failures'), patch.object(authz, 'is_global_admin', return_value=False), patch.object(settings_svc, 'setup_notice', return_value=None), patch('totp_svc.needs_challenge', return_value=None), patch('mailer.login_alerts_enabled', return_value=False):
            r = self.client.post('/login', data={'email': 'a@b.c', 'password': 'secret12'}, follow_redirects=False)
        assert r.status_code == 302
        with self.client.session_transaction() as s:
            assert 'stale' not in s
            assert s['user_id'] == str(uid)

    def test_csrf_rejects_post_without_token(self):
        store.app.config['CSRF_TESTING'] = True
        try:
            with self.client.session_transaction() as s:
                s['_csrf'] = 'good-token'
            r = self.client.post('/logout')
            assert r.status_code == 400
        finally:
            store.app.config['CSRF_TESTING'] = False

    def test_csrf_accepts_valid_token(self):
        store.app.config['CSRF_TESTING'] = True
        try:
            with self.client.session_transaction() as s:
                s['_csrf'] = 'good-token'
                s['user_id'] = str(uuid4())
            r = self.client.post('/logout', data={'_csrf': 'good-token'}, follow_redirects=False)
            assert r.status_code == 302
            assert '/login' in r.location
        finally:
            store.app.config['CSRF_TESTING'] = False

    def test_select_team_blocks_open_redirect(self):
        with self.client.session_transaction() as s:
            s['user_id'] = str(uuid4())
        r = self.client.post('/select-team', data={'team_id': '', 'next': '//evil.com'}, follow_redirects=False)
        assert r.status_code == 302
        assert 'evil' not in r.location
        assert r.location.endswith('/projects') or '/projects' in r.location

    def test_login_ldap_ok(self):
        uid = uuid4()
        ldap_user = {'email': 'ldap@ex.com', 'name': 'LDAP User', 'groups': ['CN=secretstore-admins,OU=groups,DC=ex,DC=com']}
        synced = {'id': uid, 'email': 'ldap@ex.com', 'name': 'LDAP User', 'is_global_admin': True}
        conn, _ = _conn(fetchone=None)
        with patch.object(db, 'connect', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'true'}), patch.object(ldap_auth, 'ldap_authenticate', return_value=ldap_user), patch.object(ldap_auth, 'sync_ldap_user', return_value=synced), patch('lockout.is_locked', return_value=False), patch('lockout.clear_failures'), patch.object(authz, 'is_global_admin', return_value=True), patch.object(settings_svc, 'setup_notice', return_value=None), patch('totp_svc.needs_challenge', return_value=None), patch('mailer.login_alerts_enabled', return_value=False):
            r = self.client.post('/login', data={'email': 'ldapuser', 'password': 'dir-pass'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location
        with self.client.session_transaction() as s:
            assert s['user_id'] == str(uid)
            assert s['email'] == 'ldap@ex.com'
            assert s['is_global_admin']

    def test_register_short_password(self):
        with patch.object(settings_svc, 'registration_enabled', return_value=True), patch.object(settings_svc, 'setup_notice', return_value=None):
            r = self.client.post('/register', data={'email': 'a@b.c', 'password': 'short', 'name': 'A'})
        assert r.status_code == 400
        assert b'8 characters' in r.data

    def test_register_ok(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={'id': uid})
        with patch.object(db, 'connect', return_value=conn), patch.object(settings_svc, 'registration_enabled', return_value=True), patch.object(settings_svc, 'setup_notice', return_value=None), patch.object(authz, 'is_global_admin', return_value=False), patch('totp_svc.needs_challenge', return_value=None), patch('mailer.login_alerts_enabled', return_value=False):
            r = self.client.post('/register', data={'email': 'new@b.c', 'password': 'password1', 'name': 'N'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location
        with self.client.session_transaction() as s:
            assert not s.get('is_global_admin')

    def test_register_does_not_auto_promote_first_user(self):
        """register_user SQL must set is_global_admin false (no first_user race)."""
        from pathlib import Path
        init = (REPO_ROOT / 'db' / 'init.sql').read_text()
        start = init.index('CREATE OR REPLACE FUNCTION private.register_user')
        end = init.index('$$;', start)
        body = init[start:end]
        assert "false, 'local'" in body
        assert 'first_user' not in body

    def test_bootstrap_email_promotes_on_register(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={'id': uid})
        admin_conn, admin_cur = _conn()
        with patch.object(db, 'connect', return_value=conn), patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(settings_svc, 'registration_enabled', return_value=True), patch.object(settings_svc, 'setup_notice', return_value=None), patch('routes.auth.bootstrap_admin_email', return_value='admin@ex.com'), patch.object(authz, 'is_global_admin', return_value=True), patch('totp_svc.needs_challenge', return_value=None), patch('mailer.login_alerts_enabled', return_value=False):
            r = self.client.post('/register', data={'email': 'admin@ex.com', 'password': 'password1', 'name': 'A'}, follow_redirects=False)
        assert r.status_code == 302
        sql = ' '.join((str(c.args[0]) for c in admin_cur.execute.call_args_list))
        assert 'is_global_admin = true' in sql

    def test_register_disabled(self):
        with patch.object(settings_svc, 'registration_enabled', return_value=False):
            r = self.client.get('/register', follow_redirects=False)
        assert r.status_code == 302
        assert '/login' in r.location
        with patch.object(settings_svc, 'registration_enabled', return_value=False):
            r = self.client.post('/register', data={'email': 'new@b.c', 'password': 'password1', 'name': 'N'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/login' in r.location

    def test_login_hides_register_when_disabled(self):
        with patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch.object(settings_svc, 'registration_enabled', return_value=False), patch.object(settings_svc, 'setup_notice', return_value=None):
            r = self.client.get('/login')
        assert r.status_code == 200
        assert b'href="/register"' not in r.data

    def test_registration_disabled_without_bootstrap(self):
        with patch.object(settings_svc, 'has_global_admin', return_value=False), patch('settings_svc.bootstrap_admin_email', return_value=''), patch.object(settings_svc, 'get_settings', return_value={'registration_enabled': 'true'}):
            assert not settings_svc.registration_enabled()

    def test_logout(self):
        with self.client.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'a@b.c'
        r = self.client.post('/logout')
        assert r.status_code == 302
        assert '/login' in r.location
        with self.client.session_transaction() as s:
            assert 'user_id' not in s

    def test_profile_requires_login(self):
        r = self.client.get('/profile')
        assert r.status_code == 302
        assert '/login' in r.location

    def test_forgot_password_get(self):
        r = self.client.get('/forgot-password')
        assert r.status_code == 200
        assert b'Forgot password' in r.data

    def test_forgot_password_post_no_enumeration(self):
        with patch('passwords.create_reset_token', return_value=None):
            r = self.client.post('/forgot-password', data={'email': 'nobody@ex.com'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/login' in r.location

    def test_change_password_requires_login(self):
        r = self.client.post('/profile/password', data={'current_password': 'old', 'new_password': 'newpass12', 'new_password_confirm': 'newpass12'})
        assert r.status_code == 302
        assert '/login' in r.location

    def test_change_password_ok(self):
        uid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = uid
            s['sid'] = str(uuid4())
        with patch('passwords.change_password', return_value=(True, '')), patch('user_sessions.revoke_other_sessions', return_value=2):
            r = self.client.post('/profile/password', data={'current_password': 'oldpass12', 'new_password': 'newpass12', 'new_password_confirm': 'newpass12'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/profile' in r.location
        assert 'tab=security' in r.location

    def test_change_password_mismatch(self):
        uid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = uid
        r = self.client.post('/profile/password', data={'current_password': 'oldpass12', 'new_password': 'newpass12', 'new_password_confirm': 'other'}, follow_redirects=False)
        assert r.status_code == 302
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('match' in msg.lower() for _c, msg in flashes))

    def test_revoke_other_sessions(self):
        uid = str(uuid4())
        sid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = uid
            s['sid'] = sid
        with patch('user_sessions.revoke_other_sessions', return_value=3) as rev:
            r = self.client.post('/profile/sessions/revoke-others', follow_redirects=False)
        assert r.status_code == 302
        rev.assert_called_once_with(uid, sid)

    def test_reset_password_mismatch(self):
        r = self.client.post('/reset-password/tok', data={'password': 'newpass12', 'password_confirm': 'nope'})
        assert r.status_code == 400

    def test_reset_password_ok(self):
        with patch('passwords.consume_reset_token', return_value=(True, '')):
            r = self.client.post('/reset-password/goodtoken', data={'password': 'newpass12', 'password_confirm': 'newpass12'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/login' in r.location

    def test_password_schema_helpers(self):
        from pathlib import Path
        init = (REPO_ROOT / 'db' / 'init.sql').read_text()
        assert 'private.change_password' in init
        assert 'private.set_local_password' in init
        assert 'private.user_sessions' in init
        assert 'private.password_reset_tokens' in init

    def test_profile_my_access(self):
        uid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = str(uid)
            s['email'] = 'a@b.c'
            s['is_global_admin'] = False
        admin_conn, _ = _conn(fetchone={'id': uid, 'email': 'a@b.c', 'name': 'Ada', 'is_global_admin': False, 'auth_source': 'local', 'created_at': '2026-01-01'})
        last_sql = {'s': ''}

        def execute(sql, params=None):
            last_sql['s'] = ' '.join(str(sql).lower().split())

        def fetchall():
            s = last_sql['s']
            if 'my_access_rows' in s:
                return [
                    {'scope_kind': 'team', 'scope_label': 'Platform', 'role_name': 'team-owner',
                     'role_description': 'Owns the team', 'grant_kind': 'Direct',
                     'grant_subject': 'You', 'created_at': '2026-01-02'},
                    {'scope_kind': 'project', 'scope_label': 'API', 'role_name': 'project-write',
                     'role_description': 'Write access', 'grant_kind': 'Group',
                     'grant_subject': 'platform-ops', 'created_at': '2026-01-03'},
                ]
            return []
        user_conn, cur = _conn(fetchone=None)
        cur.execute.side_effect = execute
        cur.fetchall.side_effect = fetchall
        with patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(db, 'as_user', return_value=user_conn):
            r = self.client.get('/profile?tab=myaccess')
        assert r.status_code == 200
        assert b'My access' in r.data
        assert b'platform-ops' in r.data
        assert b'team-owner' in r.data
        assert b'Team access' in r.data
        assert b'Project access' in r.data
        assert b'?tab=myaccess' in r.data

    def test_profile_ok(self):
        uid = uuid4()
        tid = uuid4()
        pid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = str(uid)
            s['email'] = 'a@b.c'
            s['name'] = 'Ada'
            s['is_global_admin'] = False
        admin_conn, _ = _conn(fetchone={'id': uid, 'email': 'a@b.c', 'name': 'Ada Lovelace', 'is_global_admin': False, 'auth_source': 'local', 'created_at': '2026-01-01'})
        last_sql = {'s': ''}

        def execute(sql, params=None):
            last_sql['s'] = ' '.join(str(sql).lower().split())

        def fetchone():
            s = last_sql['s']
            if 'from api.secrets' in s and 'count' in s:
                return {'n': 3}
            if 'from api.secret_pins' in s and 'count' in s:
                return {'n': 1}
            return None

        def fetchall():
            s = last_sql['s']
            if 'my_access_rows' in s:
                return [
                    {'scope_kind': 'team', 'scope_label': 'Platform', 'role_name': 'team-owner',
                     'role_description': 'Owns the team', 'grant_kind': 'Direct',
                     'grant_subject': 'You', 'created_at': '2026-01-02'},
                    {'scope_kind': 'project', 'scope_label': 'API', 'role_name': 'project-write',
                     'role_description': 'Write access', 'grant_kind': 'Group',
                     'grant_subject': 'platform-ops', 'created_at': '2026-01-03'},
                ]
            if 'from api.teams t' in s:
                return [{'id': tid, 'name': 'Platform', 'role': 'owner', 'source': 'manual', 'created_at': '2026-01-02', 'project_count': 1}]
            if 'from api.projects p' in s:
                return [{'id': pid, 'name': 'API', 'created_at': '2026-01-03', 'team_id': tid, 'team_name': 'Platform', 'team_role': 'owner', 'project_role': None, 'secret_count': 3}]
            if 'team_join_requests' in s:
                return []
            if 'secret_pins pin' in s or 'from api.secret_pins pin' in s:
                return []
            if 'secret_recent' in s:
                return []
            return []
        user_conn, cur = _conn(fetchone=fetchone)
        cur.execute.side_effect = execute
        cur.fetchall.side_effect = fetchall
        with patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(db, 'as_user', return_value=user_conn), patch('user_sessions.list_sessions', return_value=[]):
            r = self.client.get('/profile')
        assert r.status_code == 200
        assert b'My profile' in r.data
        assert b'?tab=account' in r.data
        assert b'?tab=security' in r.data
        assert b'?tab=myaccess' in r.data
        assert b'?tab=teams' in r.data
        assert b'?tab=projects' in r.data
        assert b'?tab=activity' in r.data
        assert b'Ada Lovelace' in r.data
        assert b'a@b.c' in r.data
        assert b'Local' in r.data
        assert b'Database' in r.data
        assert b'At a glance' in r.data
        assert b'Change password' not in r.data
        assert b'Active sessions' not in r.data
        with patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(db, 'as_user', return_value=user_conn), patch('user_sessions.list_sessions', return_value=[]), patch('pats.list_for_user', return_value=[]):
            r_sec = self.client.get('/profile?tab=security')
        assert r_sec.status_code == 200
        assert b'Change password' in r_sec.data
        assert b'Active sessions' in r_sec.data
        assert b'Two-factor authentication' in r_sec.data
        assert b'Personal access tokens' in r_sec.data
        assert b'API access' in r_sec.data
        assert b'show-session-jwt' in r_sec.data
        with patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(db, 'as_user', return_value=user_conn):
            r_teams = self.client.get('/profile?tab=teams')
        assert r_teams.status_code == 200
        assert b'Platform' in r_teams.data
        assert b'Your role' in r_teams.data
        assert b'owner' in r_teams.data
        with patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(db, 'as_user', return_value=user_conn):
            r_proj = self.client.get('/profile?tab=projects')
        assert r_proj.status_code == 200
        assert b'API' in r_proj.data

    def test_profile_shows_ldap_and_admin(self):
        uid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = str(uid)
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        admin_conn, _ = _conn(fetchone={'id': uid, 'email': 'admin@ex.com', 'name': 'Admin', 'is_global_admin': True, 'auth_source': 'ldap', 'created_at': '2025-06-01'})
        user_conn, _ = _conn(fetchone={'n': 0}, fetchall=[])
        with patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(db, 'as_user', return_value=user_conn), patch('user_sessions.list_sessions', return_value=[]), patch('pats.list_for_user', return_value=[]):
            r = self.client.get('/profile?tab=account')
            r_sec = self.client.get('/profile?tab=security')
        assert r.status_code == 200
        assert b'LDAP' in r.data
        assert b'Directory' in r.data
        assert b'Global admin' in r.data
        assert r_sec.status_code == 200
        assert b'LDAP' in r_sec.data
        assert b'name="current_password"' not in r_sec.data

