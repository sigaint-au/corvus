"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import app as store
import crypto
from auth import authz
from core import cache, config, db, settings_svc
from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestSettings:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())

    def test_settings_requires_login(self):
        r = self.client.get('/settings')
        assert r.status_code == 302
        assert '/login' in r.location

    def test_settings_requires_global_admin(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'u@ex.com'
            s['is_global_admin'] = False
        conn, _ = _conn(fetchall=[])
        with patch.object(db, 'as_user', return_value=conn), patch.object(authz, 'is_global_admin', return_value=False):
            r = self.client.get('/settings', follow_redirects=False)
        assert r.status_code == 302

    def test_demoted_admin_denied_despite_session_flag(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'was-admin@ex.com'
            s['is_global_admin'] = True
        with patch.object(authz, 'is_global_admin', return_value=False):
            r = self.client.get('/settings', follow_redirects=False)
        assert r.status_code == 302
        assert '/projects' in r.location
        with self.client.session_transaction() as s:
            assert not s.get('is_global_admin')

    def test_settings_ok_for_global_admin(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        settings = {'registration_enabled': 'true', 'user_team_creation_enabled': 'true', 'classification_enabled': 'true', 'classification_text': 'SECRET', 'classification_color': '#c62828', 'classification_fg': '#ffffff'}
        with patch.object(db, 'as_user', return_value=_conn(fetchall=[])[0]), patch.object(db, 'connect_admin', return_value=_conn(fetchall=[])[0]), patch.object(authz, 'is_global_admin', return_value=True), patch.object(settings_svc, 'get_settings', return_value=settings), patch.object(settings_svc, 'classification', return_value={'enabled': True, 'text': 'SECRET', 'color': '#c62828', 'fg': '#ffffff'}):
            r = self.client.get('/settings')
        assert r.status_code == 200
        assert b'?tab=general' in r.data
        assert b'?tab=branding' in r.data
        assert b'?tab=banner' in r.data
        assert b'?tab=admins' in r.data
        assert b'?tab=ldap' in r.data
        assert b'?tab=email' in r.data
        assert b'Account registration' in r.data
        assert b'Team creation' in r.data
        assert b'Save banner' not in r.data
        assert b'Make global admin' not in r.data

    def test_settings_banner_tab(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        settings = {'classification_enabled': 'true', 'classification_text': 'SECRET', 'classification_color': '#c62828', 'classification_fg': '#ffffff'}
        with patch.object(db, 'as_user', return_value=_conn(fetchall=[])[0]), patch.object(db, 'connect_admin', return_value=_conn(fetchall=[])[0]), patch.object(authz, 'is_global_admin', return_value=True), patch.object(settings_svc, 'get_settings', return_value=settings), patch.object(settings_svc, 'classification', return_value={'enabled': True, 'text': 'SECRET', 'color': '#c62828', 'fg': '#ffffff'}):
            r = self.client.get('/settings?tab=banner')
        assert r.status_code == 200
        assert b'Classification banner' in r.data
        assert b'SECRET' in r.data

    def test_settings_admins_tab(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        conn, _ = _conn(fetchall=[{'id': self.uid, 'email': 'admin@ex.com', 'name': 'Admin', 'is_global_admin': True, 'created_at': 'now'}])
        with patch.object(db, 'as_user', return_value=conn), patch.object(db, 'connect_admin', return_value=conn), patch.object(authz, 'is_global_admin', return_value=True), patch.object(settings_svc, 'get_settings', return_value={}), patch.object(settings_svc, 'classification', return_value={'enabled': False, 'text': '', 'color': '#000', 'fg': '#fff'}):
            r = self.client.get('/settings?tab=admins')
        assert r.status_code == 200
        assert b'Global admins' in r.data

    def test_settings_health_tab(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        conn, _ = _conn(fetchone={'v': 'PostgreSQL 16.1 on x86_64', 'db': 'secrets', 'usr': 'admin'}, fetchall=[])
        with patch.object(db, 'as_user', return_value=_conn(fetchall=[])[0]), patch.object(db, 'connect_admin', return_value=conn), patch.object(authz, 'is_global_admin', return_value=True), patch.object(settings_svc, 'get_settings', return_value={}), patch.object(settings_svc, 'classification', return_value={'enabled': False, 'text': '', 'color': '#000', 'fg': '#fff'}), patch.object(cache, 'redis_client', return_value=None):
            r = self.client.get('/settings?tab=health')
        assert r.status_code == 200
        assert b'Server health' in r.data
        assert b'PostgreSQL' in r.data
        assert b'Redis' in r.data
        assert b'Test connection' in r.data
        assert b'not configured' in r.data

    def test_health_test_redis_post_redirects(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(cache, 'redis_client', return_value=None), patch.object(db, 'connect_admin', return_value=_conn(fetchall=[])[0]):
            r = self.client.post('/settings', data={'action': 'health_test_redis'}, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=health' in r.location

    def test_save_classification(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        sets = []

        def set_setting(k, v):
            sets.append((k, v))
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(settings_svc, 'set_setting', side_effect=set_setting), patch.object(db, 'as_user', return_value=_conn(fetchall=[])[0]):
            r = self.client.post('/settings', data={'action': 'classification', 'classification_enabled': '1', 'classification_text': 'OFFICIAL', 'classification_color': '#677381', 'classification_fg': '#ffffff'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/settings' in r.location
        assert 'tab=banner' in r.location
        assert dict(sets) == {'classification_enabled': 'true', 'classification_text': 'OFFICIAL', 'classification_color': '#677381', 'classification_fg': '#ffffff'}

    def test_save_token_policy(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        sets = []
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(settings_svc, 'set_setting', side_effect=lambda k, v: sets.append((k, v))), patch.object(db, 'as_user', return_value=_conn(fetchall=[])[0]):
            r = self.client.post('/settings', data={'action': 'token_policy', 'require_pat_expiry': '1', 'max_pat_lifetime_days': '90', 'require_machine_token_expiry': '1', 'max_machine_token_lifetime_days': '180'}, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=general' in r.location
        assert dict(sets) == {
            'require_pat_expiry': 'true',
            'max_pat_lifetime_days': '90',
            'require_machine_token_expiry': 'true',
            'max_machine_token_lifetime_days': '180',
        }

    def test_settings_email_tab(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        settings = {'smtp_enabled': 'true', 'smtp_host': 'smtp.example.com', 'smtp_port': '587', 'smtp_encryption': 'starttls', 'smtp_username': 'mailer', 'smtp_password': 'enc', 'smtp_from_email': 'noreply@example.com', 'smtp_from_name': 'Secret Store', 'smtp_login_alerts': 'true'}
        with patch.object(db, 'as_user', return_value=_conn(fetchall=[])[0]), patch.object(db, 'connect_admin', return_value=_conn(fetchall=[])[0]), patch.object(authz, 'is_global_admin', return_value=True), patch.object(settings_svc, 'get_settings', return_value=settings), patch.object(settings_svc, 'classification', return_value={'enabled': False, 'text': '', 'color': '#000', 'fg': '#fff'}):
            r = self.client.get('/settings?tab=email')
        assert r.status_code == 200
        assert b'Email (SMTP)' in r.data
        assert b'smtp.example.com' in r.data
        assert b'login alert' in r.data.lower()
        assert b'Send test' in r.data

    def test_save_smtp(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        sets = []

        def set_setting(k, v):
            sets.append((k, v))
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(settings_svc, 'set_setting', side_effect=set_setting), patch.object(db, 'as_user', return_value=_conn(fetchall=[])[0]), patch.object(crypto, 'encrypt', return_value='encrypted-pw'):
            r = self.client.post('/settings', data={'action': 'smtp', 'smtp_enabled': '1', 'smtp_host': 'smtp.example.com', 'smtp_port': '465', 'smtp_encryption': 'ssl', 'smtp_username': 'user', 'smtp_password': 'secret', 'smtp_from_email': 'noreply@example.com', 'smtp_from_name': 'SS', 'smtp_login_alerts': '1'}, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=email' in r.location
        d = dict(sets)
        assert d['smtp_enabled'] == 'true'
        assert d['smtp_host'] == 'smtp.example.com'
        assert d['smtp_port'] == '465'
        assert d['smtp_encryption'] == 'ssl'
        assert d['smtp_password'] == 'encrypted-pw'
        assert d['smtp_login_alerts'] == 'true'
        assert d['smtp_login_alerts_force'] == 'false'

    def test_smtp_test_action(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(db, 'as_user', return_value=_conn(fetchall=[])[0]), patch('integrations.mailer.send_test_email', return_value=(True, '')) as send:
            r = self.client.post('/settings', data={'action': 'smtp_test', 'test_email': 'admin@ex.com'}, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=email' in r.location
        send.assert_called_once_with('admin@ex.com')

    def test_users_tab_lists_accounts(self):
        other = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        users = [{'id': self.uid, 'email': 'admin@ex.com', 'name': 'Admin', 'is_global_admin': True, 'auth_source': 'local', 'totp_enabled_at': None, 'disabled_at': None, 'created_at': 'now'}, {'id': other, 'email': 'user@ex.com', 'name': 'User', 'is_global_admin': False, 'auth_source': 'local', 'totp_enabled_at': '2026-01-01', 'disabled_at': None, 'created_at': 'now'}]
        conn, _ = _conn(fetchall=users)
        with patch.object(db, 'as_user', return_value=conn), patch.object(db, 'connect_admin', return_value=conn), patch.object(authz, 'is_global_admin', return_value=True), patch.object(settings_svc, 'get_settings', return_value={}), patch.object(settings_svc, 'classification', return_value={'enabled': False, 'text': '', 'color': '#000', 'fg': '#fff'}):
            r = self.client.get('/settings?tab=users')
        assert r.status_code == 200
        assert b'Platform users' in r.data
        assert b'user@ex.com' in r.data
        assert b'Disable' in r.data
        assert b'Reset password' in r.data
        assert b'Reset 2FA' in r.data

    def test_user_disable_action(self):
        other = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        conn, cur = _conn(fetchone={'email': 'user@ex.com'})
        cur.rowcount = 1
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(db, 'as_user', return_value=conn), patch.object(db, 'connect_admin', return_value=conn), patch('auth.user_sessions.revoke_all_sessions', return_value=2) as rev:
            r = self.client.post('/settings', data={'action': 'user_disable', 'user_id': other}, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=users' in r.location
        rev.assert_called_once_with(other)

    def test_user_cannot_disable_self(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(db, 'as_user', return_value=_conn()[0]):
            r = self.client.post('/settings', data={'action': 'user_disable', 'user_id': self.uid}, follow_redirects=False)
        assert r.status_code == 302
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('own' in msg.lower() for _c, msg in flashes))

    def test_user_reset_password_action(self):
        other = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        conn, _ = _conn(fetchone={'email': 'user@ex.com'})
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(db, 'as_user', return_value=conn), patch.object(db, 'connect_admin', return_value=conn), patch('auth.passwords.create_reset_token_for_user', return_value=('tok123', '')), patch('integrations.mailer.smtp_configured', return_value=False), patch('auth.user_sessions.revoke_all_sessions', return_value=0):
            r = self.client.post('/settings', data={'action': 'user_reset_password', 'user_id': other}, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=users' in r.location
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('reset' in msg.lower() and 'tok123' in msg for _c, msg in flashes))

    def test_user_reset_2fa_action(self):
        other = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        conn, _ = _conn(fetchone={'email': 'user@ex.com'})
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(db, 'as_user', return_value=conn), patch.object(db, 'connect_admin', return_value=conn), patch('auth.totp_svc.is_enabled', return_value=True), patch('auth.totp_svc.disable') as dis, patch('auth.user_sessions.revoke_all_sessions', return_value=1):
            r = self.client.post('/settings', data={'action': 'user_reset_2fa', 'user_id': other}, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=users' in r.location
        dis.assert_called_once_with(other)



class TestLoginBanner:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True

    def test_save(self):
        with patch.object(authz, 'is_global_admin', return_value=True), \
             patch.object(settings_svc, 'set_setting') as set_setting:
            r = self.client.post('/settings', data={
                'action': 'login_banner',
                'login_banner_enabled': '1',
                'login_banner_text': 'Authorized use only.\nAll activity is monitored.',
                'login_banner_link_text': 'Acceptable Use Policy',
                'login_banner_link_url': 'https://example.com/policy',
            }, follow_redirects=False)
        assert r.status_code == 302
        calls = {c.args[0]: c.args[1] for c in set_setting.call_args_list}
        assert calls['login_banner_enabled'] == 'true'
        assert calls['login_banner_text'] == 'Authorized use only.\nAll activity is monitored.'
        assert calls['login_banner_link_text'] == 'Acceptable Use Policy'
        assert calls['login_banner_link_url'] == 'https://example.com/policy'

    def test_requires_text_when_enabled(self):
        with patch.object(authz, 'is_global_admin', return_value=True), \
             patch.object(settings_svc, 'set_setting') as set_setting:
            r = self.client.post('/settings', data={
                'action': 'login_banner',
                'login_banner_enabled': '1',
                'login_banner_text': '',
            }, follow_redirects=False)
        assert r.status_code == 302
        assert not set_setting.called

    def test_rejects_bad_link_url(self):
        with patch.object(authz, 'is_global_admin', return_value=True), \
             patch.object(settings_svc, 'set_setting') as set_setting:
            r = self.client.post('/settings', data={
                'action': 'login_banner',
                'login_banner_enabled': '1',
                'login_banner_text': 'No.',
                'login_banner_link_url': 'javascript:alert(1)',
            }, follow_redirects=False)
        assert r.status_code == 302
        assert not set_setting.called

    def test_shown_on_login_page(self):
        with patch.object(settings_svc, 'get_settings', return_value=dict(
            config.DEFAULT_SETTINGS,
            login_banner_enabled='true',
            login_banner_text='Authorized use only',
            login_banner_link_text='Acceptable Use Policy',
            login_banner_link_url='/policy',
        )):
            r = store.app.test_client().get('/login')
        assert r.status_code == 200
        assert b'login-note' in r.data
        assert b'Authorized use only' in r.data
        assert b'/policy' in r.data

    def test_hidden_when_disabled(self):
        with patch.object(settings_svc, 'get_settings', return_value=dict(config.DEFAULT_SETTINGS)):
            r = store.app.test_client().get('/login')
        assert r.status_code == 200
        assert b'login-note' not in r.data


class TestUxSettings:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True

    def test_save_ux(self):
        with patch.object(authz, 'is_global_admin', return_value=True), \
             patch.object(settings_svc, 'set_setting') as set_setting:
            r = self.client.post('/settings', data={
                'action': 'ux',
                'clipboard_clear_seconds': '45',
                'reveal_auto_hide_seconds': '20',
                'reveal_access_grant_minutes': '60',
            }, follow_redirects=False)
        assert r.status_code == 302
        calls = {c.args[0]: c.args[1] for c in set_setting.call_args_list}
        assert calls['clipboard_clear_seconds'] == '45'
        assert calls['reveal_auto_hide_seconds'] == '20'
        assert calls['reveal_access_grant_minutes'] == '60'

    def test_rejects_non_numeric(self):
        with patch.object(authz, 'is_global_admin', return_value=True), \
             patch.object(settings_svc, 'set_setting') as set_setting:
            r = self.client.post('/settings', data={
                'action': 'ux',
                'clipboard_clear_seconds': 'lots',
                'reveal_auto_hide_seconds': '20',
                'reveal_access_grant_minutes': '60',
            }, follow_redirects=False)
        assert r.status_code == 302
        assert not set_setting.called


class TestConnectionTests:
    """Inline LDAP / OIDC connection tests (action=ldap_test|oidc_test)."""

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        # Probe imports ldap3 inside the handler; stub so unit tests
        # don't require the optional LDAP extra.
        self._ldap3_patch = patch.dict("sys.modules", {"ldap3": MagicMock()})
        self._ldap3_patch.start()

    def teardown_method(self, method=None):
        self._ldap3_patch.stop()

    def _render_mocks(self):
        return (
            patch.object(db, 'as_user', return_value=_conn(fetchall=[])[0]),
            patch.object(db, 'connect_admin', return_value=_conn(fetchall=[])[0]),
            patch.object(authz, 'is_global_admin', return_value=True),
            patch.object(settings_svc, 'get_settings', return_value={}),
            patch.object(settings_svc, 'classification', return_value={'enabled': False, 'text': '', 'color': '#000', 'fg': '#fff'}),
        )

    def test_ldap_test_success_renders_inline(self):
        conn = MagicMock()
        conn.search.return_value = True
        conn.entries = [MagicMock(), MagicMock()]
        mocks = self._render_mocks()
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], \
             patch('integrations.ldap_auth._ldap_bind', return_value=conn) as bind:
            r = self.client.post('/settings?tab=ldap', data={
                'action': 'ldap_test',
                'ldap_url': 'ldaps://ipa.example.com',
                'ldap_user_base': 'cn=users,dc=example,dc=com',
                'ldap_user_filter': '(mail={login})',
                'ldap_probe_login': 'alice@example.com',
            }, follow_redirects=False)
        assert r.status_code == 200
        assert b'Connected' in r.data
        assert b'Bind OK' in r.data
        assert b'matched 2 entries' in r.data
        assert b'name="ldap_probe_login" value="alice@example.com"' in r.data  # probe login restored
        bind.assert_called_once()

    def test_ldap_test_refuses_cleartext(self):
        mocks = self._render_mocks()
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], \
             patch('integrations.ldap_auth._ldap_bind') as bind:
            r = self.client.post('/settings?tab=ldap', data={
                'action': 'ldap_test',
                'ldap_url': 'ldap://ipa.example.com',
                'ldap_user_base': 'cn=users,dc=example,dc=com',
            }, follow_redirects=False)
        assert r.status_code == 200
        assert b'Refused' in r.data
        assert not bind.called

    def test_ldap_test_bind_failure_never_raises(self):
        mocks = self._render_mocks()
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], \
             patch('integrations.ldap_auth._ldap_bind', side_effect=RuntimeError('LDAP bind failed')):
            r = self.client.post('/settings?tab=ldap', data={
                'action': 'ldap_test',
                'ldap_url': 'ldaps://ipa.example.com',
                'ldap_user_base': 'cn=users,dc=example,dc=com',
            }, follow_redirects=False)
        assert r.status_code == 200
        assert b'LDAP bind failed' in r.data

    def test_ldap_test_zero_matches_warns(self):
        conn = MagicMock()
        conn.search.return_value = True
        conn.entries = []
        mocks = self._render_mocks()
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], \
             patch('integrations.ldap_auth._ldap_bind', return_value=conn):
            r = self.client.post('/settings?tab=ldap', data={
                'action': 'ldap_test',
                'ldap_url': 'ldaps://ipa.example.com',
                'ldap_user_base': 'cn=users,dc=example,dc=com',
            }, follow_redirects=False)
        assert r.status_code == 200
        assert b'Check settings' in r.data
        assert b'matched 0 entries' in r.data

    def test_oidc_test_discovery_ok(self):
        doc = {
            'authorization_endpoint': 'https://idp.example/authorize',
            'token_endpoint': 'https://idp.example/token',
            'jwks_uri': 'https://idp.example/jwks',
        }
        mocks = self._render_mocks()
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], \
             patch('integrations.oidc_auth._http_json', return_value=doc) as http:
            r = self.client.post('/settings?tab=oidc', data={
                'action': 'oidc_test',
                'oidc_issuer': 'https://idp.example/realms/main/',
            }, follow_redirects=False)
        assert r.status_code == 200
        assert b'Discovery OK' in r.data
        http.assert_called_once_with('GET', 'https://idp.example/realms/main/.well-known/openid-configuration')

    def test_oidc_test_missing_endpoints_fails(self):
        doc = {'authorization_endpoint': 'https://idp.example/authorize'}
        mocks = self._render_mocks()
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], \
             patch('integrations.oidc_auth._http_json', return_value=doc):
            r = self.client.post('/settings?tab=oidc', data={
                'action': 'oidc_test',
                'oidc_issuer': 'https://idp.example',
            }, follow_redirects=False)
        assert r.status_code == 200
        assert b'missing' in r.data
        assert b'token_endpoint' in r.data
        assert b'jwks_uri' in r.data

    def test_oidc_test_http_error_reports_detail(self):
        mocks = self._render_mocks()
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], \
             patch('integrations.oidc_auth._http_json', side_effect=RuntimeError('OIDC HTTP 404 from issuer')):
            r = self.client.post('/settings?tab=oidc', data={
                'action': 'oidc_test',
                'oidc_issuer': 'https://idp.example',
            }, follow_redirects=False)
        assert r.status_code == 200
        assert b'OIDC HTTP 404' in r.data

    def test_ldap_save_still_redirects_after_test_actions_exist(self):
        sets = []
        mocks = self._render_mocks()
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], \
             patch.object(settings_svc, 'set_setting', side_effect=lambda k, v: sets.append((k, v))):
            r = self.client.post('/settings?tab=ldap', data={'action': 'ldap'}, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=ldap' in r.location

    def test_missing_action_does_not_trigger_classification_error(self):
        """A POST with no action (disabled submitter omitted) must not run banner save."""
        mocks = self._render_mocks()
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], \
             patch.object(settings_svc, 'set_setting') as set_setting:
            r = self.client.post('/settings?tab=oidc', data={
                'oidc_issuer': 'https://idp.example',
            }, follow_redirects=True)
        assert r.status_code == 200
        assert b'Banner colour must be a hex value' not in r.data
        assert b'OIDC / SSO settings saved' not in r.data
        assert not set_setting.called

    def test_missing_action_stays_on_requested_tab(self):
        mocks = self._render_mocks()
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4]:
            r = self.client.post('/settings?tab=oidc', data={
                'oidc_issuer': 'https://idp.example',
            }, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=oidc' in r.location
        assert 'tab=banner' not in r.location
