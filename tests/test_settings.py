"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

import app as store
from auth import authz
from core import config
import crypto
from core import db
from core import settings_svc

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
        assert b'?tab=banner' in r.data
        assert b'?tab=admins' in r.data
        assert b'?tab=users' in r.data
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

    def test_smtp_test_action(self):
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(db, 'as_user', return_value=_conn(fetchall=[])[0]), patch('mailer.send_test_email', return_value=(True, '')) as send:
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
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(db, 'as_user', return_value=conn), patch.object(db, 'connect_admin', return_value=conn), patch('user_sessions.revoke_all_sessions', return_value=2) as rev:
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
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(db, 'as_user', return_value=conn), patch.object(db, 'connect_admin', return_value=conn), patch('passwords.create_reset_token_for_user', return_value=('tok123', '')), patch('mailer.smtp_configured', return_value=False), patch('user_sessions.revoke_all_sessions', return_value=0):
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
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(db, 'as_user', return_value=conn), patch.object(db, 'connect_admin', return_value=conn), patch('totp_svc.is_enabled', return_value=True), patch('totp_svc.disable') as dis, patch('user_sessions.revoke_all_sessions', return_value=1):
            r = self.client.post('/settings', data={'action': 'user_reset_2fa', 'user_id': other}, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=users' in r.location
        dis.assert_called_once_with(other)

