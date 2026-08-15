"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

import re
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

import app as store
from auth import authz
from core import config
from core import db
from integrations import ldap_auth
from core import settings_svc

from tests.helpers import REPO_ROOT, mock_conn as _conn

store.app.config["TESTING"] = True

class TestTotp:

    def test_verify_code_window(self):
        import base64
        import hashlib
        import hmac
        import struct
        import time

        from auth import totp_svc

        secret = (base64.b32encode(b"0" * 20)).decode().rstrip("=")
        code = totp_svc._totp_code(secret, int(time.time()) // 30)
        assert totp_svc.verify_code(secret, code)
        assert not totp_svc.verify_code(secret, '000000')
        assert not totp_svc.verify_code(secret, 'abcdef')

    def test_recovery_code_hash_roundtrip(self):
        from auth import totp_svc
        codes = totp_svc.generate_recovery_codes(3)
        assert len(codes) == 3
        assert re.search('^([a-f0-9]{4}-){7}[a-f0-9]{4}$', codes[0])
        h = totp_svc.hash_recovery_code(codes[0])
        assert h == totp_svc.hash_recovery_code(codes[0].upper().replace('-', ''))
        assert totp_svc.recovery_hash_matches(codes[0], h)
        legacy = totp_svc._legacy_hash_recovery_code(codes[0])
        assert totp_svc.recovery_hash_matches(codes[0], legacy)

    def test_needs_challenge(self):
        from auth import totp_svc
        uid = str(uuid4())
        with patch.object(totp_svc, 'is_enabled', return_value=True):
            assert totp_svc.needs_challenge(uid, False) == 'verify'
        with patch.object(totp_svc, 'is_enabled', return_value=False), patch.object(totp_svc, 'enforce_global_admins', return_value=True):
            assert totp_svc.needs_challenge(uid, True) == 'enroll'
            assert totp_svc.needs_challenge(uid, False) is None
        with patch.object(totp_svc, 'is_enabled', return_value=False), patch.object(totp_svc, 'enforce_global_admins', return_value=False):
            assert totp_svc.needs_challenge(uid, True) is None

    def test_user_totp_row_fails_closed(self):
        from auth import totp_svc
        with patch.object(db, 'connect_admin', side_effect=RuntimeError('db down')):
            with pytest.raises(totp_svc.TotpStoreError):
                totp_svc.user_totp_row(str(uuid4()))

    def test_login_redirects_to_2fa(self):
        store.app.config['TESTING'] = True
        client = store.app.test_client()
        uid = uuid4()
        conn, _ = _conn(fetchone={'id': uid, 'email': 'a@b.c', 'name': 'A'})
        with patch.object(db, 'connect', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch('lockout.is_locked', return_value=False), patch('lockout.clear_failures'), patch.object(authz, 'is_global_admin', return_value=False), patch('totp_svc.needs_challenge', return_value='verify'):
            r = client.post('/login', data={'email': 'a@b.c', 'password': 'secret12'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/login/2fa' in r.location
        with client.session_transaction() as s:
            assert s.get('pending_2fa_uid') == str(uid)
            assert 'user_id' not in s

    def test_login_2fa_ok(self):
        store.app.config['TESTING'] = True
        client = store.app.test_client()
        uid = str(uuid4())
        with client.session_transaction() as s:
            s['pending_2fa_uid'] = uid
            s['pending_2fa_email'] = 'a@b.c'
            s['pending_2fa_name'] = 'A'
            s['pending_2fa_admin'] = False
        with patch('totp_svc.verify_user_code', return_value=(True, 'totp')), patch('lockout.is_locked', return_value=False), patch('lockout.clear_failures'), patch('user_sessions.create_session', return_value=None), patch('mailer.login_alerts_enabled', return_value=False):
            r = client.post('/login/2fa', data={'code': '123456'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location
        with client.session_transaction() as s:
            assert s.get('user_id') == uid
            assert 'pending_2fa_uid' not in s

    def test_login_enroll_admin(self):
        store.app.config['TESTING'] = True
        client = store.app.test_client()
        uid = uuid4()
        conn, _ = _conn(fetchone={'id': uid, 'email': 'admin@b.c', 'name': 'A'})
        with patch.object(db, 'connect', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch('lockout.is_locked', return_value=False), patch('lockout.clear_failures'), patch.object(authz, 'is_global_admin', return_value=True), patch('totp_svc.needs_challenge', return_value='enroll'), patch('user_sessions.create_session', return_value=None):
            r = client.post('/login', data={'email': 'admin@b.c', 'password': 'secret12'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/profile/2fa' in r.location
        with client.session_transaction() as s:
            assert s.get('user_id') == str(uid)
            assert s.get('totp_setup_required')

    def test_save_totp_enforce_setting(self):
        store.app.config['TESTING'] = True
        client = store.app.test_client()
        uid = str(uuid4())
        with client.session_transaction() as s:
            s['user_id'] = uid
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        sets = []
        with patch.object(authz, 'is_global_admin', return_value=True), patch.object(settings_svc, 'set_setting', side_effect=lambda k, v: sets.append((k, v))), patch.object(db, 'as_user', return_value=_conn(fetchall=[])[0]):
            r = client.post('/settings', data={'action': 'totp_enforce', 'totp_enforce_global_admins': '1'}, follow_redirects=False)
        assert r.status_code == 302
        assert dict(sets).get('totp_enforce_global_admins') == 'true'

    def test_schema_has_totp(self):
        from pathlib import Path
        init = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'totp_secret_enc' in init
        assert 'totp_recovery_codes' in init
        assert 'totp_enforce_global_admins' in init

