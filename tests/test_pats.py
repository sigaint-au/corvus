"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

import jwt as pyjwt
import app as store
from core import config
from core import db
from auth import pats

from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestPatsUnit:

    def test_mint_raw_shape(self):
        raw, thash, prefix = pats.mint_raw()
        assert raw.startswith('pat_')
        assert len(thash) == 64
        assert prefix == raw[:12]
        assert pats.sha256_hex(raw) == thash

    def test_create_requires_name(self):
        with pytest.raises(ValueError):
            pats.create(str(uuid4()), '  ')

    def test_create_inserts_row(self):
        uid = str(uuid4())
        conn, cur = _conn(fetchone={'n': 0})
        cur.rowcount = 1
        with patch.object(db, 'connect_admin', return_value=conn):
            raw = pats.create(uid, 'cli', expires_days=7)
        assert raw.startswith('pat_')
        joined = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list if c.args))
        assert 'INSERT INTO private.personal_access_tokens' in joined

    def test_resolve_success(self):
        uid = str(uuid4())
        tid = uuid4()
        conn, cur = _conn(fetchone={'id': tid, 'user_id': uid})
        cur.rowcount = 1
        with patch.object(db, 'connect_admin', return_value=conn):
            assert pats.resolve('pat_' + 'x' * 40) == uid
        joined = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list if c.args))
        assert 'last_used_at' in joined

    def test_resolve_rejects_garbage(self):
        assert pats.resolve('') is None
        assert pats.resolve('ss_notapat') is None
        assert pats.resolve('pat_short') is None

    def test_resolve_unknown_hash(self):
        conn, cur = _conn(fetchone=None)
        with patch.object(db, 'connect_admin', return_value=conn):
            assert pats.resolve('pat_' + 'x' * 40) is None

    def test_revoke(self):
        uid = str(uuid4())
        conn, cur = _conn()
        cur.rowcount = 1
        with patch.object(db, 'connect_admin', return_value=conn):
            assert pats.revoke(uid, str(uuid4()))
        cur.rowcount = 0
        with patch.object(db, 'connect_admin', return_value=conn):
            assert not pats.revoke(uid, str(uuid4()))

    def test_create_rejects_bad_expiry(self):
        with patch.object(pats, 'count_for_user', return_value=0):
            with pytest.raises(ValueError):
                pats.create(str(uuid4()), 'x', expires_days=0)
            with pytest.raises(ValueError):
                pats.create(str(uuid4()), 'x', expires_days=99999)

    def test_create_requires_expiry_when_policy_enabled(self):
        with patch.object(pats, 'count_for_user', return_value=0), patch.object(pats.settings_svc, 'token_expiry_policy', return_value=(True, 3650)):
            with pytest.raises(ValueError, match='Expires days is required'):
                pats.create(str(uuid4()), 'x')

    def test_create_uses_policy_max(self):
        with patch.object(pats, 'count_for_user', return_value=0), patch.object(pats.settings_svc, 'token_expiry_policy', return_value=(False, 30)):
            with pytest.raises(ValueError, match='between 1 and 30'):
                pats.create(str(uuid4()), 'x', expires_days=31)


class TestPersonalTokenRoutes:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'u@ex.com'

    def test_create_pat(self):
        with patch.object(pats, 'create', return_value='pat_secretvalue') as create:
            r = self.client.post('/profile/tokens', data={'name': 'laptop', 'expires_days': '30'}, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=security' in r.location
        create.assert_called_once()
        assert create.call_args[0][0] == self.uid
        assert create.call_args[0][1] == 'laptop'
        assert create.call_args[1].get('expires_days') == 30
        with self.client.session_transaction() as s:
            assert s.get('new_pat') == 'pat_secretvalue'

    def test_create_pat_value_error(self):
        with patch.object(pats, 'create', side_effect=ValueError('Name is required')):
            r = self.client.post('/profile/tokens', data={'name': ''}, follow_redirects=False)
        assert r.status_code == 302
        with self.client.session_transaction() as s:
            assert 'new_pat' not in s
            flashes = s.get('_flashes') or []
        assert any(('Name is required' in msg for _c, msg in flashes))

    def test_delete_pat(self):
        tid = uuid4()
        with patch.object(pats, 'revoke', return_value=True) as rev:
            r = self.client.post(f'/profile/tokens/{tid}/delete', follow_redirects=False)
        assert r.status_code == 302
        rev.assert_called_once_with(self.uid, str(tid))

    def test_delete_pat_missing(self):
        with patch.object(pats, 'revoke', return_value=False):
            r = self.client.post(f'/profile/tokens/{uuid4()}/delete', follow_redirects=False)
        assert r.status_code == 302
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('not found' in msg.lower() for _c, msg in flashes))


class TestApiToken:

    def test_requires_login(self):
        r = store.app.test_client().get('/api/token')
        assert r.status_code == 302

    def test_returns_jwt(self):
        c = store.app.test_client()
        uid = str(uuid4())
        with c.session_transaction() as s:
            s['user_id'] = uid
        r = c.get('/api/token')
        assert r.status_code == 200
        data = r.get_json()
        assert data['token_type'] == 'bearer'
        claims = pyjwt.decode(data['access_token'], config.JWT_SECRET, algorithms=['HS256'])
        assert claims['sub'] == uid
        assert 'expires_in' in data

    def test_unauthenticated_json_401(self):
        r = store.app.test_client().get('/api/token', headers={'Accept': 'application/json'})
        assert r.status_code == 401

    def test_pat_bearer_returns_jwt(self):
        uid = str(uuid4())
        with patch.object(pats, 'resolve', return_value=uid):
            r = store.app.test_client().get('/api/token', headers={'Authorization': 'Bearer pat_testdummytokenvaluehere', 'Accept': 'application/json'})
        assert r.status_code == 200
        claims = pyjwt.decode(r.get_json()['access_token'], config.JWT_SECRET, algorithms=['HS256'])
        assert claims['sub'] == uid

    def test_bad_pat_401(self):
        with patch.object(pats, 'resolve', return_value=None):
            r = store.app.test_client().get('/api/token', headers={'Authorization': 'Bearer pat_invalid'})
        assert r.status_code == 401

