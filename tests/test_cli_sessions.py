"""Unit tests for CLI session tokens (mock DB — no Postgres required)."""
from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import app as store
from auth import cli_sessions
from core import db, settings_svc
from lib.auth_tokens import classify_token
from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True


class TestCliSessionsUnit:

    def test_mint_raw_shape(self):
        raw, thash, prefix = cli_sessions.mint_raw()
        assert raw.startswith('sso_')
        assert len(thash) == 64
        assert prefix == raw[:12]

    def test_ttl_seconds_floor(self):
        with patch.object(settings_svc, 'int_setting', return_value=5):
            assert cli_sessions.ttl_seconds() == 60

    def test_create_inserts_hashed_token(self):
        uid = str(uuid4())
        conn, cur = _conn()
        with patch.object(db, 'connect_admin', return_value=conn), \
             patch.object(settings_svc, 'int_setting', return_value=3600):
            raw = cli_sessions.create(uid)
        assert raw.startswith('sso_')
        joined = ' '.join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert 'INSERT INTO private.cli_session_tokens' in joined
        assert raw not in joined  # only the hash is stored

    def test_resolve_success(self):
        uid = str(uuid4())
        conn, cur = _conn(fetchone={'id': uuid4(), 'user_id': uid})
        with patch.object(db, 'connect_admin', return_value=conn):
            assert cli_sessions.resolve('sso_' + 'x' * 40) == uid
        joined = ' '.join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert 'last_used_at' in joined

    def test_resolve_rejects_garbage(self):
        assert cli_sessions.resolve('') is None
        assert cli_sessions.resolve('pat_notasso') is None
        assert cli_sessions.resolve('sso_short') is None

    def test_resolve_unknown_hash(self):
        conn, cur = _conn(fetchone=None)
        with patch.object(db, 'connect_admin', return_value=conn):
            assert cli_sessions.resolve('sso_' + 'x' * 40) is None

    def test_classify_token_returns_sso_kind(self):
        uid = str(uuid4())
        conn, cur = _conn(fetchone={'id': uuid4(), 'user_id': uid})
        with patch.object(db, 'connect_admin', return_value=conn):
            kind, ident = classify_token('sso_' + 'x' * 40)
        assert kind == 'sso'
        assert ident == uid

    def test_classify_token_sso_unresolved(self):
        conn, cur = _conn(fetchone=None)
        with patch.object(db, 'connect_admin', return_value=conn):
            kind, ident = classify_token('sso_' + 'x' * 40)
        assert kind is None
        assert ident is None


class TestCliLoginRoutes:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'u@ex.com'

    def test_cli_login_command_renders_command(self):
        with patch.object(cli_sessions, 'create', return_value='sso_secretvalue'), \
             patch.object(settings_svc, 'public_base_url', return_value='https://secrets.example.com'), \
             patch.object(settings_svc, 'int_setting', return_value=3600):
            r = self.client.post('/login/command', follow_redirects=False)
        assert r.status_code == 200
        body = r.get_data(as_text=True)
        assert 'corvus login --url https://secrets.example.com --token sso_secretvalue' in body
        assert 'cli-login-command' in body
        assert '60 minutes' in body

    def test_cli_login_command_requires_login(self):
        r = store.app.test_client().post('/login/command', follow_redirects=False)
        assert r.status_code == 302
