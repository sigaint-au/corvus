"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import app as store
import crypto
from core import db
from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestSecretLifecycle:
    """Versioning helpers, expiry status, import parse (no DB)."""

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        self.pid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'u@ex.com'

    def test_parse_env(self):
        from routes.projects import parse_secret_pairs
        pairs = parse_secret_pairs("FOO=bar\n# c\nBAZ='qux'\nexport Q=1\n")
        assert pairs == [('FOO', 'bar'), ('BAZ', 'qux'), ('Q', '1')]

    def test_parse_json_object(self):
        from routes.projects import parse_secret_pairs
        pairs = parse_secret_pairs('{"A": "1", "B": {"value": "2"}}')
        assert pairs == [('A', '1'), ('B', '2')]

    def test_parse_json_enc(self):
        from routes.projects import parse_secret_pairs
        pairs = parse_secret_pairs('{"K": {"value_enc": "gAAAA", "note": "n"}}')
        assert pairs[0][0] == 'K'
        assert pairs[0][1]['_enc'] == 'gAAAA'

    def test_parse_csv(self):
        from routes.projects import parse_secret_pairs
        pairs = parse_secret_pairs('key,value\nX,y\n')
        assert pairs == [('X', 'y')]

    def test_due_status(self):
        from datetime import datetime, timedelta, timezone

        from routes.projects import expires_status, secret_due_status
        now = datetime.now(timezone.utc)
        assert secret_due_status({'expires_at': now - timedelta(days=1)}) == 'overdue'
        assert secret_due_status({'expires_at': now + timedelta(days=3)}) == 'soon'
        assert secret_due_status({'expires_at': now + timedelta(days=60)}) is None
        assert secret_due_status({'updated_at': now - timedelta(days=10)}) is None
        assert expires_status(now - timedelta(hours=1)) == 'overdue'
        assert expires_status(now + timedelta(days=2)) == 'soon'
        assert expires_status(None) is None

    def test_secret_kind_helpers(self):
        from secret_svc import secret_kinds as sk
        assert sk.detect_secret_kind('secret', 'type:ssh') == 'plain'
        assert sk.detect_secret_kind('postgresql://u:p@h/db') == 'database'
        assert sk.normalize_kind('KV') == 'kv'
        assert sk.normalize_kind('nope') == 'plain'

    def test_history_requires_login(self):
        r = store.app.test_client().get(f'/projects/{uuid4()}/secrets/{uuid4()}/history')
        assert r.status_code == 302

    def test_export_plain_env(self):
        enc = crypto.encrypt('secret-val')
        conn, cur = _conn()
        cur.fetchone.return_value = {'r': True}
        cur.fetchall.return_value = [{'key': 'K', 'value_enc': enc, 'note': ''}]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/export?format=env&mode=plain')
        assert r.status_code == 200
        assert b'K=secret-val' in r.data
        conn.commit.assert_called()
        sql = ' '.join(str(c.args[0]) for c in cur.execute.call_args_list)
        assert 'audit_secret' in sql
        assert 'exported' in str(cur.execute.call_args_list)

    def test_import_preview(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'w': True}, {'name': 'prod', 'id': self.pid, 'team_name': 'T'}]
        cur.fetchall.return_value = [{'key': 'EXISTING'}]
        with patch.object(db, 'as_user', return_value=conn), patch('ui.nav.nav_teams', return_value=[]):
            r = self.client.post(f'/projects/{self.pid}/import/preview', data={'payload': 'NEW_KEY=hello\nEXISTING=updated'}, follow_redirects=False)
        assert r.status_code == 200
        assert b'Import preview' in r.data
        assert b'NEW_KEY' in r.data
        assert b'EXISTING' in r.data
        assert b'hello' in r.data
        assert b'updated' in r.data
        assert b'name="kind"' in r.data
        assert b'name="value"' in r.data
        with self.client.session_transaction() as s:
            assert s.get('import_pending') is None

    def test_import_commit(self):
        sid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = str(uuid4())
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'w': True}, None, {'id': sid}]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/import/commit', data={'key': 'NEW_KEY', 'value': 'hello', 'value_enc': '', 'note': '', 'kind': 'plain', 'enc': '0'}, follow_redirects=False)
        assert r.status_code == 302
        conn.commit.assert_called()

    def test_history_page(self):
        sid, vid = (uuid4(), uuid4())
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'id': sid, 'key': 'K', 'note': 'current note', 'updated_at': '2026-01-02', 'expires_at': None}, {'w': True}, {'name': 'prod', 'id': self.pid, 'team_name': 'Ops', 'team_id': uuid4()}]
        cur.fetchall.return_value = [{'id': vid, 'note': 'old note', 'created_at': '2020-01-01'}]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/history')
        assert r.status_code == 200
        assert b'Current' in r.data
        assert b'Prior versions' in r.data
        assert b'current note' in r.data
        assert b'old note' in r.data
        assert b'Reveal' in r.data
        assert b'Rollback' in r.data
        assert b'versions/' in r.data

    def test_reveal_secret_version(self):
        sid, vid = (uuid4(), uuid4())
        enc = crypto.encrypt('prior-secret')
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'key': 'K', 'secret_id': sid}, {'a': True}, {'value_enc': enc, 'crypto_provider': 'master'}]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/versions/{vid}/reveal')
        assert r.status_code == 200
        assert b'prior-secret' in r.data

