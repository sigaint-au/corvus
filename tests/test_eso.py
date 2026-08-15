"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

import app as store
from core import config, db, settings_svc
import crypto
from auth import pats
from routes import eso as eso_routes

from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestESO:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.pid = uuid4()

    def test_get_no_auth(self):
        r = self.client.get(f'/eso/v1/projects/{self.pid}/secrets/KEY')
        assert r.status_code == 401

    def test_get_secret_ok(self):
        enc = crypto.encrypt('val')
        sid = uuid4()
        fo = [{'ok': True}, {'id': sid, 'key': 'KEY', 'value_enc': enc, 'note': 'n', 'kind': 'plain', 'expires_at': None, 'created_at': None, 'updated_at': None}, {'label': 'eso:ss_testtoke'}]
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        with patch.object(db, 'connect', return_value=conn):
            r = self.client.get(f'/eso/v1/projects/{self.pid}/secrets/KEY', headers={'Authorization': 'Bearer ss_testtoken'})
        assert r.status_code == 200
        body = r.get_json()
        assert body['value'] == 'val'
        assert body['key'] == 'KEY'
        assert body['id'] == str(sid)
        assert body['note'] == 'n'
        assert body['kind'] == 'plain'
        conn.commit.assert_called()
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
        assert 'audit_secret' in sql
        audit_params = [c.args[1] for c in cur.execute.call_args_list if c.args and 'audit_secret' in str(c.args[0])]
        assert any(('revealed' in p for p in audit_params))

    def test_get_secret_not_found(self):
        fo = [{'ok': True}, None]
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        with patch.object(db, 'connect', return_value=conn):
            r = self.client.get(f'/eso/v1/projects/{self.pid}/secrets/MISSING', headers={'Authorization': 'Bearer ss_x'})
        assert r.status_code == 404

    def test_list_unauthorized(self):
        conn, _ = _conn(fetchone={'ok': False})
        with patch.object(db, 'connect', return_value=conn):
            r = self.client.get(f'/eso/v1/projects/{self.pid}/secrets', headers={'Authorization': 'Bearer bad'})
        assert r.status_code == 401

    def test_list_ok(self):
        fo = [{'ok': True}, {'label': 'eso:ss_ok'}]
        enc = crypto.encrypt('v1')
        conn, cur = _conn(fetchall=[{'key': 'A', 'value_enc': enc}])
        cur.fetchone.side_effect = fo
        with patch.object(db, 'connect', return_value=conn):
            r = self.client.get(f'/eso/v1/projects/{self.pid}/secrets', headers={'Authorization': 'Bearer ss_ok'})
        assert r.status_code == 200
        assert r.get_json()['secrets'] == {'A': 'v1'}
        conn.commit.assert_called()
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
        assert 'audit_secret' in sql
        audit_params = [c.args[1] for c in cur.execute.call_args_list if c.args and 'audit_secret' in str(c.args[0])]
        assert any(('exported' in p for p in audit_params))
        assert any((any((isinstance(x, str) and 'machine/values' in x for x in p)) for p in audit_params))

    def test_list_meta_ok(self):
        sid = uuid4()
        fo = [{'ok': True}, {'label': 'eso:ss_ok'}]
        conn, cur = _conn(fetchall=[{'id': sid, 'key': 'API_KEY', 'note': 'prod', 'kind': 'plain', 'expires_at': None, 'created_at': None, 'updated_at': None}])
        cur.fetchone.side_effect = fo
        with patch.object(db, 'connect', return_value=conn):
            r = self.client.get(f'/eso/v1/projects/{self.pid}/secrets?meta=1&q=api', headers={'Authorization': 'Bearer ss_ok'})
        assert r.status_code == 200
        items = r.get_json()['items']
        assert len(items) == 1
        assert items[0]['key'] == 'API_KEY'
        assert items[0]['id'] == str(sid)
        assert 'value' not in items[0]
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
        assert 'machine_list_meta' in sql
        assert 'audit_secret' in sql
        audit_params = [c.args[1] for c in cur.execute.call_args_list if c.args and 'audit_secret' in str(c.args[0])]
        assert any(('exported' in p for p in audit_params))
        assert any((any((isinstance(x, str) and 'machine/meta' in x for x in p)) for p in audit_params))
        conn.commit.assert_called()

    def test_bearer_hash_none(self):
        with store.app.test_request_context('/', headers={}):
            assert eso_routes.bearer_hash() is None

    def test_upsert_read_forbidden(self):
        fo = [{'ok': True}, {'role': 'read'}]
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        with patch.object(db, 'connect', return_value=conn):
            r = self.client.post(f'/eso/v1/projects/{self.pid}/secrets', json={'key': 'K', 'value': 'v'}, headers={'Authorization': 'Bearer ss_ro'})
        assert r.status_code == 403
        assert 'write' in r.get_json().get('error', '')
        conn.commit.assert_not_called()

    def test_upsert_write_ok(self):
        sid = uuid4()
        fo = [{'ok': True}, {'role': 'write'}, {'id': sid}, {'label': 'ci:ss_write'}, {'id': sid, 'key': 'K', 'value_enc': crypto.encrypt('secret'), 'note': '', 'kind': 'plain', 'expires_at': None, 'created_at': None, 'updated_at': None}]
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        with patch.object(db, 'connect', return_value=conn):
            r = self.client.post(f'/eso/v1/projects/{self.pid}/secrets', json={'key': 'K', 'value': 'secret'}, headers={'Authorization': 'Bearer ss_write'})
        assert r.status_code == 200
        body = r.get_json()
        assert body['ok']
        assert body['key'] == 'K'
        assert body['value'] == 'secret'
        conn.commit.assert_called()
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
        assert 'audit_secret' in sql
        assert 'machine_upsert' in sql

    def test_put_secret_ok(self):
        sid = uuid4()
        fo = [{'ok': True}, {'role': 'write'}, {'id': sid}, {'label': 'ci:ss_write'}, {'id': sid, 'key': 'API_KEY', 'value_enc': crypto.encrypt('new'), 'note': 'rotated', 'kind': 'plain', 'expires_at': None, 'created_at': None, 'updated_at': None}]
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        with patch.object(db, 'connect', return_value=conn):
            r = self.client.put(f'/eso/v1/projects/{self.pid}/secrets/API_KEY', json={'value': 'new', 'note': 'rotated'}, headers={'Authorization': 'Bearer ss_write'})
        assert r.status_code == 200
        assert r.get_json()['key'] == 'API_KEY'
        assert r.get_json()['value'] == 'new'
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
        assert 'machine_upsert' in sql

    def test_patch_secret_not_found(self):
        fo = [{'ok': True}, {'role': 'write'}, None]
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        with patch.object(db, 'connect', return_value=conn):
            r = self.client.patch(f'/eso/v1/projects/{self.pid}/secrets/MISSING', json={'note': 'x'}, headers={'Authorization': 'Bearer ss_write'})
        assert r.status_code == 404

    def test_delete_secret_ok(self):
        sid = uuid4()
        enc = crypto.encrypt('v')
        fo = [{'ok': True}, {'role': 'write'}, {'id': sid, 'key': 'K', 'value_enc': enc, 'note': '', 'kind': 'plain', 'expires_at': None, 'created_at': None, 'updated_at': None}, {'id': sid}, {'label': 'ci:ss_write'}]
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        with patch.object(db, 'connect', return_value=conn):
            r = self.client.delete(f'/eso/v1/projects/{self.pid}/secrets/K', headers={'Authorization': 'Bearer ss_write'})
        assert r.status_code == 200
        body = r.get_json()
        assert body['ok']
        assert body['key'] == 'K'
        assert body['id'] == str(sid)
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
        assert 'machine_delete' in sql
        assert 'audit_secret' in sql
        audit_params = [c.args[1] for c in cur.execute.call_args_list if c.args and 'audit_secret' in str(c.args[0])]
        assert any(('deleted' in p for p in audit_params))
        conn.commit.assert_called()

    def test_delete_read_forbidden(self):
        fo = [{'ok': True}, {'role': 'read'}]
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        with patch.object(db, 'connect', return_value=conn):
            r = self.client.delete(f'/eso/v1/projects/{self.pid}/secrets/K', headers={'Authorization': 'Bearer ss_ro'})
        assert r.status_code == 403

    def test_eso_post_exempt_from_csrf(self):
        """Bearer ESO upsert must not require session CSRF when CSRF_TESTING is on."""
        store.app.config['CSRF_TESTING'] = True
        try:
            sid = uuid4()
            fo = [{'ok': True}, {'role': 'write'}, {'id': sid}, {'label': 'ci:ss_write'}, {'id': sid, 'key': 'K', 'value_enc': crypto.encrypt('v'), 'note': '', 'kind': 'plain', 'expires_at': None, 'created_at': None, 'updated_at': None}]
            conn, cur = _conn()
            cur.fetchone.side_effect = fo
            with patch.object(db, 'connect', return_value=conn):
                r = self.client.post(f'/eso/v1/projects/{self.pid}/secrets', json={'key': 'K', 'value': 'v'}, headers={'Authorization': 'Bearer ss_write'})
            assert r.status_code != 400
            assert r.status_code == 200
        finally:
            store.app.config['CSRF_TESTING'] = False

    def test_upsert_no_auth(self):
        r = self.client.post(f'/eso/v1/projects/{self.pid}/secrets', json={'key': 'K', 'value': 'v'})
        assert r.status_code == 401

    def test_upsert_missing_key_value(self):
        r = self.client.post(f'/eso/v1/projects/{self.pid}/secrets', json={'key': '', 'value': 'v'}, headers={'Authorization': 'Bearer ss_x'})
        assert r.status_code == 400

    def test_upsert_invalid_kind(self):
        r = self.client.post(f'/eso/v1/projects/{self.pid}/secrets', json={'key': 'K', 'value': 'v', 'kind': 'nope'}, headers={'Authorization': 'Bearer ss_x'})
        assert r.status_code == 400
        assert 'kind' in r.get_json()['error']

    def test_management_routes_moved_off_eso_prefix(self):
        rules = {rule.rule for rule in store.app.url_map.iter_rules()}
        assert '/api/v1/manage/teams' in rules
        assert '/api/v1/manage/projects/<project_ref>/members' in rules
        assert '/eso/v1/projects/<project_ref>/secrets/<path:key>' in rules
        assert '/eso/v1/teams' not in rules
        assert '/eso/v1/projects/<project_ref>/members' not in rules

    def test_create_token_with_expiry(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'u@ex.com'
        conn, cur = _conn(fetchone={'w': True})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn), patch.object(settings_svc, 'token_expiry_policy', return_value=(False, 3650)):
            r = c.post(f'/projects/{self.pid}/tokens', data={'name': 'eso', 'role': 'reveal', 'expires_days': '30'}, follow_redirects=False)
        assert r.status_code == 302
        insert = [c for c in cur.execute.call_args_list if c.args and 'INSERT INTO api.machine_tokens' in str(c.args[0])][0]
        assert insert.args[1][5] is not None

    def test_mgmt_add_team_binding_owner_guard(self):
        """A non-owner must not grant team-owner via the management API."""
        uid = str(uuid4())
        tid, mid = uuid4(), uuid4()
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            {'id': tid},     # _resolve_team by uuid
            {'r': 'team-admin'},  # api.team_role -> requestor is only a team-admin
            {'id': str(mid)},  # would-be user lookup (must not be reached)
        ]
        with patch.object(pats, 'resolve', return_value=uid), patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(
                f'/api/v1/manage/teams/{tid}/members',
                json={'email': 'u@x.com', 'role': 'team-owner'},
                headers={'Authorization': 'Bearer pat_owner_guard'},
            )
        assert r.status_code == 403

    def test_pat_list_projects(self):
        uid = str(uuid4())
        conn, cur = _conn(fetchall=[{'id': self.pid, 'name': 'ios-app', 'team_id': uuid4(), 'team_name': 'Mobile'}])
        with patch.object(pats, 'resolve', return_value=uid), patch.object(db, 'as_user', return_value=conn):
            r = self.client.get('/eso/v1/projects?name=ios', headers={'Authorization': 'Bearer pat_testtoken1234567890'})
        assert r.status_code == 200
        items = r.get_json()['items']
        assert items[0]['name'] == 'ios-app'

    def test_pat_get_secret_by_name(self):
        uid = str(uuid4())
        sid = uuid4()
        enc = crypto.encrypt('secret-val')
        conn, cur = _conn()
        # name resolve uses fetchall; then secret row, ACL, reveal via fetchone
        fo = [
            {
                'id': sid,
                'key': 'API_KEY',
                'value_enc': enc,
                'note': '',
                'kind': 'plain',
                'expires_at': None,
                'created_at': None,
                'updated_at': None,
                'last_accessed_at': None,
            },
            {'ok': True},  # can_access_secret
            {'ok': True},  # can_reveal_secret
            None,  # touch_secret_access
            None,
        ]
        cur.fetchone.side_effect = fo
        cur.fetchall.side_effect = [
            [{'id': self.pid}],  # project name resolve
            [],  # secret_meta_rows
        ]
        with patch.object(pats, 'resolve', return_value=uid), patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(
                '/eso/v1/projects/ios-app/secrets/API_KEY',
                headers={'Authorization': 'Bearer pat_testtoken1234567890'},
            )
        assert r.status_code == 200
        assert r.get_json()['value'] == 'secret-val'

    def test_machine_rejects_project_name(self):
        r = self.client.get('/eso/v1/projects/ios-app/secrets/KEY', headers={'Authorization': 'Bearer ss_x'})
        assert r.status_code == 401

    def test_create_token_rejects_huge_expiry(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'u@ex.com'
        conn, cur = _conn(fetchone={'w': True})
        with patch.object(db, 'as_user', return_value=conn), patch.object(settings_svc, 'token_expiry_policy', return_value=(False, 3650)):
            r = c.post(f'/projects/{self.pid}/tokens', data={'name': 'eso', 'role': 'reveal', 'expires_days': str(config.MAX_EXPIRY_DAYS + 1)}, follow_redirects=False)
        assert r.status_code == 302
        inserts = [c for c in cur.execute.call_args_list if c.args and 'INSERT INTO api.machine_tokens' in str(c.args[0])]
        assert inserts == []

    def test_mgmt_create_token_requires_expiry_when_policy_enabled(self):
        from routes.mgmt_api import tokens as mgmt_tokens

        with store.app.test_request_context('/x', method='POST', json={}):
            with patch.object(mgmt_tokens, '_require_pat', return_value=(str(uuid4()), None)), patch.object(mgmt_tokens.settings_svc, 'token_expiry_policy', return_value=(True, 3650)):
                r = mgmt_tokens.mgmt_create_token(str(self.pid))
        resp, status = r
        assert status == 400
        assert resp.get_json()['error'] == 'expires_days is required'

    def test_machine_token_roles_config(self):
        assert 'service-reveal' in config.MACHINE_TOKEN_ROLES
        assert 'service-write' in config.MACHINE_TOKEN_ROLES
        assert 'service-read' in config.MACHINE_TOKEN_ROLES
        assert config.MAX_EXPIRY_DAYS == 3650
        assert config.MAX_CONTENT_LENGTH >= 64 * 1024
        assert store.app.config.get('MAX_CONTENT_LENGTH') == config.MAX_CONTENT_LENGTH

    def test_parse_expires_at_capped(self):
        from secret_svc.secret_ops import _parse_expires_at
        from datetime import datetime, timezone, timedelta
        from werkzeug.datastructures import MultiDict
        far = (datetime.now(timezone.utc) + timedelta(days=config.MAX_EXPIRY_DAYS + 30)).date().isoformat()
        with pytest.raises(ValueError):
            _parse_expires_at(MultiDict({'expires_at': far}))

    def test_import_file_size_cap(self):
        from io import BytesIO
        c = store.app.test_client()
        with c.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'u@ex.com'
        big = b'K=' + b'x' * (config.MAX_IMPORT_BYTES + 10)
        conn, _ = _conn(fetchone={'w': True})
        with patch.object(db, 'as_user', return_value=conn):
            r = c.post(f'/projects/{self.pid}/import', data={'file': (BytesIO(big), 'big.env')}, content_type='multipart/form-data', follow_redirects=False)
        assert r.status_code in (302, 413)
        if r.status_code == 302:
            with c.session_transaction() as s:
                flashes = s.get('_flashes') or []
            assert any(('large' in msg.lower() for _c, msg in flashes))

