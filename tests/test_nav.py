"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

import app as store
from core import config
from core import db
from ui import nav

from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestNav:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        self.tid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'u@ex.com'
            s['team_id'] = str(self.tid)

    def test_select_team(self):
        r = self.client.post('/select-team', data={'team_id': str(self.tid), 'next': '/projects'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/projects' in r.location
        with self.client.session_transaction() as s:
            assert s['team_id'] == str(self.tid)

    def test_select_team_leaves_other_team_project_secrets(self):
        """Switching team from a project secrets URL must not stay on that project."""
        other_pid = uuid4()
        with patch.object(nav, '_project_team_id', return_value=str(uuid4())):
            r = self.client.post('/select-team', data={'team_id': str(self.tid), 'next': f'/projects/{other_pid}?tab=secrets'}, follow_redirects=False)
        assert r.status_code == 302
        assert r.location.endswith('/secrets') or '/secrets' in r.location
        assert str(other_pid) not in r.location

    def test_redirect_after_team_switch_helper(self):
        pid = 'c29f6ab5-6ec7-4484-beb5-8b0741b54713'
        with store.app.test_request_context('/'):
            with patch.object(nav, '_project_team_id', return_value='other'):
                assert nav.redirect_after_team_switch(f'/projects/{pid}?tab=secrets', 'new') == '/secrets'
                assert nav.redirect_after_team_switch(f'/projects/{pid}?tab=settings', 'new') == '/projects'
            assert nav.redirect_after_team_switch('/secrets', 'new') == '/secrets'

    def test_projects_list(self):
        pid = uuid4()
        state = {'n': 0}

        def fetchone():
            state['n'] += 1
            if state['n'] == 1:
                return {'id': self.tid, 'name': 'Ops'}
            return {'n': 1}
        conn, cur = _conn(fetchone=fetchone, fetchall=[{'id': pid, 'name': 'api', 'description': 'prod', 'created_at': 'now', 'secret_count': 3}])
        with patch.object(db, 'as_user', return_value=conn), patch.object(nav, 'ensure_active_team', return_value=str(self.tid)):
            r = self.client.get('/projects')
        assert r.status_code == 200
        assert b'api' in r.data

    def test_secrets_list(self):
        pid = uuid4()
        sid = uuid4()
        state = {'n': 0}

        def fetchone():
            state['n'] += 1
            if state['n'] == 1:
                return {'id': self.tid, 'name': 'Ops'}
            return {'n': 1}
        conn, _ = _conn(fetchone=fetchone, fetchall=[{'id': sid, 'key': 'DB_URL', 'note': '', 'kind': 'plain', 'updated_at': 'now', 'expires_at': None, 'access_mode': 'inherit', 'project_id': pid, 'project_name': 'api'}, {'id': pid, 'name': 'api'}])
        with patch.object(db, 'as_user', return_value=conn), patch.object(nav, 'ensure_active_team', return_value=str(self.tid)):
            r = self.client.get('/secrets')
        assert r.status_code == 200
        assert b'DB_URL' in r.data

    def test_machines_list(self):
        conn, _ = _conn(fetchone={'id': self.tid, 'name': 'Ops'}, fetchall=[{'id': uuid4(), 'name': 'eso', 'token_prefix': 'ss_abc', 'created_at': 'now', 'project_id': uuid4(), 'project_name': 'api'}])
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get('/machines')
        assert r.status_code == 200
        assert b'eso' in r.data
        assert b'Machine accounts' in r.data

    def test_trash_empty_no_team(self):
        conn, _ = _conn(fetchall=[])
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get('/trash')
        assert r.status_code == 200
        assert b'Trash' in r.data
        assert b'Select a team' in r.data

    def test_trash_empty_with_team(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={'id': tid, 'name': 'Ops'}, fetchall=[])
        with self.client.session_transaction() as s:
            s['team_id'] = str(tid)
        with patch.object(db, 'as_user', return_value=conn), patch.object(
            nav, 'ensure_active_team', return_value=str(tid)
        ):
            r = self.client.get('/trash')
        assert r.status_code == 200
        assert b'Nothing in trash' in r.data

    def test_trash_with_items(self):
        tid = uuid4()
        pid = uuid4()
        sid = uuid4()
        conn, _ = _conn(
            fetchone={'id': tid, 'name': 'Ops'},
            fetchall=[
                {
                    'id': sid,
                    'key': 'DB_URL',
                    'note': 'old',
                    'deleted_at': '2026-01-01',
                    'project_id': pid,
                    'project_name': 'prod',
                    'can_write': True,
                }
            ],
        )
        with self.client.session_transaction() as s:
            s['team_id'] = str(tid)
        with patch.object(db, 'as_user', return_value=conn), patch.object(
            nav, 'ensure_active_team', return_value=str(tid)
        ):
            r = self.client.get('/trash')
        assert r.status_code == 200
        assert b'DB_URL' in r.data
        assert b'Restore' in r.data
        assert b'Delete forever' in r.data
        assert 'Delete forever - this cannot be undone'.encode() in r.data
        assert b'&& confirm(' in r.data

    def test_restore_secret(self):
        conn, cur = _conn()
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/trash/secrets/{uuid4()}/restore', follow_redirects=False)
        assert r.status_code == 302
        assert '/trash' in r.location

    def test_restore_secret_denied(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/trash/secrets/{uuid4()}/restore', follow_redirects=False)
        assert r.status_code == 302
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('could not' in msg.lower() or 'permission' in msg.lower() for _c, msg in flashes))

    def test_purge_secret(self):
        conn, _ = _conn()
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/trash/secrets/{uuid4()}/purge', follow_redirects=False)
        assert r.status_code == 302
        assert '/trash' in r.location

