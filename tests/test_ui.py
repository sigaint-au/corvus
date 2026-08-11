"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

import app as store
import authz
import config
import db

from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestUIShell:

    def test_login_is_auth_layout(self):
        r = store.app.test_client().get('/login')
        assert b'class="auth"' in r.data
        assert b'auth-card' in r.data
        assert b'class="sidebar"' not in r.data
        assert b'Sigaint' in r.data
        assert b'Secret Server' in r.data
        assert b'light-dark(#000000, #f5f5f5)' in r.data

    def test_app_has_sidebar(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'x@y.z'
        conn, _ = _conn(fetchall=[])
        with patch.object(db, 'as_user', return_value=conn), patch.object(authz, 'is_global_admin', return_value=False):
            r = c.get('/teams')
        assert b'class="app"' in r.data
        assert b'sidebar' in r.data
        assert b'x@y.z' in r.data
        assert b'Log out' in r.data
        assert b'Projects' in r.data
        assert b'Secrets' in r.data
        assert b'Machine accounts' in r.data
        assert b'Trash' in r.data
        assert b'side-team-select' in r.data
        assert b'Active team' not in r.data
        assert b'Server settings' not in r.data

    def test_global_admin_sees_settings_nav(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        conn, _ = _conn(fetchall=[])
        with patch.object(db, 'as_user', return_value=conn), patch.object(authz, 'is_global_admin', return_value=True):
            r = c.get('/teams')
        assert b'Server settings' in r.data
        assert b'Global admin' in r.data

    def test_app_has_skip_link_and_responsive_table_css(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'x@y.z'
        conn, _ = _conn(fetchall=[])
        with patch.object(db, 'as_user', return_value=conn), patch.object(authz, 'is_global_admin', return_value=False):
            r = c.get('/teams')
        # Accessibility: a keyboard-first skip link must render on app pages.
        assert b'class="skip-link"' in r.data
        assert b'Skip to content' in r.data
        # Responsive tables: the oat .table scroll container must exist.
        assert b'.table {' in r.data
        assert b'overflow-x: auto' in r.data

    def test_machines_template_shows_last_used(self):
        from flask import render_template
        team = {'id': str(uuid4()), 'name': 'Acme'}
        token = {
            'name': 'ci', 'id': str(uuid4()), 'token_prefix': 'ss_abc123', 'role': 'reveal',
            'created_at': '2026-01-01T00:00:00', 'expires_at': None, 'last_used_at': None,
        }
        with store.app.test_request_context('/machines'):
            html = render_template('machines.html', team=team, tokens=[token])
        assert 'never' in html                 # unused token reports "never"
        assert 'class="table"' in html    # machine table is scrollable/responsive

    def test_project_tabs_use_nav_links_not_tablist_role(self):
        # Server-side page tabs are plain navigation links (no fake tablist),
        # so screen readers announce them as links, not broken tabs.
        from flask import render_template
        project = {
            'id': str(uuid4()), 'name': 'App', 'team_id': str(uuid4()),
            'team_name': 'Acme', 'description': 'demo',
        }
        with store.app.test_request_context('/projects/p?tab=secrets'):
            html = render_template('project.html', project=project, active_tab='secrets')
        assert 'role="tablist"' not in html
        assert 'role="tab"' not in html
        assert 'class="tabs"' in html
        assert 'tab active' in html

