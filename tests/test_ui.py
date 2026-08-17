"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

import app as store
from auth import authz
from core import config
from core import db

from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestUIShell:

    def test_login_is_auth_layout(self):
        conn, _ = _conn(fetchall=[])
        with patch.object(db, 'connect_admin', return_value=conn):
            r = store.app.test_client().get('/login')
        assert b'class="auth"' in r.data
        assert b'auth-card' in r.data
        assert b'class="sidebar"' not in r.data
        assert b'Sigaint' in r.data
        assert b'Secret Server' in r.data
        assert b'static/app.css' in r.data

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
        assert b'Shared secrets' in r.data
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

    def test_binding_role_options_have_tooltips(self):
        # Role dropdowns must explain what each role grants (mention in the
        # panel hint "Hover a role name for its permissions").
        from flask import render_template
        tid = str(uuid4())
        desc = {'team-owner': 'Full control of a team and its projects/secrets'}
        with store.app.test_request_context(f'/teams/{tid}'):
            panel = render_template(
                'partials/access_bindings_panel.html',
                role_dropdown=[('team-owner', 'Owner')], role_descriptions=desc,
                access_bindings=[], can_edit_access=True,
                subject_kinds=['User', 'Group', 'ServiceAccount'], access_groups=[],
                create_url='/x', panel_title='Access', empty_message='',
                full_bindings_url='', form_id_prefix='t')
        assert 'title="Full control of a team and its projects/secrets"' in panel
        # Secret Access tab reuses the panel: secret-* role options carry
        # role-description tooltips
        sid = str(uuid4())
        with store.app.test_request_context(f'/projects/{tid}/secrets/{sid}'):
            sv = render_template(
                'secret_view.html', project_id=tid, secret_id=sid, secret_key='K',
                kind='plain', project_name='P', active_tab='access', can_admin=True,
                can_write=False, can_reveal=True, access_blocked=False, is_version=False,
                value='', access_mode='inherit', access_modes=['inherit', 'restricted'],
                access_mode_labels={}, team_groups=[],
                role_dropdown=[('secret-reveal', 'Reveal')],
                role_descriptions={'secret-reveal': 'Read metadata and reveal the secret value'},
                secret_bindings=[], effective_access=[], custom_meta=[], note='',
                expires_at='', created_at='', updated_at='', last_accessed_at=None,
                last_accessed_by_email='', clipboard_clear_seconds=30)
        assert 'title="Read metadata and reveal the secret value"' in sv
        assert 'name="role_name"' in sv

    def test_rbac_bindings_breadcrumb_shows_scope(self):
        # RBAC bindings accessed from the sidebar (no back_team_id / no active
        # team) must still show context about the team/project being bound.
        from flask import render_template
        tid, pid = str(uuid4()), str(uuid4())
        base = dict(scope_kinds=['cluster', 'team', 'project', 'secret'],
                    teams=[{'id': tid, 'name': 'Acme'}], projects=[], secrets=[],
                    groups=[], bindings=[], all_roles=[], dropdown=[],
                    role_descriptions={}, can_edit=True,
                    subject_kinds=['User', 'Group', 'ServiceAccount'])
        with store.app.test_request_context('/rbac/bindings'):
            # Team scope via sidebar default: no explicit back link
            t = render_template('rbac_bindings.html', **base, scope_kind='team',
                                scope_id=tid, scope_label='Acme',
                                back_team_id=None, back_team_name=None)
            assert 'Teams' in t and 'Acme' in t and 'Role bindings' in t
            # Project scope: team + project names in the crumb
            p = render_template('rbac_bindings.html', **base, scope_kind='project',
                                scope_id=pid, scope_label='App',
                                back_team_id=tid, back_team_name='Acme')
            assert 'Acme' in p and 'App' in p and 'Role bindings' in p

    def test_empty_binding_table_offers_add_binding(self):
        # An empty bindings table must not dead-end: give a direct route to the
        # add-binding form, which may be below the fold on long pages.
        from flask import render_template
        tid = str(uuid4())
        base = dict(scope_kinds=['cluster', 'team', 'project', 'secret'],
                    teams=[{'id': tid, 'name': 'Acme'}], projects=[], secrets=[],
                    groups=[], all_roles=[], dropdown=[], role_descriptions={},
                    subject_kinds=['User', 'Group', 'ServiceAccount'],
                    scope_kind='team', scope_id=tid, scope_label='Acme',
                    back_team_id=tid, back_team_name='Acme')
        with store.app.test_request_context('/rbac/bindings'):
            html = render_template('rbac_bindings.html', **base, bindings=[], can_edit=True)
        assert 'href="#add-binding">+ Add binding' in html
        assert 'Add the first binding' in html
        assert '<section id="add-binding">' in html
        with store.app.test_request_context('/rbac/bindings'):
            ro = render_template('rbac_bindings.html', **base, bindings=[], can_edit=False)
        assert 'Add the first binding' not in ro

    def test_single_role_bindings_nav_item(self):
        # The team-scoped 'Role bindings' entry (Organisation group) is hidden
        # for global admins, who get the Administration entry instead — exactly
        # one visible item either way.
        tid = str(uuid4())
        team = {'id': tid, 'name': 'Acme', 'classification_enabled': None,
                'classification_text': '', 'classification_color': '',
                'classification_fg': ''}
        conn, cur = _conn()
        last_sql = {'s': ''}

        def execute(sql, params=None):
            last_sql['s'] = ' '.join(str(sql).lower().split())

        def fetchone():
            return {'n': 0}

        def fetchall():
            s = last_sql['s']
            if 'from api.teams' in s and 'join' not in s:
                return [team]
            return []

        cur.execute.side_effect = execute
        cur.fetchone.side_effect = fetchone
        cur.fetchall.side_effect = fetchall
        # global admin with an active team → administration item only
        c = store.app.test_client()
        with c.session_transaction() as s:
            s['user_id'] = str(uuid4()); s['email'] = 'admin@x.y'; s['team_id'] = tid
            s['is_global_admin'] = True
        with patch.object(db, 'as_user', return_value=conn), patch.object(authz, 'is_global_admin', return_value=True):
            r = c.get('/teams')
        assert r.status_code == 200
        assert r.data.count(b'>Role bindings</a>') == 1
        # regular member with an active team → organisation item only
        c2 = store.app.test_client()
        with c2.session_transaction() as s:
            s['user_id'] = str(uuid4()); s['email'] = 'u@x.y'; s['team_id'] = tid
            s['is_global_admin'] = False
        with patch.object(db, 'as_user', return_value=conn), patch.object(authz, 'is_global_admin', return_value=False):
            r2 = c2.get('/teams')
        assert r2.status_code == 200
        assert r2.data.count(b'>Role bindings</a>') == 1

    def test_non_admin_role_bindings_keeps_organisation_open(self):
        # Members reach Role bindings from Organisation. That endpoint used to
        # be classified as Administration, so the Organisation <details> closed
        # and nothing replaced it (Administration is hidden for non-admins).
        tid = str(uuid4())
        team = {'id': tid, 'name': 'Acme', 'classification_enabled': None,
                'classification_text': '', 'classification_color': '',
                'classification_fg': ''}
        conn, cur = _conn()
        last_sql = {'s': ''}

        def execute(sql, params=None):
            last_sql['s'] = ' '.join(str(sql).lower().split())

        def fetchone():
            s = last_sql['s']
            if 'can_manage_rbac' in s:
                return {'ok': True}
            if 'count(*)' in s:
                return {'n': 0}
            return {'id': tid, 'name': 'Acme'}

        def fetchall():
            s = last_sql['s']
            if 'from api.teams' in s:
                return [team]
            return []

        cur.execute.side_effect = execute
        cur.fetchone.side_effect = fetchone
        cur.fetchall.side_effect = fetchall
        c = store.app.test_client()
        with c.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'u@x.y'
            s['team_id'] = tid
            s['is_global_admin'] = False
        with patch.object(db, 'as_user', return_value=conn), patch.object(
            authz, 'is_global_admin', return_value=False
        ):
            r = c.get(f'/rbac/bindings?scope=team&scope_id={tid}')
        assert r.status_code == 200
        assert b'data-side-group="account" open' in r.data
        assert b'data-side-group="administration"' not in r.data
        # Same default as other Organisation pages (e.g. Teams).
        teams = store.app.test_client()
        with teams.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'u@x.y'
            s['team_id'] = tid
            s['is_global_admin'] = False
        with patch.object(db, 'as_user', return_value=conn), patch.object(
            authz, 'is_global_admin', return_value=False
        ):
            r_teams = teams.get('/teams')
        assert r_teams.status_code == 200
        assert b'data-side-group="account" open' in r_teams.data

    def test_global_admin_role_bindings_keeps_administration_open(self):
        tid = str(uuid4())
        team = {'id': tid, 'name': 'Acme', 'classification_enabled': None,
                'classification_text': '', 'classification_color': '',
                'classification_fg': ''}
        conn, cur = _conn()
        last_sql = {'s': ''}

        def execute(sql, params=None):
            last_sql['s'] = ' '.join(str(sql).lower().split())

        def fetchone():
            s = last_sql['s']
            if 'can_manage_rbac' in s:
                return {'ok': True}
            if 'count(*)' in s:
                return {'n': 0}
            return {'id': tid, 'name': 'Acme'}

        def fetchall():
            s = last_sql['s']
            if 'from api.teams' in s:
                return [team]
            return []

        cur.execute.side_effect = execute
        cur.fetchone.side_effect = fetchone
        cur.fetchall.side_effect = fetchall
        c = store.app.test_client()
        with c.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'admin@x.y'
            s['team_id'] = tid
            s['is_global_admin'] = True
        with patch.object(db, 'as_user', return_value=conn), patch.object(
            authz, 'is_global_admin', return_value=True
        ):
            r = c.get('/rbac/bindings?scope=team')
        assert r.status_code == 200
        assert b'data-side-group="administration" open' in r.data
        assert b'data-side-group="account" open' not in r.data

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
        # Responsive tables: app.css defines the oat .table scroll container.
        css = store.app.test_client().get('/static/app.css')
        assert css.status_code == 200
        assert b'.table {' in css.data
        assert b'overflow-x: auto' in css.data

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
        # Server-side page navigation is plain links (no fake tablist), so
        # screen readers announce them as links, not broken tabs. Scope the
        # check to the actual <nav class="page-subnav"> markup (not the
        # shared <style> block, whose `.role-mode-tabs [role=tablist]` selector
        # legitimately contains `role=` text).
        from flask import render_template
        project = {
            'id': str(uuid4()), 'name': 'App', 'team_id': str(uuid4()),
            'team_name': 'Acme', 'description': 'demo',
        }
        with store.app.test_request_context('/projects/p?tab=secrets'):
            html = render_template('project.html', project=project, active_tab='secrets')
        i = html.find('<nav class="page-subnav"')
        j = html.find('</nav>', i)
        tabs = html[i:j] if i != -1 and j != -1 else ''
        assert 'role="tablist"' not in tabs
        assert 'role="tab"' not in tabs
        assert 'page-subnav-link' in tabs
        assert 'page-subnav-link active' in tabs

