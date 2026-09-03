"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import app as store
import crypto
from auth import authz
from core import db, settings_svc
from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestSecrets:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        self.pid = uuid4()
        self._settings_patch = patch.object(settings_svc, 'get_settings', return_value={})
        self._settings_patch.start()
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'u@ex.com'
            s['is_global_admin'] = False

    def teardown_method(self, method=None):
        self._settings_patch.stop()

    # Role-catalog rows consumed by the first roles.helper call per request
    # (cached in flask.g afterwards). Mirrors the baseline seed precedences.
    _CATALOG_ROWS = [
        {'name': 'team-owner', 'description': 'Owner', 'scopes': ['team'], 'precedence': 4, 'built_in': True},
        {'name': 'team-admin', 'description': 'Admin', 'scopes': ['team'], 'precedence': 3, 'built_in': True},
        {'name': 'team-member', 'description': 'Member', 'scopes': ['team'], 'precedence': 2, 'built_in': True},
        {'name': 'team-viewer', 'description': 'Viewer', 'scopes': ['team'], 'precedence': 1, 'built_in': True},
        {'name': 'project-admin', 'description': 'Admin', 'scopes': ['project'], 'precedence': 0, 'built_in': True},
        {'name': 'project-read', 'description': 'Read', 'scopes': ['project'], 'precedence': 0, 'built_in': True},
        {'name': 'secret-reveal', 'description': 'Reveal', 'scopes': ['folder', 'secret'], 'precedence': 0, 'built_in': True},
    ]

    def _project_conn(self, tab='secrets', can_write=True, can_admin=None, team_role='team-owner', secrets=None, tokens=None, audit_log=None, access_requests=None, total=None, pending_count=0):
        """as_user used by project_detail (tab-scoped queries)."""
        project = {'id': self.pid, 'name': 'prod', 'team_name': 'Ops', 'team_id': uuid4()}
        if can_admin is None:
            can_admin = team_role in ('team-owner', 'team-admin')
        rows = secrets or [] if tab == 'secrets' else audit_log or [] if tab == 'audit' else tokens or []
        if total is None:
            total = len(rows)
        fo = [project, {'w': can_write}, {'a': can_admin}, {'r': team_role}, {'g': False}]
        if tab in ('secrets', 'audit'):
            fo.append({'n': total})
        if tab == 'secrets':
            fo.append({'a': can_admin})
        fo.append({'n': pending_count})
        if tab == 'settings':
            fa = [[]]
        elif tab == 'secrets':
            # _load_secrets_page: secrets page + pins + grants; then detail.py: folders + expiry + rotation
            fa = [rows, [], [], [], [], []] if rows else [rows, [], [], [], []]
            # rows truthy → pins + grants executed; rows falsy → pins/grants skipped, one fewer fetchall
        elif tab in ('access', 'requests'):
            fa = [access_requests or []]
        else:
            fa = [rows] if tab in ('audit', 'tokens') else []
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        cur.fetchall.side_effect = [self._CATALOG_ROWS] + (fa if fa else [[]])
        return conn

    def test_project_detail(self):
        with patch.object(db, 'as_user', return_value=self._project_conn()):
            r = self.client.get(f'/projects/{self.pid}')
        assert r.status_code == 200
        assert b'prod' in r.data
        assert b'Secrets' in r.data
        assert b'>Access<' in r.data
        assert b'Activity' in r.data

    def test_project_detail_shows_search_when_only_folders(self):
        folder = {
            'id': uuid4(), 'parent_id': None, 'path': 'ops',
            'access_mode': 'inherit', 'n_secrets': 0,
        }
        project = {'id': self.pid, 'name': 'prod', 'team_name': 'Ops', 'team_id': uuid4()}
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            project, {'w': True}, {'a': False}, {'r': 'team-member'}, {'g': False},
            {'n': 0}, {'a': False}, {'n': 0},
        ]
        cur.fetchall.side_effect = [self._CATALOG_ROWS, [], [folder], [], []]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}?tab=secrets')
        assert r.status_code == 200
        assert b'aria-label="Search secrets"' in r.data
        assert b'ops' in r.data

    def test_project_detail_htmx_returns_panel(self):
        with patch.object(db, 'as_user', return_value=self._project_conn()):
            r = self.client.get(
                f'/projects/{self.pid}?tab=secrets',
                headers={'HX-Request': 'true'},
            )
        assert r.status_code == 200
        assert b'project-panel' not in r.data
        assert b'Projects' not in r.data
        assert b'Add secret' in r.data

    def test_viewer_can_request_reveal_without_reveal_acl(self):
        sid = uuid4()
        secret = {
            'id': sid, 'key': 'API_KEY', 'note': '', 'kind': 'plain',
            'expires_at': None, 'updated_at': '2026-01-01',
            'rotation_next_at': None, 'rotation_owner': None, 'rotated_at': None,
            'is_pinned': False, 'due': None, 'rotation_due': None,
            'access_mode': 'inherit', 'access_restricted': False,
            'reveal_access': 'locked', 'needs_approval': False,
            'can_reveal': False,
        }
        with patch.object(
            db, 'as_user',
            return_value=self._project_conn(
                can_write=False, can_admin=False, team_role='team-viewer', secrets=[secret]
            ),
        ):
            r = self.client.get(f'/projects/{self.pid}?tab=secrets')
        assert r.status_code == 200
        assert f'/projects/{self.pid}/secrets/{sid}/reveal'.encode() not in r.data
        assert b'data-open-dialog=' in r.data
        assert b'Request access' in r.data

    def test_list_row_without_reveal_acl_is_requestable(self):
        from secret_svc.secret_ops import _set_row_reveal_access
        r = {'can_reveal': False, 'needs_approval': False}
        _set_row_reveal_access(r, is_admin=False, grant=None)
        assert r['reveal_access'] == 'locked'
        r = {'can_reveal': False, 'needs_approval': False}
        _set_row_reveal_access(
            r, is_admin=False,
            grant={'status': 'approved', 'approved_until': '2099-01-01'},
        )
        assert r['reveal_access'] == 'granted'
        r = {'can_reveal': False, 'needs_approval': False}
        _set_row_reveal_access(r, is_admin=False, grant=None, allow_requests=False)
        assert r['reveal_access'] == 'denied'
        r = {'can_reveal': False, 'needs_approval': False}
        _set_row_reveal_access(r, is_admin=True, grant=None, allow_requests=False)
        assert r['reveal_access'] == 'allowed'

    def test_project_access_tab(self):
        reqs = [{'id': uuid4(), 'secret_id': uuid4(), 'secret_key': 'API_KEY', 'user_id': self.uid, 'email': 'u@ex.com', 'name': 'User', 'status': 'pending', 'reason': 'debug prod', 'created_at': '2026-01-01', 'resolved_at': None, 'approved_until': None, 'resolver_email': ''}]
        with patch.object(db, 'as_user', return_value=self._project_conn(tab='requests', access_requests=reqs, pending_count=1)):
            r = self.client.get(f'/projects/{self.pid}?tab=requests')
        assert r.status_code == 200
        assert b'API_KEY' in r.data
        assert b'pending' in r.data
        assert b'debug prod' in r.data
        assert b'Approve' in r.data
        assert b'Deny' in r.data
        assert b'>Access<' in r.data

    def test_project_audit_tab(self):
        audit_rows = [{'id': uuid4(), 'secret_id': uuid4(), 'secret_key': 'API_KEY', 'action': 'revealed', 'created_at': '2026-01-01', 'actor_email': 'u@ex.com', 'user_id': self.uid, 'actor_name': 'User'}]
        with patch.object(db, 'as_user', return_value=self._project_conn(tab='audit', audit_log=audit_rows)):
            r = self.client.get(f'/projects/{self.pid}?tab=audit')
        assert r.status_code == 200
        assert b'API_KEY' in r.data
        assert b'revealed' in r.data
        assert b'u@ex.com' in r.data

    def test_project_audit_tab_ip_and_hide_reveals_filters(self):
        audit_rows = [{'id': uuid4(), 'secret_id': uuid4(), 'secret_key': 'API_KEY', 'action': 'created', 'created_at': '2026-01-01', 'actor_email': 'u@ex.com', 'user_id': self.uid, 'actor_name': 'User', 'ip_address': '203.0.113.7', 'user_agent': 'UA'}]
        with patch.object(db, 'as_user', return_value=self._project_conn(tab='audit', audit_log=audit_rows)):
            r = self.client.get(f'/projects/{self.pid}?tab=audit&ip=203.0.113.7&hide_reveals=1')
        assert r.status_code == 200
        assert b'value="203.0.113.7"' in r.data
        assert b'checked' in r.data
        assert b'Hide reveals' in r.data
        assert b'Apply' in r.data

    def test_project_audit_tab_htmx_returns_panel(self):
        audit_rows = [{'id': uuid4(), 'secret_id': uuid4(), 'secret_key': 'API_KEY', 'action': 'created', 'created_at': '2026-01-01', 'actor_email': 'u@ex.com', 'user_id': self.uid, 'actor_name': 'User'}]
        with patch.object(db, 'as_user', return_value=self._project_conn(tab='audit', audit_log=audit_rows)):
            r = self.client.get(
                f'/projects/{self.pid}?tab=audit',
                headers={'HX-Request': 'true'},
            )
        assert r.status_code == 200
        assert b'id="project-panel"' not in r.data
        assert b'hx-get' in r.data

    def test_project_404(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{uuid4()}')
        assert r.status_code == 404

    def test_delete_project_route_owner_ok(self):
        tid = uuid4()
        conn, cur = _conn(fetchone={'team_id': tid, 'r': 'team-owner'})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/delete', follow_redirects=False)
        assert r.status_code == 302
        assert str(tid) in r.location
        conn.commit.assert_called()

    def test_delete_project_route_viewer_denied(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={'team_id': tid, 'r': 'team-viewer'})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/delete', follow_redirects=False)
        assert r.status_code == 302
        assert str(self.pid) in r.location
        conn.commit.assert_not_called()

    def test_project_settings_tab_shows_members_and_delete_for_owner(self):
        with patch.object(db, 'as_user', return_value=self._project_conn(tab='settings', team_role='team-owner')):
            r = self.client.get(f'/projects/{self.pid}?tab=settings')
        assert r.status_code == 200
        assert b'Settings' in r.data
        assert b'Danger zone' in r.data
        assert b'Delete project' in r.data
        assert b'Settings' in r.data
        assert b'Project settings' not in r.data

    def test_project_settings_hidden_for_writer_without_admin(self):
        """Project write without admin cannot manage members; Settings tab hidden."""
        with patch.object(db, 'as_user', return_value=self._project_conn(team_role='team-member', can_write=True, can_admin=False)):
            r = self.client.get(f'/projects/{self.pid}')
        assert r.status_code == 200
        assert b'?tab=settings' not in r.data
        assert b'Delete project' not in r.data

    def test_project_settings_tab_hidden_for_viewer(self):
        with patch.object(db, 'as_user', return_value=self._project_conn(team_role='team-viewer', can_write=False, can_admin=False)):
            r = self.client.get(f'/projects/{self.pid}')
        assert r.status_code == 200
        assert b'?tab=settings' not in r.data
        assert b'Delete project' not in r.data

    def test_project_admin_settings_members_without_delete(self):
        """Project admin can manage members; team member cannot delete project."""
        with patch.object(db, 'as_user', return_value=self._project_conn(tab='settings', team_role='team-member', can_write=True, can_admin=True)):
            r = self.client.get(f'/projects/{self.pid}?tab=settings')
        assert r.status_code == 200
        assert b'Settings' in r.data
        assert b'Delete project' not in r.data

    def test_project_secrets_tab_no_danger_zone(self):
        with patch.object(db, 'as_user', return_value=self._project_conn(team_role='team-owner')):
            r = self.client.get(f'/projects/{self.pid}?tab=secrets')
        assert r.status_code == 200
        assert b'Settings' in r.data
        assert b'Danger zone' not in r.data

    def test_create_secret(self):
        sid = uuid4()
        conn, cur = _conn()
        cur.fetchone.side_effect = [None, {'id': sid}]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/secrets', data={'key': 'API_KEY', 'value': 'sekrit', 'note': ''}, follow_redirects=False)
        assert r.status_code == 302
        assert str(self.pid) in r.location
        assert conn.cursor.called

    def test_create_secret_missing_key(self):
        r = self.client.post(f'/projects/{self.pid}/secrets', data={'key': '', 'value': 'x'}, follow_redirects=False)
        assert r.status_code == 302

    def test_create_secret_rejects_invalid_path_before_db(self):
        with patch.object(db, 'as_user') as as_user:
            r = self.client.post(
                f'/projects/{self.pid}/secrets',
                data={'key': 'folder//secret', 'value': 'x'},
                follow_redirects=False,
            )
        assert r.status_code == 302
        as_user.assert_not_called()

    def test_delete_secret(self):
        sid = uuid4()
        conn, cur = _conn(fetchone={'id': sid, 'key': 'API_KEY'})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/secrets/{sid}/delete', follow_redirects=False)
        assert r.status_code == 302
        conn.commit.assert_called()

    def test_delete_secret_read_only_no_op(self):
        """Read (SELECT) ok but write (UPDATE) blocked — must flash, not silent success."""
        sid = uuid4()
        conn, cur = _conn(fetchone={'id': sid, 'key': 'API_KEY'})
        cur.rowcount = 0
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/secrets/{sid}/delete', follow_redirects=False)
        assert r.status_code == 302
        conn.commit.assert_not_called()
        conn.rollback.assert_called()
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('permission' in msg.lower() for _cat, msg in flashes))

    def test_reveal_secret(self):
        sid = uuid4()
        enc = crypto.encrypt('super-secret')
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'id': sid, 'key': 'API_KEY', 'expires_at': None}, {'a': True, 'r': True}, {'value_enc': enc, 'crypto_provider': 'master'}, {'w': True}]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/reveal', headers={'HX-Request': 'true'})
        assert r.status_code == 200
        assert b'super-secret' in r.data
        assert b'Save' in r.data
        assert b'/value' in r.data
        assert b'Copy' in r.data
        assert b'Open full view' in r.data
        assert b'>Hide</button>' in r.data
        assert b'/hide' in r.data
        assert b'<button type="button"' in r.data
        # OOB toggle must be an oat menu item (button, not anchor) that closes
        # the kebab popover after clicking, styled like the other menu items.
        assert b'role="menuitem"' in r.data
        assert b'popovertarget="secret-menu-' + str(sid).encode() + b'"' in r.data
        assert b'class="reveal-toggle ghost"' in r.data
        assert b'name="expires_at"' not in r.data

    def test_reveal_secret_owner_without_reveal_acl(self):
        """Team-owner / project admin may reveal even without secret-reveal ACL."""
        sid = uuid4()
        enc = crypto.encrypt('owner-secret')
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            {'id': sid, 'key': 'API_KEY', 'expires_at': None},
            {'a': True, 'r': False},
            {'value_enc': enc, 'crypto_provider': 'master'},
            {'w': True},
        ]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(
                f'/projects/{self.pid}/secrets/{sid}/reveal',
                headers={'HX-Request': 'true'},
            )
        assert r.status_code == 200
        assert b'owner-secret' in r.data
        assert b'Reveal access required' not in r.data

    def test_reveal_secret_denied_when_team_disables_requests(self):
        sid = uuid4()
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            {'id': sid, 'key': 'API_KEY', 'expires_at': None},
            {'a': False, 'r': False},
            None,
            {'r': False},
            {'ok': False},
        ]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(
                f'/projects/{self.pid}/secrets/{sid}/reveal',
                headers={'HX-Request': 'true'},
            )
        assert r.status_code == 200
        assert b'Reveal access required' in r.data
        assert b'secret-reveal' in r.data
        assert b'Request access' not in r.data

    def test_reveal_secret_denied_shows_permission_message(self):
        sid = uuid4()
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            {'id': sid, 'key': 'API_KEY', 'expires_at': None},
            {'a': False, 'r': False},
            None,
            {'r': False},
            {'ok': True},
        ]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(
                f'/projects/{self.pid}/secrets/{sid}/reveal',
                headers={'HX-Request': 'true'},
            )
        assert r.status_code == 200
        assert b'Request access' in r.data
        assert b'The action failed' not in r.data

    def test_reveal_secret_requires_access_request(self):
        sid = uuid4()
        enc = crypto.encrypt('super-secret')
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'id': sid, 'key': 'API_KEY', 'value_enc': enc, 'expires_at': None}, {'a': False, 'r': False}, None, {'r': True}]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/reveal', headers={'HX-Request': 'true'})
        assert r.status_code == 200
        assert b'super-secret' not in r.data
        assert b'Approval required' in r.data
        assert b'Request access' in r.data
        assert b'<dialog' in r.data

    def test_reveal_open_secret_no_approval(self):
        """Project default off + no override → instant reveal for readers."""
        sid = uuid4()
        enc = crypto.encrypt('open-secret')
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'id': sid, 'key': 'FEATURE_FLAG', 'expires_at': None}, {'a': False, 'r': True}, None, {'value_enc': enc, 'crypto_provider': 'master'}, {'w': False}]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/reveal', headers={'HX-Request': 'true'})
        assert r.status_code == 200
        assert b'open-secret' in r.data

    def test_reveal_secret_with_approved_grant(self):
        sid = uuid4()
        enc = crypto.encrypt('granted-secret')
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            {'id': sid, 'key': 'API_KEY', 'expires_at': None},
            {'a': False, 'r': True},
            {'status': 'approved', 'approved_until': '2026-09-01T00:00:00Z', 'id': uuid4()},
            {'value_enc': enc, 'crypto_provider': 'master'},
            {'w': False},
        ]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/reveal', headers={'HX-Request': 'true'})
        assert r.status_code == 200
        assert b'granted-secret' in r.data

    def test_reveal_access_state_keeps_grant_row_when_allowed(self):
        """Allowed via can_reveal_secret still surfaces an approved grant's expiry."""
        from routes.secrets.helpers import _reveal_access_state
        cur = MagicMock()
        cur.fetchone.side_effect = [
            {'r': True, 'a': False},
            {'status': 'approved', 'approved_until': '2026-09-01T00:00:00Z'},
        ]
        state, row = _reveal_access_state(cur, str(uuid4()), str(uuid4()), str(uuid4()))
        assert state == 'allowed'
        assert row is not None and row['status'] == 'approved'

    def test_reveal_access_state_admin_skips_grant_lookup(self):
        cur = MagicMock()
        cur.fetchone.side_effect = [{'r': False, 'a': True}]
        from routes.secrets.helpers import _reveal_access_state
        state, row = _reveal_access_state(cur, str(uuid4()), str(uuid4()), str(uuid4()))
        assert state == 'allowed'
        assert row is None

    def test_request_secret_access(self):
        sid = uuid4()
        conn, cur = _conn()
        created = {'id': uuid4(), 'status': 'pending', 'created_at': '2026-01-01', 'reason': 'need it'}
        cur.fetchone.side_effect = [{'id': sid, 'key': 'API_KEY'}, {'a': False, 'r': False}, None, {'r': False}, {'ok': True}, created]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/secrets/{sid}/access-request', data={'reason': 'need it', 'dialog': '1'}, headers={'HX-Request': 'true'})
        assert r.status_code == 200
        assert b'Request submitted' in r.data
        assert b'Waiting' in r.data
        conn.commit.assert_called()
        sql = ' '.join(str(c.args[0]) for c in cur.execute.call_args_list)
        assert 'secret_access_requests' in sql
        audit_args = ' '.join(str(c.args) for c in cur.execute.call_args_list if c.args)
        assert 'access_requested' in audit_args

    def test_request_secret_access_blocked_when_team_disables(self):
        sid = uuid4()
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            {'id': sid, 'key': 'API_KEY'}, {'a': False, 'r': False}, None, {'r': False}, {'ok': False},
        ]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(
                f'/projects/{self.pid}/secrets/{sid}/access-request',
                data={'reason': 'need it'},
                follow_redirects=False,
            )
        assert r.status_code == 302
        conn.commit.assert_not_called()
        sql = ' '.join(str(c.args[0]) for c in cur.execute.call_args_list)
        assert 'INSERT INTO api.secret_access_requests' not in sql

    def test_approve_secret_access(self):
        rid, sid = (uuid4(), uuid4())
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'a': True}, {'id': rid, 'secret_id': sid, 'user_id': self.uid, 'status': 'pending', 'secret_key': 'API_KEY'}]
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/access-requests/{rid}/approve', data={'minutes': '15'}, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=requests' in r.location
        conn.commit.assert_called()
        all_args = ' '.join(str(c.args) for c in cur.execute.call_args_list if c.args)
        assert 'approved' in all_args
        assert 'access_approved' in all_args

    def test_deny_secret_access(self):
        rid, sid = (uuid4(), uuid4())
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'a': True}, {'id': rid, 'secret_id': sid, 'status': 'pending', 'secret_key': 'API_KEY'}]
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/access-requests/{rid}/deny', follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=requests' in r.location
        conn.commit.assert_called()
        all_args = ' '.join(str(c.args) for c in cur.execute.call_args_list if c.args)
        assert 'denied' in all_args
        assert 'access_denied' in all_args

    def test_secret_view_keeps_secret_row_after_binding_enrichment(self):
        """Regression: the admin binding email-enrichment loop previously shadowed
        the `row` variable, clobbering the secret row and raising KeyError: 'key'
        later when rendering/auditing the reveal. (secret_view reveal path)."""
        from contextlib import contextmanager
        sid = uuid4()
        binder_uid = str(uuid4())
        enc = crypto.encrypt('super-secret')
        conn, cur = _conn()
        row = {
            'id': sid, 'key': 'API_KEY', 'value_enc': enc, 'note': '', 'kind': 'plain',
            'expires_at': None, 'requires_approval': None, 'access_mode': 'inherit',
            'created_at': '2026-01-01', 'updated_at': '2026-01-01',
            'last_accessed_at': None, 'last_accessed_by': None,
            'project_name': 'prod', 'require_reveal_approval': False,
        }
        # as_user cursor fetchone order:
        #   [secret row, can_write, helper can_admin, can_admin, secret_enc]
        cur.fetchone.side_effect = [
            row, {'w': True}, {'a': True}, {'a': True},
            {'value_enc': enc, 'crypto_provider': 'master'},
        ]
        bindings = [{'id': sid, 'subject_kind': 'User', 'subject_id': binder_uid,
                     'created_at': '2026-01-01', 'role_name': 'secret-reveal', 'group_name': None}]
        # fetchall order: custom_meta, secret_bindings, team_groups
        cur.fetchall.side_effect = [[], bindings, []]
        # admin connection (enrichment) — returns the binder user row
        acur = MagicMock()
        acur.fetchall.return_value = [{'id': binder_uid, 'email': 'b@x.com', 'name': 'Bob'}]

        @contextmanager
        def _acur_cm(*_a, **_k):
            yield acur

        aconn = MagicMock()
        aconn.__enter__ = MagicMock(return_value=aconn)
        aconn.__exit__ = MagicMock(return_value=False)
        aconn.cursor.side_effect = _acur_cm
        with patch.object(db, 'as_user', return_value=conn), \
             patch.object(db, 'connect_admin', return_value=aconn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/view')
        assert r.status_code == 200
        assert b'API_KEY' in r.data
        assert b'super-secret' in r.data

    def test_secret_view_plain_get(self):
        sid = uuid4()
        enc = crypto.encrypt('plain-value')
        conn, cur = _conn()
        row = {
            'id': sid, 'key': 'DATABASE_URL', 'value_enc': enc, 'note': '', 'kind': 'plain',
            'expires_at': None, 'requires_approval': None, 'access_mode': 'inherit',
            'created_at': '2026-01-01', 'updated_at': '2026-01-01',
            'last_accessed_at': None, 'last_accessed_by': None,
            'project_name': 'prod', 'require_reveal_approval': False,
        }
        cur.fetchone.side_effect = [
            row, {'w': True}, {'a': True}, {'a': False},
            {'value_enc': enc, 'crypto_provider': 'master'},
        ]
        cur.fetchall.side_effect = [[], [], []]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/view')
        assert r.status_code == 200
        assert b'DATABASE_URL' in r.data
        assert b'plain-value' in r.data
        plain_copy = r.data[
            r.data.index(b'data-copy-target="plain-view"') - 100 :
        ]
        assert b'class="button outline small copy-btn"' in plain_copy
        assert b'id="toggle-edit-mode"' in r.data

    def test_secret_view_update_binds_note_and_provider(self):
        """BYOK splat used to bind provider as note and note as expires_at (500)."""
        sid = uuid4()
        enc = crypto.encrypt('old')
        conn, cur = _conn()
        row = {
            'id': sid, 'key': 'API_KEY', 'value_enc': enc, 'note': 'old-note', 'kind': 'plain',
            'expires_at': None, 'requires_approval': None, 'access_mode': 'inherit',
            'created_at': '2026-01-01', 'updated_at': '2026-01-01',
            'last_accessed_at': None, 'last_accessed_by': None,
            'project_name': 'prod', 'require_reveal_approval': False,
        }
        cur.fetchone.side_effect = [
            row, {'w': True}, {'a': True}, {'a': True},
        ]
        cur.fetchall.side_effect = [[], [], [], []]
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn), \
             patch.object(crypto, 'encrypt_for_project', return_value=('enc-token', 'project')):
            r = self.client.post(
                f'/projects/{self.pid}/secrets/{sid}/view',
                data={
                    'kind': 'plain',
                    'plain_value': 'new-secret',
                    'note': 'rotated',
                    'expires_at': '2030-01-15',
                },
                follow_redirects=False,
            )
        assert r.status_code == 302
        update = next(
            c for c in cur.execute.call_args_list
            if c.args and 'UPDATE api.secrets' in str(c.args[0])
        )
        params = update.args[1]
        assert params[0] == 'enc-token'
        assert params[1] == 'rotated'
        assert getattr(params[2], 'year', None) == 2030
        assert params[3] == 'plain'
        assert params[4] == 'project'
        assert params[5] == str(sid)
        assert params[6] == str(self.pid)
        conn.commit.assert_called()

    def test_hide_secret(self):
        sid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = str(uuid4())
        r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/hide', headers={'HX-Request': 'true'})
        assert r.status_code == 200
        assert b'*******' in r.data
        assert b'>Reveal</button>' in r.data
        assert b'/reveal' in r.data

    def test_update_secret_value(self):
        sid = uuid4()
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'w': True}, {'id': sid, 'key': 'API_KEY'}]
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/secrets/{sid}/value', data={'value': 'new-secret', 'expires_at': '2030-01-15'}, headers={'HX-Request': 'true'})
        assert r.status_code == 200
        assert b'new-secret' not in r.data
        assert b'*******' in r.data
        assert b'Updated' in r.data
        assert b'>Reveal</button>' in r.data
        conn.commit.assert_called()
        sql = ' '.join(str(c.args[0]) for c in cur.execute.call_args_list)
        assert 'expires_at' in sql

    def test_reveal_missing(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{uuid4()}/reveal')
        assert r.status_code == 404

    def test_users_suggest_requires_login(self):
        c = store.app.test_client()
        r = c.get('/api/users/suggest?q=ab')
        assert r.status_code == 302
        assert '/login' in r.location

    def test_users_suggest_ok(self):
        with self.client.session_transaction() as s:
            s['user_id'] = str(uuid4())
        conn, _ = _conn(fetchall=[{'email': 'alice@ex.com', 'name': 'Alice'}])
        with patch.object(db, 'connect_admin', return_value=conn), patch.object(authz, 'is_global_admin', return_value=True):
            r = self.client.get('/api/users/suggest?q=ali')
        assert r.status_code == 200
        data = r.get_json()
        assert data[0]['email'] == 'alice@ex.com'

    def test_add_secret_access_binding_service_account(self):
        sid, sa_id, role_id, pid = uuid4(), uuid4(), uuid4(), uuid4()
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            {'a': True},
            {'id': sid, 'key': 'KEY', 'access_mode': 'inherit', 'team_id': uuid4()},
            {'id': role_id},
            {'id': sa_id},
        ]
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(
                f'/projects/{pid}/secrets/{sid}/access/bindings',
                data={'subject_kind': 'ServiceAccount', 'subject_sa': str(sa_id),
                      'role_name': 'secret-reveal'},
                follow_redirects=False,
            )
        assert r.status_code == 302
        assert f'/projects/{pid}/secrets/{sid}/view?tab=access' in r.location
        conn.commit.assert_called()
        all_args = ' '.join(str(c.args) for c in cur.execute.call_args_list if c.args)
        assert 'INSERT INTO rbac.bindings' in all_args
        assert 'ServiceAccount' in all_args
        assert str(sa_id) in all_args
        assert 'secret-reveal' in all_args

    def test_add_secret_access_binding_external_user_ok(self):
        """Non-team user can be bound when secret does not require approval."""
        sid, uid, role_id, pid, tid = uuid4(), uuid4(), uuid4(), uuid4(), uuid4()
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            {'a': True},
            {'id': sid, 'key': 'KEY', 'access_mode': 'inherit', 'team_id': tid},
            {'id': role_id},
            {'id': uid},
            {'member': False},
            {'a': False},  # secret_requires_approval
        ]
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(
                f'/projects/{pid}/secrets/{sid}/access/bindings',
                data={
                    'subject_kind': 'User',
                    'subject_email': 'ext@ex.com',
                    'role_name': 'secret-reveal',
                },
                follow_redirects=False,
            )
        assert r.status_code == 302
        conn.commit.assert_called()
        all_args = ' '.join(str(c.args) for c in cur.execute.call_args_list if c.args)
        assert 'INSERT INTO rbac.bindings' in all_args

    def test_add_secret_access_binding_external_user_blocked_if_approval(self):
        """Cannot share approval-required secrets with non-team users."""
        sid, uid, role_id, pid, tid = uuid4(), uuid4(), uuid4(), uuid4(), uuid4()
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            {'a': True},
            {'id': sid, 'key': 'KEY', 'access_mode': 'restricted', 'team_id': tid},
            {'id': role_id},
            {'id': uid},
            {'member': False},
            {'a': True},  # secret_requires_approval
        ]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(
                f'/projects/{pid}/secrets/{sid}/access/bindings',
                data={
                    'subject_kind': 'User',
                    'subject_email': 'ext@ex.com',
                    'role_name': 'secret-reveal',
                },
                follow_redirects=False,
            )
        assert r.status_code == 302
        conn.commit.assert_not_called()
        all_args = ' '.join(str(c.args) for c in cur.execute.call_args_list if c.args)
        assert 'INSERT INTO rbac.bindings' not in all_args

    def test_shared_secrets_list(self):
        sid, pid = uuid4(), uuid4()
        rows = [{
            'id': sid,
            'key': 'SHARED_KEY',
            'note': '',
            'kind': 'plain',
            'project_id': pid,
            'project_name': 'prod',
            'team_id': uuid4(),
            'team_name': 'Ops',
            'access_mode': 'restricted',
            'updated_at': '2026-01-01',
            'expires_at': None,
            'role_name': 'secret-reveal',
        }]
        conn, cur = _conn()
        cur.fetchall.side_effect = [rows]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get('/shared')
        assert r.status_code == 200
        assert b'Shared secrets' in r.data
        assert b'SHARED_KEY' in r.data
        assert b'prod' in r.data
        assert b'Ops' in r.data
        assert b'secret-reveal' in r.data
