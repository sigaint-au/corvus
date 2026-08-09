"""Unit tests per component (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

import os
import re
from contextlib import contextmanager
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

# Import-time env (app reads these at load). conftest also sets these for tox/pytest.
_FAKE_DSN = "postgres://test:test@127.0.0.1:1/test?connect_timeout=1"
os.environ.setdefault("DATABASE_URL", _FAKE_DSN)
os.environ.setdefault("DATABASE_ADMIN_URL", _FAKE_DSN)
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-change-me-32chars!!")
os.environ.setdefault("MASTER_KEY", "test-master-key-change-in-prod!!")
os.environ.setdefault("SECRET_KEY", "test-flask-session-secret")
os.environ.setdefault("ALLOW_INSECURE_DEFAULTS", "1")

import jwt as pyjwt  # noqa: E402
import app as store  # noqa: E402
import audit  # noqa: E402
import authz  # noqa: E402
import config  # noqa: E402
import crypto  # noqa: E402
import db  # noqa: E402
import ldap_auth  # noqa: E402
import lockout  # noqa: E402
import nav  # noqa: E402
import paging  # noqa: E402
import pats  # noqa: E402
import schema as schema_mod  # noqa: E402
import settings_svc  # noqa: E402
import user_sessions  # noqa: E402
from routes import eso as eso_routes  # noqa: E402

store.app.config["TESTING"] = True


_UNSET = object()

def _conn(fetchone=_UNSET, fetchall=_UNSET, side_effect=None):
    cur = MagicMock()
    if side_effect is not None:
        cur.execute.side_effect = side_effect
    if fetchone is not _UNSET:
        if callable(fetchone) and (not isinstance(fetchone, dict)):
            cur.fetchone.side_effect = fetchone
        else:
            cur.fetchone.return_value = fetchone
    else:
        cur.fetchone.return_value = None
    if fetchall is not _UNSET:
        cur.fetchall.return_value = fetchall
    else:
        cur.fetchall.return_value = []

    def cursor(*_a, **_k):

        @contextmanager
        def cm():
            yield cur
        return cm()
    conn = MagicMock()
    conn.cursor.side_effect = cursor
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)
    return (conn, cur)

class TestCrypto:

    def test_roundtrip(self):
        assert crypto.decrypt(crypto.encrypt('ping')) == 'ping'

    def test_empty(self):
        assert crypto.decrypt(crypto.encrypt('')) == ''

    def test_unicode(self):
        s = 'héllo 🔐 日本語'
        assert crypto.decrypt(crypto.encrypt(s)) == s

    def test_ciphertext_differs(self):
        a, b = (crypto.encrypt('x'), crypto.encrypt('x'))
        assert a != b
        assert crypto.decrypt(a) == crypto.decrypt(b)

class TestJWT:

    def test_make_jwt_claims(self):
        uid = str(uuid4())
        token = db.make_jwt(uid, hours=1)
        claims = pyjwt.decode(token, config.JWT_SECRET, algorithms=['HS256'])
        assert claims['sub'] == uid
        assert claims['role'] == 'authenticated'
        assert 'exp' in claims

class TestPatsUnit:

    def test_mint_raw_shape(self):
        raw, thash, prefix = pats.mint_raw()
        assert raw.startswith('pat_')
        assert len(thash) == 64
        assert prefix == raw[:12]
        assert pats._hash(raw) == thash

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

class TestLdapPassword:

    def test_empty(self):
        assert ldap_auth.ldap_password_plain({}) == ''
        assert ldap_auth.ldap_password_plain({'ldap_bind_password': '  '}) == ''

    def test_decrypts(self):
        enc = crypto.encrypt('bind-secret')
        assert ldap_auth.ldap_password_plain({'ldap_bind_password': enc}) == 'bind-secret'

    def test_decrypt_failure_returns_empty_not_ciphertext(self):
        bad = 'not-valid-fernet-ciphertext'
        assert ldap_auth.ldap_password_plain({'ldap_bind_password': bad}) == ''

class TestLdapTlsPolicy:

    def test_ldaps_ok_without_starttls(self):
        assert ldap_auth.ldap_tls_required_ok('ldaps://ipa.example.com', False)

    def test_ldap_requires_starttls(self):
        assert not ldap_auth.ldap_tls_required_ok('ldap://ipa.example.com', False)
        assert ldap_auth.ldap_tls_required_ok('ldap://ipa.example.com', True)

    def test_empty_url_rejected(self):
        assert not ldap_auth.ldap_tls_required_ok('', True)

    def test_authenticate_refuses_cleartext(self):
        with patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'true', 'ldap_url': 'ldap://ipa.example.com', 'ldap_start_tls': 'false', 'ldap_user_base': 'cn=users'}):
            assert ldap_auth.ldap_authenticate('user', 'pass') is None

class TestLdapStartTLS:

    def test_open_start_tls_before_bind(self):
        order = []

        class FakeConn:

            def __init__(self, *a, **k):
                self.auto_bind = k.get('auto_bind', True)

            def open(self):
                order.append('open')
                return True

            def start_tls(self):
                order.append('start_tls')
                return True

            def bind(self):
                order.append('bind')
                return True

            def unbind(self):
                order.append('unbind')
        with patch.dict('sys.modules', {'ldap3': MagicMock()}):
            import ldap3 as ldap3_mod
            ldap3_mod.Connection = FakeConn
            conn = ldap_auth._ldap_bind(object(), user='cn=x', password='p', start_tls=True)
        assert order[:3] == ['open', 'start_tls', 'bind']
        assert not conn.auto_bind

    def test_start_tls_failure_fails_closed(self):
        bound = {'n': 0}

        class FakeConn:

            def __init__(self, *a, **k):
                pass

            def open(self):
                return True

            def start_tls(self):
                return False

            def unbind(self):
                pass

            def bind(self):
                bound['n'] += 1
                return True
        fake_mod = MagicMock()
        fake_mod.Connection = FakeConn
        with patch.dict('sys.modules', {'ldap3': fake_mod}):
            with pytest.raises(RuntimeError) as cm:
                ldap_auth._ldap_bind(object(), start_tls=True)
        assert 'StartTLS' in str(cm.value)
        assert bound['n'] == 0

class TestEnsureSchema:

    def test_requires_admin_url(self):
        with patch.object(schema_mod, 'DATABASE_ADMIN_URL', ''):
            with pytest.raises(RuntimeError) as cm:
                schema_mod.ensure_schema()
        assert 'DATABASE_ADMIN_URL' in str(cm.value)

    def test_uses_advisory_lock(self):
        conn, cur = _conn()
        with patch.object(schema_mod, 'DATABASE_ADMIN_URL', 'postgres://admin@x/db'), patch.object(db, 'connect_admin', return_value=conn), patch.object(schema_mod, 'bootstrap_admin_email', return_value=''):
            schema_mod.ensure_schema()
        sqls = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list if c.args))
        assert 'pg_advisory_lock' in sqls
        assert 'pg_advisory_unlock' in sqls

class TestHelpers:

    def test_htmx_false(self):
        with store.app.test_request_context('/'):
            assert not authz.htmx()

    def test_htmx_true(self):
        with store.app.test_request_context('/', headers={'HX-Request': 'true'}):
            assert authz.htmx()

    def test_login_required_redirects(self):

        @authz.login_required
        def protected():
            return 'ok'
        with store.app.test_request_context('/x'):
            resp = protected()
            assert resp.status_code == 302
            assert '/login' in resp.location

    def test_login_required_passes(self):
        c = store.app.test_client()
        with c.session_transaction() as sess:
            sess['user_id'] = str(uuid4())
            sess['email'] = 't@t.t'
        conn, _ = _conn(fetchall=[])
        with patch.object(db, 'as_user', return_value=conn):
            r = c.get('/teams')
        assert r.status_code == 200

    def test_safe_redirect_allows_relative(self):
        assert authz.safe_redirect_target('/teams', '/x') == '/teams'
        assert authz.safe_redirect_target(None, '/x') == '/x'

    def test_safe_redirect_blocks_open_redirect(self):
        assert authz.safe_redirect_target('//evil', '/x') == '/x'
        assert authz.safe_redirect_target('https://evil', '/x') == '/x'
        assert authz.safe_redirect_target('teams', '/x') == '/x'

    def test_page_window_basic(self):
        w = paging.page_window(100, 2, per_page=25)
        assert w['page'] == 2
        assert w['offset'] == 25
        assert w['pages'] == 4
        assert w['has_prev']
        assert w['has_next']

    def test_page_window_empty(self):
        w = paging.page_window(0, 1)
        assert w['pages'] == 1
        assert w['start'] == 0
        assert w['end'] == 0

class TestLockout:

    def test_empty_email_not_locked(self):
        assert not lockout.is_locked('')
        assert not lockout.is_locked('  ')

    def test_is_locked_when_at_threshold(self):
        conn, _ = _conn(fetchone={'n': lockout.MAX_ATTEMPTS})
        with patch.object(db, 'connect_admin', return_value=conn):
            assert lockout.is_locked('a@b.c')

    def test_not_locked_below_threshold(self):
        conn, _ = _conn(fetchone={'n': lockout.MAX_ATTEMPTS - 1})
        with patch.object(db, 'connect_admin', return_value=conn):
            assert not lockout.is_locked('a@b.c')

    def test_db_error_fails_open(self):
        with patch.object(db, 'connect_admin', side_effect=RuntimeError('db')):
            assert not lockout.is_locked('a@b.c')

    def test_record_and_clear(self):
        conn, cur = _conn()
        with patch.object(db, 'connect_admin', return_value=conn):
            lockout.record_failure('A@B.C')
            lockout.clear_failures('A@B.C')
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
        assert 'INSERT INTO private.login_failures' in sql
        assert 'DELETE FROM private.login_failures' in sql
        assert cur.execute.call_args_list[0].args[1] == ('a@b.c',)

class TestRefuseInsecureDefaults:

    def test_opt_in_allows(self):
        with patch.dict(os.environ, {'ALLOW_INSECURE_DEFAULTS': '1'}, clear=False):
            os.environ.pop('FLASK_ENV', None)
            config.refuse_insecure_defaults()

    def test_blocks_default_secrets(self):
        with patch.dict(os.environ, {'ALLOW_INSECURE_DEFAULTS': '0'}, clear=False), patch.object(config, 'SECRET_KEY', config._DEFAULT_SECRET_KEY), patch.object(config, 'JWT_SECRET', config._DEFAULT_JWT_SECRET), patch.object(config, 'MASTER_KEY', config._DEFAULT_MASTER_KEY):
            os.environ.pop('FLASK_ENV', None)
            with pytest.raises(SystemExit):
                config.refuse_insecure_defaults()

class TestAudit:

    def test_describe_event_readable(self):
        s = audit.describe_event({'actor_email': 'a@b.c', 'action': 'revealed', 'secret_key': 'API_KEY'})
        assert 'a@b.c' in s
        assert 'revealed' in s
        assert 'API_KEY' in s

    def test_format_time_ago(self):
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        assert audit.format_time_ago(None) == '—'
        assert audit.format_time_ago(now - timedelta(seconds=10)) == 'just now'
        assert audit.format_time_ago(now - timedelta(minutes=5)) == '5 minutes ago'
        assert audit.format_time_ago(now - timedelta(hours=3)) == '3 hours ago'
        assert audit.format_time_ago(now - timedelta(days=4)) == '4 days ago'
        abs_s = audit.format_when(now - timedelta(hours=1))
        assert 'UTC' in abs_s

    def test_global_search_requires_login(self):
        r = store.app.test_client().get('/search?q=x')
        assert r.status_code == 302

    def test_filter_clause_actor_action_dates(self):
        sql, params = audit._filter_clause(actor='bob', action='revealed', since='2026-01-01', until='2026-01-02')
        assert 'actor_email' in sql
        assert 'action' in sql
        assert 'created_at' in sql
        assert params[0] == '%bob%'
        assert params[1] == 'revealed'

    def test_invalid_action_raises(self):
        cur = MagicMock()
        with store.app.test_request_context('/'):
            with pytest.raises(ValueError):
                audit.log_secret(cur, project_id=uuid4(), action='nope')

    def test_log_secret_calls_audit_secret_fn(self):
        cur = MagicMock()
        pid, sid = (uuid4(), uuid4())
        with store.app.test_request_context('/'):
            from flask import session
            session['user_id'] = str(uuid4())
            session['email'] = 'a@b.c'
            audit.log_secret(cur, project_id=pid, secret_id=sid, secret_key='K', action='revealed')
        assert cur.execute.call_count == 1
        sql, params = (cur.execute.call_args.args[0], cur.execute.call_args.args[1])
        assert 'private.audit_secret' in sql
        assert 'NULL::uuid' in sql
        assert 'INSERT INTO api.secret_audit' not in sql
        assert params[-1] == 'a@b.c'

    def test_schema_revokes_secret_audit_insert(self):
        from pathlib import Path
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        assert 'REVOKE INSERT ON api.secret_audit FROM authenticated' in init
        assert 'CREATE OR REPLACE FUNCTION private.audit_secret' in init
        assert 'Never trust caller-supplied p_user_id' in init
        src = Path(schema_mod.__file__).read_text()
        assert 'REVOKE INSERT ON api.secret_audit FROM authenticated' in src
        assert 'private.audit_secret' in src
        assert 'Never trust caller-supplied p_user_id' in src

class TestAuth:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        store.app.config['CSRF_TESTING'] = False
        self.client = store.app.test_client()

    def test_index_anon_to_login(self):
        r = self.client.get('/')
        assert r.status_code == 302
        assert '/login' in r.location

    def test_index_authed_to_teams(self):
        with self.client.session_transaction() as s:
            s['user_id'] = str(uuid4())
        r = self.client.get('/')
        assert r.status_code == 302
        assert '/teams' in r.location

    def test_login_get(self):
        with patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch.object(settings_svc, 'setup_notice', return_value=None), patch.object(settings_svc, 'registration_enabled', return_value=True):
            r = self.client.get('/login')
        assert r.status_code == 200
        assert b'Sign in' in r.data

    def test_login_bad_creds(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, 'connect', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch('lockout.record_failure'), patch('lockout.is_locked', return_value=False):
            r = self.client.post('/login', data={'email': 'a@b.c', 'password': 'nope'})
        assert r.status_code == 401
        assert b'Invalid' in r.data

    def test_login_locked(self):
        with patch('lockout.is_locked', return_value=True), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}):
            r = self.client.post('/login', data={'email': 'a@b.c', 'password': 'x'})
        assert r.status_code == 429

    def test_login_ok(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={'id': uid, 'email': 'a@b.c', 'name': 'A'})
        with patch.object(db, 'connect', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch('lockout.is_locked', return_value=False), patch('lockout.clear_failures'), patch.object(authz, 'is_global_admin', return_value=False), patch.object(settings_svc, 'setup_notice', return_value=None), patch('totp_svc.needs_challenge', return_value=None), patch('mailer.login_alerts_enabled', return_value=False):
            r = self.client.post('/login', data={'email': 'a@b.c', 'password': 'secret12'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location
        with self.client.session_transaction() as s:
            assert s['user_id'] == str(uid)
            assert s['email'] == 'a@b.c'
            assert 'jwt' in s

    def test_login_clears_session_first(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={'id': uid, 'email': 'a@b.c', 'name': 'A'})
        with self.client.session_transaction() as s:
            s['stale'] = 'should-be-gone'
            s['_csrf'] = 'old'
        with patch.object(db, 'connect', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch('lockout.is_locked', return_value=False), patch('lockout.clear_failures'), patch.object(authz, 'is_global_admin', return_value=False), patch.object(settings_svc, 'setup_notice', return_value=None), patch('totp_svc.needs_challenge', return_value=None), patch('mailer.login_alerts_enabled', return_value=False):
            r = self.client.post('/login', data={'email': 'a@b.c', 'password': 'secret12'}, follow_redirects=False)
        assert r.status_code == 302
        with self.client.session_transaction() as s:
            assert 'stale' not in s
            assert s['user_id'] == str(uid)

    def test_csrf_rejects_post_without_token(self):
        store.app.config['CSRF_TESTING'] = True
        try:
            with self.client.session_transaction() as s:
                s['_csrf'] = 'good-token'
            r = self.client.post('/logout')
            assert r.status_code == 400
        finally:
            store.app.config['CSRF_TESTING'] = False

    def test_csrf_accepts_valid_token(self):
        store.app.config['CSRF_TESTING'] = True
        try:
            with self.client.session_transaction() as s:
                s['_csrf'] = 'good-token'
                s['user_id'] = str(uuid4())
            r = self.client.post('/logout', data={'_csrf': 'good-token'}, follow_redirects=False)
            assert r.status_code == 302
            assert '/login' in r.location
        finally:
            store.app.config['CSRF_TESTING'] = False

    def test_select_team_blocks_open_redirect(self):
        with self.client.session_transaction() as s:
            s['user_id'] = str(uuid4())
        r = self.client.post('/select-team', data={'team_id': '', 'next': '//evil.com'}, follow_redirects=False)
        assert r.status_code == 302
        assert 'evil' not in r.location
        assert r.location.endswith('/projects') or '/projects' in r.location

    def test_login_ldap_ok(self):
        uid = uuid4()
        ldap_user = {'email': 'ldap@ex.com', 'name': 'LDAP User', 'groups': ['CN=secretstore-admins,OU=groups,DC=ex,DC=com']}
        synced = {'id': uid, 'email': 'ldap@ex.com', 'name': 'LDAP User', 'is_global_admin': True}
        conn, _ = _conn(fetchone=None)
        with patch.object(db, 'connect', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'true'}), patch.object(ldap_auth, 'ldap_authenticate', return_value=ldap_user), patch.object(ldap_auth, 'sync_ldap_user', return_value=synced), patch('lockout.is_locked', return_value=False), patch('lockout.clear_failures'), patch.object(authz, 'is_global_admin', return_value=True), patch.object(settings_svc, 'setup_notice', return_value=None), patch('totp_svc.needs_challenge', return_value=None), patch('mailer.login_alerts_enabled', return_value=False):
            r = self.client.post('/login', data={'email': 'ldapuser', 'password': 'dir-pass'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location
        with self.client.session_transaction() as s:
            assert s['user_id'] == str(uid)
            assert s['email'] == 'ldap@ex.com'
            assert s['is_global_admin']

    def test_register_short_password(self):
        with patch.object(settings_svc, 'registration_enabled', return_value=True), patch.object(settings_svc, 'setup_notice', return_value=None):
            r = self.client.post('/register', data={'email': 'a@b.c', 'password': 'short', 'name': 'A'})
        assert r.status_code == 400
        assert b'8 characters' in r.data

    def test_register_ok(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={'id': uid})
        with patch.object(db, 'connect', return_value=conn), patch.object(settings_svc, 'registration_enabled', return_value=True), patch.object(settings_svc, 'setup_notice', return_value=None), patch.object(authz, 'is_global_admin', return_value=False), patch('totp_svc.needs_challenge', return_value=None), patch('mailer.login_alerts_enabled', return_value=False):
            r = self.client.post('/register', data={'email': 'new@b.c', 'password': 'password1', 'name': 'N'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location
        with self.client.session_transaction() as s:
            assert not s.get('is_global_admin')

    def test_register_does_not_auto_promote_first_user(self):
        """register_user SQL must set is_global_admin false (no first_user race)."""
        from pathlib import Path
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        start = init.index('CREATE OR REPLACE FUNCTION private.register_user')
        end = init.index('$$;', start)
        body = init[start:end]
        assert "false, 'local'" in body
        assert 'first_user' not in body

    def test_bootstrap_email_promotes_on_register(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={'id': uid})
        admin_conn, admin_cur = _conn()
        with patch.object(db, 'connect', return_value=conn), patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(settings_svc, 'registration_enabled', return_value=True), patch.object(settings_svc, 'setup_notice', return_value=None), patch('routes.auth.bootstrap_admin_email', return_value='admin@ex.com'), patch.object(authz, 'is_global_admin', return_value=True), patch('totp_svc.needs_challenge', return_value=None), patch('mailer.login_alerts_enabled', return_value=False):
            r = self.client.post('/register', data={'email': 'admin@ex.com', 'password': 'password1', 'name': 'A'}, follow_redirects=False)
        assert r.status_code == 302
        sql = ' '.join((str(c.args[0]) for c in admin_cur.execute.call_args_list))
        assert 'is_global_admin = true' in sql

    def test_register_disabled(self):
        with patch.object(settings_svc, 'registration_enabled', return_value=False):
            r = self.client.get('/register', follow_redirects=False)
        assert r.status_code == 302
        assert '/login' in r.location
        with patch.object(settings_svc, 'registration_enabled', return_value=False):
            r = self.client.post('/register', data={'email': 'new@b.c', 'password': 'password1', 'name': 'N'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/login' in r.location

    def test_login_hides_register_when_disabled(self):
        with patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch.object(settings_svc, 'registration_enabled', return_value=False), patch.object(settings_svc, 'setup_notice', return_value=None):
            r = self.client.get('/login')
        assert r.status_code == 200
        assert b'href="/register"' not in r.data

    def test_registration_disabled_without_bootstrap(self):
        with patch.object(settings_svc, 'has_global_admin', return_value=False), patch('settings_svc.bootstrap_admin_email', return_value=''), patch.object(settings_svc, 'get_settings', return_value={'registration_enabled': 'true'}):
            assert not settings_svc.registration_enabled()

    def test_logout(self):
        with self.client.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'a@b.c'
        r = self.client.post('/logout')
        assert r.status_code == 302
        assert '/login' in r.location
        with self.client.session_transaction() as s:
            assert 'user_id' not in s

    def test_profile_requires_login(self):
        r = self.client.get('/profile')
        assert r.status_code == 302
        assert '/login' in r.location

    def test_forgot_password_get(self):
        r = self.client.get('/forgot-password')
        assert r.status_code == 200
        assert b'Forgot password' in r.data

    def test_forgot_password_post_no_enumeration(self):
        with patch('passwords.create_reset_token', return_value=None):
            r = self.client.post('/forgot-password', data={'email': 'nobody@ex.com'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/login' in r.location

    def test_change_password_requires_login(self):
        r = self.client.post('/profile/password', data={'current_password': 'old', 'new_password': 'newpass12', 'new_password_confirm': 'newpass12'})
        assert r.status_code == 302
        assert '/login' in r.location

    def test_change_password_ok(self):
        uid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = uid
            s['sid'] = str(uuid4())
        with patch('passwords.change_password', return_value=(True, '')), patch('user_sessions.revoke_other_sessions', return_value=2):
            r = self.client.post('/profile/password', data={'current_password': 'oldpass12', 'new_password': 'newpass12', 'new_password_confirm': 'newpass12'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/profile' in r.location
        assert 'tab=security' in r.location

    def test_change_password_mismatch(self):
        uid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = uid
        r = self.client.post('/profile/password', data={'current_password': 'oldpass12', 'new_password': 'newpass12', 'new_password_confirm': 'other'}, follow_redirects=False)
        assert r.status_code == 302
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('match' in msg.lower() for _c, msg in flashes))

    def test_revoke_other_sessions(self):
        uid = str(uuid4())
        sid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = uid
            s['sid'] = sid
        with patch('user_sessions.revoke_other_sessions', return_value=3) as rev:
            r = self.client.post('/profile/sessions/revoke-others', follow_redirects=False)
        assert r.status_code == 302
        rev.assert_called_once_with(uid, sid)

    def test_reset_password_mismatch(self):
        r = self.client.post('/reset-password/tok', data={'password': 'newpass12', 'password_confirm': 'nope'})
        assert r.status_code == 400

    def test_reset_password_ok(self):
        with patch('passwords.consume_reset_token', return_value=(True, '')):
            r = self.client.post('/reset-password/goodtoken', data={'password': 'newpass12', 'password_confirm': 'newpass12'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/login' in r.location

    def test_password_schema_helpers(self):
        from pathlib import Path
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        assert 'private.change_password' in init
        assert 'private.set_local_password' in init
        assert 'private.user_sessions' in init
        assert 'private.password_reset_tokens' in init

    def test_profile_ok(self):
        uid = uuid4()
        tid = uuid4()
        pid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = str(uid)
            s['email'] = 'a@b.c'
            s['name'] = 'Ada'
            s['is_global_admin'] = False
        admin_conn, _ = _conn(fetchone={'id': uid, 'email': 'a@b.c', 'name': 'Ada Lovelace', 'is_global_admin': False, 'auth_source': 'local', 'created_at': '2026-01-01'})
        last_sql = {'s': ''}

        def execute(sql, params=None):
            last_sql['s'] = ' '.join(str(sql).lower().split())

        def fetchone():
            s = last_sql['s']
            if 'from api.secrets' in s and 'count' in s:
                return {'n': 3}
            if 'from api.secret_pins' in s and 'count' in s:
                return {'n': 1}
            return None

        def fetchall():
            s = last_sql['s']
            if 'from api.teams t' in s:
                return [{'id': tid, 'name': 'Platform', 'role': 'owner', 'source': 'manual', 'created_at': '2026-01-02', 'project_count': 1}]
            if 'from api.projects p' in s:
                return [{'id': pid, 'name': 'API', 'created_at': '2026-01-03', 'team_id': tid, 'team_name': 'Platform', 'team_role': 'owner', 'project_role': None, 'secret_count': 3}]
            if 'team_join_requests' in s:
                return []
            if 'secret_pins pin' in s or 'from api.secret_pins pin' in s:
                return []
            if 'secret_recent' in s:
                return []
            return []
        user_conn, cur = _conn(fetchone=fetchone)
        cur.execute.side_effect = execute
        cur.fetchall.side_effect = fetchall
        with patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(db, 'as_user', return_value=user_conn), patch('user_sessions.list_sessions', return_value=[]):
            r = self.client.get('/profile')
        assert r.status_code == 200
        assert b'My profile' in r.data
        assert b'?tab=account' in r.data
        assert b'?tab=security' in r.data
        assert b'?tab=teams' in r.data
        assert b'?tab=projects' in r.data
        assert b'?tab=activity' in r.data
        assert b'Ada Lovelace' in r.data
        assert b'a@b.c' in r.data
        assert b'Local' in r.data
        assert b'Database' in r.data
        assert b'At a glance' in r.data
        assert b'Change password' not in r.data
        assert b'Active sessions' not in r.data
        with patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(db, 'as_user', return_value=user_conn), patch('user_sessions.list_sessions', return_value=[]), patch('pats.list_for_user', return_value=[]):
            r_sec = self.client.get('/profile?tab=security')
        assert r_sec.status_code == 200
        assert b'Change password' in r_sec.data
        assert b'Active sessions' in r_sec.data
        assert b'Two-factor authentication' in r_sec.data
        assert b'Personal access tokens' in r_sec.data
        assert b'API access' in r_sec.data
        assert b'show-session-jwt' in r_sec.data
        with patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(db, 'as_user', return_value=user_conn):
            r_teams = self.client.get('/profile?tab=teams')
        assert r_teams.status_code == 200
        assert b'Platform' in r_teams.data
        with patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(db, 'as_user', return_value=user_conn):
            r_proj = self.client.get('/profile?tab=projects')
        assert r_proj.status_code == 200
        assert b'API' in r_proj.data

    def test_profile_shows_ldap_and_admin(self):
        uid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = str(uid)
            s['email'] = 'admin@ex.com'
            s['is_global_admin'] = True
        admin_conn, _ = _conn(fetchone={'id': uid, 'email': 'admin@ex.com', 'name': 'Admin', 'is_global_admin': True, 'auth_source': 'ldap', 'created_at': '2025-06-01'})
        user_conn, _ = _conn(fetchone={'n': 0}, fetchall=[])
        with patch.object(db, 'connect_admin', return_value=admin_conn), patch.object(db, 'as_user', return_value=user_conn), patch('user_sessions.list_sessions', return_value=[]), patch('pats.list_for_user', return_value=[]):
            r = self.client.get('/profile?tab=account')
            r_sec = self.client.get('/profile?tab=security')
        assert r.status_code == 200
        assert b'LDAP' in r.data
        assert b'Directory' in r.data
        assert b'Global admin' in r.data
        assert r_sec.status_code == 200
        assert b'LDAP' in r_sec.data
        assert b'name="current_password"' not in r_sec.data

class TestTeams:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'u@ex.com'

    def test_list_requires_login(self):
        c = store.app.test_client()
        r = c.get('/teams')
        assert r.status_code == 302
        assert '/login' in r.location

    def test_list_teams(self):
        tid = uuid4()
        conn, _ = _conn(fetchall=[{'id': tid, 'name': 'Platform', 'role': 'owner', 'project_count': 2}])
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get('/teams')
        assert r.status_code == 200
        assert b'Platform' in r.data
        assert b'sidebar' in r.data

    def test_create_team_empty_name(self):
        with patch.object(settings_svc, 'can_create_team', return_value=True):
            r = self.client.post('/teams', data={'name': '  '}, follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location

    def test_create_team(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={'id': tid})
        with patch.object(db, 'connect', return_value=conn), patch.object(settings_svc, 'can_create_team', return_value=True):
            r = self.client.post('/teams', data={'name': 'Ops'}, follow_redirects=False)
        assert r.status_code == 302
        assert str(tid) in r.location

    def test_create_team_restricted(self):
        with patch.object(settings_svc, 'can_create_team', return_value=False):
            r = self.client.post('/teams', data={'name': 'Ops'}, follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location
        assert 'Ops' not in r.headers.get('Location', '')

    def test_team_detail_404(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/teams/{uuid4()}')
        assert r.status_code == 404

    def test_team_detail_ok(self):
        tid = uuid4()
        last_sql = {'s': ''}

        def execute(sql, params=None):
            last_sql['s'] = ' '.join(str(sql).lower().split())

        def fetchone():
            s = last_sql['s']
            if 'from api.teams' in s and 'where id' in s:
                return {'id': tid, 'name': 'T'}
            if 'api.team_role' in s or 'select role from api.team_members' in s:
                return {'r': 'owner', 'role': 'owner'}
            return None
        conn, cur = _conn(fetchone=fetchone, fetchall=[])
        cur.execute.side_effect = execute
        with patch.object(db, 'as_user', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}):
            r = self.client.get(f'/teams/{tid}')
        assert r.status_code == 200
        assert b'>T<' in r.data
        assert b'?tab=projects' in r.data
        assert b'?tab=members' in r.data
        assert b'?tab=groups' in r.data
        assert b'?tab=settings' in r.data
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list)).lower()
        assert 'from api.projects' in sql
        assert 'team_member_rows' not in sql

    def test_team_detail_members_tab(self):
        tid = uuid4()
        last_sql = {'s': ''}

        def execute(sql, params=None):
            last_sql['s'] = ' '.join(str(sql).lower().split())

        def fetchone():
            s = last_sql['s']
            if 'from api.teams' in s and 'where id' in s:
                return {'id': tid, 'name': 'T'}
            if 'api.team_role' in s or 'select role from api.team_members' in s:
                return {'r': 'owner', 'role': 'owner'}
            return None
        conn, cur = _conn(fetchone=fetchone, fetchall=[])
        cur.execute.side_effect = execute
        with patch.object(db, 'as_user', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}):
            r = self.client.get(f'/teams/{tid}?tab=members')
        assert r.status_code == 200
        assert b'Invites' in r.data
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list)).lower()
        assert 'team_member_rows' in sql

    def test_add_member_user_missing(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={'id': None})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/members', data={'email': 'nope@x.com', 'role': 'member'}, follow_redirects=False)
        assert r.status_code == 302

    def test_add_member_uses_lookup_user(self):
        tid, uid = (uuid4(), uuid4())
        conn, cur = _conn(fetchone={'id': uid})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/members', data={'email': 'u@ex.com', 'role': 'member'}, follow_redirects=False)
        assert r.status_code == 302
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
        assert 'private.lookup_user' in sql
        assert 'user_directory' not in sql

    def test_user_directory_not_granted_to_authenticated(self):
        from pathlib import Path
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        assert 'GRANT SELECT ON api.user_directory TO authenticated' not in init
        assert 'private.lookup_user' in init
        assert 'private.team_member_rows' in init

    def test_non_member_cannot_self_join(self):
        """RLS must reject self-insert into a team the user does not admin."""
        tid = uuid4()
        rls_err = Exception('new row violates row-level security policy for table "team_members"')
        state = {'n': 0}

        def execute(sql, params=None):
            if 'INSERT INTO api.team_members' in str(sql):
                raise rls_err

        def fetchone():
            state['n'] += 1
            # 1: team_role (non-owner) 2: lookup_user 3: existing membership
            if state['n'] == 1:
                return {'r': 'member'}
            if state['n'] == 2:
                return {'id': self.uid}
            return None

        conn, cur = _conn(fetchone=fetchone)
        cur.execute.side_effect = execute
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(
                f'/teams/{tid}/members',
                data={'email': 'u@ex.com', 'role': 'member'},
                follow_redirects=False,
            )
        assert r.status_code == 302
        conn.commit.assert_not_called()
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('row-level security' in msg for _cat, msg in flashes))

    def test_tm_insert_policy_forbids_self_join(self):
        """Policy must require owner/admin — no user_id = current_user escape hatch."""
        from pathlib import Path
        init_sql = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        start = init_sql.index('CREATE POLICY tm_insert ON api.team_members')
        end = init_sql.index(';', start)
        policy = init_sql[start:end]
        assert "api.team_role(team_id) IN ('owner', 'admin')" in policy
        assert 'user_id = api.current_user_id()' not in policy
        src = Path(schema_mod.__file__).read_text()
        assert 'DROP POLICY IF EXISTS tm_insert ON api.team_members' in src
        ensure_start = src.index('DROP POLICY IF EXISTS tm_insert ON api.team_members')
        ensure_chunk = src[ensure_start:ensure_start + 280]
        assert "api.team_role(team_id) IN ('owner', 'admin')" in ensure_chunk
        assert 'user_id = api.current_user_id()' not in ensure_chunk

    def test_team_roles_include_viewer(self):
        assert 'viewer' in config.TEAM_ROLES
        assert config.ROLE_RANK['viewer'] < config.ROLE_RANK['member']

    def test_add_member_viewer_role(self):
        tid, uid = (uuid4(), uuid4())
        conn, cur = _conn(fetchone={'id': uid})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/members', data={'email': 'ro@ex.com', 'role': 'viewer'}, follow_redirects=False)
        assert r.status_code == 302
        sql = ' '.join((str(c) for c in cur.execute.call_args_list))
        assert 'viewer' in sql

    def test_create_project(self):
        tid, pid = (uuid4(), uuid4())
        conn, _ = _conn(fetchone={'id': pid})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/projects', data={'name': 'prod'}, follow_redirects=False)
        assert r.status_code == 302
        assert str(pid) in r.location

    def test_delete_team_owner_ok(self):
        tid = uuid4()
        conn, cur = _conn(fetchone={'r': 'owner'})
        cur.rowcount = 1
        with self.client.session_transaction() as s:
            s['team_id'] = str(tid)
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/delete', follow_redirects=False)
        assert r.status_code == 302
        assert '/teams' in r.location
        assert str(tid) not in r.location
        conn.commit.assert_called()
        with self.client.session_transaction() as s:
            assert s.get('team_id') != str(tid)

    def test_delete_team_non_owner_denied(self):
        tid = uuid4()
        for role in ('admin', 'member', 'viewer'):
            conn, cur = _conn(fetchone={'r': role})
            with patch.object(db, 'as_user', return_value=conn):
                r = self.client.post(f'/teams/{tid}/delete', follow_redirects=False)
            assert r.status_code == 302
            assert str(tid) in r.location
            conn.commit.assert_not_called()
            with self.client.session_transaction() as s:
                flashes = s.get('_flashes') or []
            assert any(('owner' in msg.lower() for _c, msg in flashes))

    def test_delete_project_admin_ok(self):
        tid, pid = (uuid4(), uuid4())
        conn, cur = _conn(fetchone={'r': 'admin'})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/projects/{pid}/delete', follow_redirects=False)
        assert r.status_code == 302
        assert str(tid) in r.location
        conn.commit.assert_called()

    def test_delete_project_member_denied(self):
        tid, pid = (uuid4(), uuid4())
        conn, _ = _conn(fetchone={'r': 'member'})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{tid}/projects/{pid}/delete', follow_redirects=False)
        assert r.status_code == 302
        conn.commit.assert_not_called()
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('owner' in msg.lower() or 'admin' in msg.lower() for _c, msg in flashes))

class TestSecrets:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        self.pid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'u@ex.com'

    def _project_conn(self, tab='secrets', can_write=True, can_admin=None, team_role='owner', secrets=None, tokens=None, audit_log=None, access_requests=None, total=None, pending_count=0):
        """as_user used by project_detail (tab-scoped queries)."""
        project = {'id': self.pid, 'name': 'prod', 'team_name': 'Ops', 'team_id': uuid4()}
        if can_admin is None:
            can_admin = team_role in ('owner', 'admin')
        rows = secrets or [] if tab == 'secrets' else audit_log or [] if tab == 'audit' else tokens or []
        if total is None:
            total = len(rows)
        fo = [project, {'w': can_write}, {'a': can_admin}, {'r': team_role}]
        if tab in ('secrets', 'audit'):
            fo.append({'n': total})
        if tab == 'secrets':
            fo.append({'a': can_admin})
        fo.append({'n': pending_count})
        if tab == 'settings':
            fa = [[]]
        elif tab == 'secrets':
            fa = [rows, [], [], []]
        elif tab == 'access':
            fa = [access_requests or []]
        else:
            fa = [rows] if tab in ('audit', 'tokens') else []
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        cur.fetchall.side_effect = fa if fa else [[]]
        return conn

    def test_project_detail(self):
        with patch.object(db, 'as_user', return_value=self._project_conn()):
            r = self.client.get(f'/projects/{self.pid}')
        assert r.status_code == 200
        assert b'prod' in r.data
        assert b'Secrets' in r.data
        assert b'>Access<' in r.data
        assert b'Audit log' in r.data

    def test_project_access_tab(self):
        reqs = [{'id': uuid4(), 'secret_id': uuid4(), 'secret_key': 'API_KEY', 'user_id': self.uid, 'email': 'u@ex.com', 'name': 'User', 'status': 'pending', 'reason': 'debug prod', 'created_at': '2026-01-01', 'resolved_at': None, 'approved_until': None, 'resolver_email': ''}]
        with patch.object(db, 'as_user', return_value=self._project_conn(tab='access', access_requests=reqs, pending_count=1)):
            r = self.client.get(f'/projects/{self.pid}?tab=access')
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

    def test_project_404(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{uuid4()}')
        assert r.status_code == 404

    def test_delete_project_route_owner_ok(self):
        tid = uuid4()
        conn, cur = _conn(fetchone={'team_id': tid, 'r': 'owner'})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/delete', follow_redirects=False)
        assert r.status_code == 302
        assert str(tid) in r.location
        conn.commit.assert_called()

    def test_delete_project_route_viewer_denied(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={'team_id': tid, 'r': 'viewer'})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/delete', follow_redirects=False)
        assert r.status_code == 302
        assert str(self.pid) in r.location
        conn.commit.assert_not_called()

    def test_project_settings_tab_shows_members_and_delete_for_owner(self):
        with patch.object(db, 'as_user', return_value=self._project_conn(tab='settings', team_role='owner')):
            r = self.client.get(f'/projects/{self.pid}?tab=settings')
        assert r.status_code == 200
        assert b'Members' in r.data
        assert b'Danger zone' in r.data
        assert b'Delete project' in r.data
        assert b'Settings' in r.data
        assert b'Project settings' not in r.data

    def test_project_settings_hidden_for_writer_without_admin(self):
        """Project write without admin cannot manage members; Settings tab hidden."""
        with patch.object(db, 'as_user', return_value=self._project_conn(team_role='member', can_write=True, can_admin=False)):
            r = self.client.get(f'/projects/{self.pid}')
        assert r.status_code == 200
        assert b'?tab=settings' not in r.data
        assert b'Delete project' not in r.data

    def test_project_settings_tab_hidden_for_viewer(self):
        with patch.object(db, 'as_user', return_value=self._project_conn(team_role='viewer', can_write=False, can_admin=False)):
            r = self.client.get(f'/projects/{self.pid}')
        assert r.status_code == 200
        assert b'?tab=settings' not in r.data
        assert b'Delete project' not in r.data

    def test_project_admin_settings_members_without_delete(self):
        """Project admin can manage members; team member cannot delete project."""
        with patch.object(db, 'as_user', return_value=self._project_conn(tab='settings', team_role='member', can_write=True, can_admin=True)):
            r = self.client.get(f'/projects/{self.pid}?tab=settings')
        assert r.status_code == 200
        assert b'Members' in r.data
        assert b'Delete project' not in r.data

    def test_project_secrets_tab_no_danger_zone(self):
        with patch.object(db, 'as_user', return_value=self._project_conn(team_role='owner')):
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
        cur.fetchone.side_effect = [{'id': sid, 'key': 'API_KEY', 'value_enc': enc, 'expires_at': None}, {'ok': True}, {'a': True}, {'w': True}]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/reveal', headers={'HX-Request': 'true'})
        assert r.status_code == 200
        assert b'super-secret' in r.data
        assert b'Save' in r.data
        assert b'/value' in r.data
        assert b'Copy' in r.data
        assert b'Open full view' in r.data
        assert b'>Hide</a>' in r.data
        assert b'/hide' in r.data
        assert b'name="expires_at"' not in r.data

    def test_reveal_secret_requires_access_request(self):
        sid = uuid4()
        enc = crypto.encrypt('super-secret')
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'id': sid, 'key': 'API_KEY', 'value_enc': enc, 'expires_at': None}, {'ok': True}, {'a': False}, {'r': True}, None]
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
        cur.fetchone.side_effect = [{'id': sid, 'key': 'FEATURE_FLAG', 'value_enc': enc, 'expires_at': None}, {'ok': True}, {'a': False}, {'r': False}, {'w': False}]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/reveal', headers={'HX-Request': 'true'})
        assert r.status_code == 200
        assert b'open-secret' in r.data

    def test_reveal_secret_with_approved_grant(self):
        sid = uuid4()
        enc = crypto.encrypt('granted-secret')
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'id': sid, 'key': 'API_KEY', 'value_enc': enc, 'expires_at': None}, {'ok': True}, {'a': False}, {'r': True}, {'id': uuid4(), 'status': 'approved', 'approved_until': '2099-01-01', 'created_at': '2026-01-01', 'reason': ''}, {'w': False}]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/reveal', headers={'HX-Request': 'true'})
        assert r.status_code == 200
        assert b'granted-secret' in r.data

    def test_request_secret_access(self):
        sid = uuid4()
        conn, cur = _conn()
        created = {'id': uuid4(), 'status': 'pending', 'created_at': '2026-01-01', 'reason': 'need it'}
        cur.fetchone.side_effect = [{'id': sid, 'key': 'API_KEY'}, {'a': False}, {'r': True}, None, created]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/secrets/{sid}/access-request', data={'reason': 'need it', 'dialog': '1'}, headers={'HX-Request': 'true'})
        assert r.status_code == 200
        assert b'Request submitted' in r.data
        assert b'Waiting' in r.data
        conn.commit.assert_called()
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
        assert 'secret_access_requests' in sql
        audit_args = ' '.join((str(c.args) for c in cur.execute.call_args_list if c.args))
        assert 'access_requested' in audit_args

    def test_approve_secret_access(self):
        rid, sid = (uuid4(), uuid4())
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'a': True}, {'id': rid, 'secret_id': sid, 'user_id': self.uid, 'status': 'pending', 'secret_key': 'API_KEY'}]
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/access-requests/{rid}/approve', data={'minutes': '15'}, follow_redirects=False)
        assert r.status_code == 302
        assert 'tab=access' in r.location
        conn.commit.assert_called()
        all_args = ' '.join((str(c.args) for c in cur.execute.call_args_list if c.args))
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
        assert 'tab=access' in r.location
        conn.commit.assert_called()
        all_args = ' '.join((str(c.args) for c in cur.execute.call_args_list if c.args))
        assert 'denied' in all_args
        assert 'access_denied' in all_args

    def test_hide_secret(self):
        sid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = str(uuid4())
        r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/hide', headers={'HX-Request': 'true'})
        assert r.status_code == 200
        assert b'*******' in r.data
        assert b'>Reveal</a>' in r.data
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
        assert b'>Reveal</a>' in r.data
        conn.commit.assert_called()
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
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

class TestTokens:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'u@ex.com'

    def test_create_token(self):
        conn, cur = _conn(fetchone={'w': True})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/tokens', data={'name': 'openshift'}, follow_redirects=False)
        assert r.status_code == 302
        with self.client.session_transaction() as s:
            assert s.get('new_token', '').startswith('ss_')
        sql = ' '.join((str(c) for c in cur.execute.call_args_list))
        assert 'read-only' in sql

    def test_create_token_write_role(self):
        conn, cur = _conn(fetchone={'w': True})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/tokens', data={'name': 'ci-writer', 'role': 'write'}, follow_redirects=False)
        assert r.status_code == 302
        insert_calls = [c for c in cur.execute.call_args_list if c.args and 'INSERT INTO api.machine_tokens' in str(c.args[0])]
        assert insert_calls
        assert insert_calls[0].args[1][4] == 'write'

    def test_create_token_invalid_role_defaults_read_only(self):
        conn, cur = _conn(fetchone={'w': True})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/tokens', data={'name': 'x', 'role': 'owner'}, follow_redirects=False)
        assert r.status_code == 302
        insert_calls = [c for c in cur.execute.call_args_list if c.args and 'INSERT INTO api.machine_tokens' in str(c.args[0])]
        assert insert_calls[0].args[1][4] == 'read-only'

    def test_create_token_read_only_denied(self):
        conn, _ = _conn(fetchone={'w': False})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/tokens', data={'name': 'openshift'}, follow_redirects=False)
        assert r.status_code == 302
        conn.commit.assert_not_called()
        with self.client.session_transaction() as s:
            assert 'new_token' not in s
            flashes = s.get('_flashes') or []
        assert any(('permission' in msg.lower() for _cat, msg in flashes))

    def test_delete_token(self):
        conn, cur = _conn(fetchone={'w': True})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/tokens/{uuid4()}/delete', follow_redirects=False)
        assert r.status_code == 302

    def test_delete_token_read_only_denied(self):
        conn, _ = _conn(fetchone={'w': False})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/tokens/{uuid4()}/delete', follow_redirects=False)
        assert r.status_code == 302
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('permission' in msg.lower() for _cat, msg in flashes))

    def test_mt_select_policy_allows_readers(self):
        """Read-only may list tokens; only writers insert/delete."""
        from pathlib import Path
        init_sql = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        sel_start = init_sql.index('CREATE POLICY mt_select ON api.machine_tokens')
        sel_end = init_sql.index(';', sel_start)
        assert 'can_read_project' in init_sql[sel_start:sel_end]
        ins_start = init_sql.index('CREATE POLICY mt_insert ON api.machine_tokens')
        ins_end = init_sql.index(';', ins_start)
        assert 'can_write_project' in init_sql[ins_start:ins_end]

    def test_pm_policies_use_can_admin_project(self):
        """Member management requires project admin, not mere write."""
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        init_sql = (root / 'db' / 'init.sql').read_text()
        schema_src = (root / 'app' / 'schema.py').read_text()
        for name in ('pm_insert', 'pm_update', 'pm_delete'):
            start = init_sql.index(f'CREATE POLICY {name} ON api.project_members')
            end = init_sql.index(';', start)
            chunk = init_sql[start:end]
            assert 'can_admin_project' in chunk, name
            assert 'can_write_project' not in chunk, name
        assert 'can_admin_project' in schema_src
        assert 'pm_insert ON api.project_members' in schema_src
        assert 'pm_delete ON api.project_members' in schema_src

    def test_can_write_project_team_admin_floor(self):
        """Team owner/admin keep write; project role elevates; team members inherit write."""
        from pathlib import Path
        init_sql = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        start = init_sql.index('CREATE OR REPLACE FUNCTION api.can_write_project')
        end = init_sql.index('$$;', start) + 3
        body = init_sql[start:end]
        assert "api.team_role" in body
        assert "IN ('owner', 'admin')" in body
        assert "api.project_role(pid) IN ('admin', 'write')" in body
        assert "api.team_role((SELECT team_id FROM api.projects WHERE id = pid)) = 'member'" in body

    def test_can_read_project_most_specific_wins(self):
        """Any project role or team membership grants read (helpers, not inline NOT EXISTS)."""
        from pathlib import Path
        init_sql = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        start = init_sql.index('CREATE OR REPLACE FUNCTION api.can_read_project')
        end = init_sql.index('$$;', start) + 3
        body = init_sql[start:end]
        assert 'api.project_role(pid) IS NOT NULL' in body
        assert 'api.is_team_member' in body
        assert 'FROM api.projects p' in body

    def test_can_admin_project_defined(self):
        from pathlib import Path
        init_sql = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        assert 'CREATE OR REPLACE FUNCTION api.can_admin_project' in init_sql
        start = init_sql.index('CREATE OR REPLACE FUNCTION api.can_admin_project')
        end = init_sql.index('$$;', start) + 3
        body = init_sql[start:end]
        assert "api.project_role(pid) = 'admin'" in body
        assert "api.team_role" in body
        assert "IN ('owner', 'admin')" in body

    def test_add_project_member_requires_admin(self):
        """Project write members cannot add project members."""
        conn, cur = _conn(fetchone={'a': False})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/members', data={'email': 'x@ex.com', 'role': 'read'}, follow_redirects=False)
        assert r.status_code == 302
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list)).lower()
        assert 'can_admin_project' in sql
        assert 'insert into api.project_members' not in sql
        with self.client.session_transaction() as s:
            flashes = s.get('_flashes') or []
        assert any(('permission' in msg.lower() for _c, msg in flashes))

    def test_add_project_member_ok_for_admin(self):
        uid = uuid4()
        tid = uuid4()
        last = {'s': ''}

        def execute(sql, params=None):
            last['s'] = ' '.join(str(sql).lower().split())

        def fetchone():
            s = last['s']
            if 'can_admin_project' in s:
                return {'a': True}
            if 'lookup_user' in s:
                return {'id': uid}
            if 'from api.projects' in s and 'team_id' in s:
                return {'team_id': tid}
            if 'from api.project_members' in s and 'select role' in s:
                return None
            return None
        conn, cur = _conn(fetchone=fetchone)
        cur.execute.side_effect = execute
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/members', data={'email': 'x@ex.com', 'role': 'write'}, follow_redirects=False)
        assert r.status_code == 302
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list)).lower()
        assert 'insert into api.project_members' in sql
        assert 'can_admin_project' in sql

    def test_remove_project_member_requires_admin(self):
        conn, cur = _conn(fetchone={'a': False})
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/projects/{self.pid}/members/{uuid4()}/remove', follow_redirects=False)
        assert r.status_code == 302
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list)).lower()
        assert 'can_admin_project' in sql
        assert 'delete from api.project_members' not in sql

    def test_secrets_updated_at_trigger_defined(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        init_sql = (root / 'db' / 'init.sql').read_text()
        assert 'CREATE TRIGGER secrets_touch_updated_at' in init_sql
        assert 'api.touch_updated_at' in init_sql
        routes = (Path(__file__).resolve().parent / 'routes' / 'projects.py').read_text()
        assert 'updated_at = now()' not in routes
        assert 'updated_at=now()' not in routes

    def test_secret_versions_schema(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        init = (root / 'db' / 'init.sql').read_text()
        assert 'CREATE TABLE api.secret_versions' in init
        assert 'archive_secret_version' in init
        assert 'expires_at' in init
        assert 'rotate_days' not in init
        src = Path(schema_mod.__file__).read_text()
        assert 'api.secret_versions' in src
        assert 'archive_secret_version' in src
        assert 'rotate_days' not in src

    def test_token_prefix_unique_constraint(self):
        from pathlib import Path
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        assert 'token_prefix text NOT NULL UNIQUE' in init
        src = Path(schema_mod.__file__).read_text()
        assert 'machine_tokens_token_prefix_key' in src
        assert 'personal_access_tokens' in src

    def test_init_sql_allows_oidc_auth_source(self):
        from pathlib import Path
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        assert "'local', 'ldap', 'oidc'" in init
        assert 'upsert_oidc_user' in init
        assert 'team_oidc_maps' in init
        assert 'oidc_role_maps' in init
        assert "source IN ('manual', 'ldap', 'oidc')" in init
        src = Path(schema_mod.__file__).read_text()
        assert 'users_auth_source_check' in src
        assert 'team_members_source_check' in src

class TestOrgAccess:
    """Project members, invites, org audit schema (no live DB)."""

    def test_schema_has_invites_and_org_audit(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        init = (root / 'db' / 'init.sql').read_text()
        assert 'CREATE TABLE api.team_invites' in init
        assert 'CREATE TABLE api.team_join_requests' in init
        assert 'CREATE TABLE api.org_audit' in init
        assert 'guard_last_team_owner' in init
        assert 'NOT EXISTS (SELECT 1 FROM api.teams WHERE id = OLD.team_id)' in init
        assert 'NOT EXISTS (SELECT 1 FROM api.teams WHERE id = OLD.team_id)' in Path(schema_mod.__file__).read_text()
        assert 'private.project_member_rows' in init
        assert 'private.audit_org' in init
        assert 'default_token_days' in init
        assert "'exported'" in init
        assert 'CREATE TABLE api.secret_access_requests' in init
        assert 'api.can_reveal_secret' in init
        assert 'api.secret_requires_approval' in init
        assert 'require_reveal_approval' in init
        assert 'private.secret_access_request_rows' in init
        assert 'access_requested' in init
        src = Path(schema_mod.__file__).read_text()
        assert 'api.team_invites' in src
        assert 'private.audit_org' in src
        assert 'exported' in src
        assert 'secret_access_requests' in src
        assert 'can_reveal_secret' in src
        assert 'secret_requires_approval' in src
        assert 'require_reveal_approval' in src
        assert 'access_approved' in src

    def test_log_org_calls_fn(self):
        cur = MagicMock()
        with store.app.test_request_context('/'):
            from flask import session
            session['email'] = 'a@b.c'
            audit.log_org(cur, team_id=uuid4(), action=audit.ORG_MEMBER_ADD, detail='x')
        sql = cur.execute.call_args.args[0]
        assert 'private.audit_org' in sql

    def test_project_roles_config(self):
        assert 'write' in config.PROJECT_ROLES
        assert 'member' in config.INVITE_ROLES
        assert 'owner' not in config.INVITE_ROLES

    def test_secret_meta_schema(self):
        from pathlib import Path
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        assert 'CREATE TABLE api.secret_meta' in init
        assert 'last_accessed_at' in init
        assert 'last_accessed_by' in init
        assert 'private.secret_meta_rows' in init
        assert 'private.touch_secret_access' in init
        src = Path(schema_mod.__file__).read_text()
        assert 'secret_meta' in src
        assert 'touch_secret_access' in src
        routes = (Path(__file__).resolve().parent / 'routes' / 'secrets.py').read_text()
        assert routes.count('touch_secret_access') >= 2
        ops = (Path(__file__).resolve().parent / 'secret_ops.py').read_text()
        assert 'secret_meta' in ops

    def test_machine_token_scope_schema(self):
        """Per-token key allow-list (exact + glob) is in schema and helpers."""
        from pathlib import Path
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        src = Path(schema_mod.__file__).read_text()
        assert 'CREATE TABLE api.machine_token_scope' in init
        assert 'machine_token_scope' in src
        assert 'private.machine_key_allowed' in init
        assert 'private.glob_to_like' in init
        assert 'machine_key_allowed' in src
        from routes.project_tokens import parse_token_scope_lines
        pairs = parse_token_scope_lines('API_KEY\n# comment\nprod/*\nDB_?\n')
        assert pairs == [('key', 'API_KEY'), ('pattern', 'prod/*'), ('pattern', 'DB_?')]

    def test_security_hardening_policies(self):
        """H1/M1/L1/L2/L5: projects_update, owner assignment, versions, ACL team, FORCE RLS."""
        from pathlib import Path
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        src = Path(schema_mod.__file__).read_text()
        assert 'USING (api.can_admin_project(id))' in init
        assert 'USING (api.can_admin_project(id))' in src
        assert "role IS DISTINCT FROM 'owner'" in init
        assert "role IS DISTINCT FROM 'owner'" in src
        assert 'CREATE POLICY secret_versions_insert ON api.secret_versions FOR INSERT' not in init
        assert 'REVOKE INSERT, UPDATE, DELETE ON api.secret_versions FROM authenticated' in init
        assert 'SECURITY DEFINER' in init.split('archive_secret_version')[1][:400]
        assert 'REVOKE INSERT, UPDATE, DELETE ON api.secret_versions' in src
        assert 'g.team_id = p.team_id' in init
        assert 'g.team_id = p.team_id' in src
        assert 'FORCE ROW LEVEL SECURITY' in init
        assert 'FORCE ROW LEVEL SECURITY' in src

    def test_secret_acl_schema_and_config(self):
        from pathlib import Path
        assert 'owners' in config.SECRET_ACL_MODES
        assert 'reveal' in config.SECRET_ACL_PERMISSIONS
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        assert 'acl_mode' in init
        assert 'CREATE TABLE api.secret_acl' in init
        assert 'api.can_access_secret' in init
        assert 'api.can_access_secret_row' in init
        assert 'api._perm_rank' in init
        assert "can_access_secret_row(id, project_id, acl_mode, 'read', deleted_at)" in init
        rev = init[init.index('FUNCTION api.can_reveal_secret'):]
        rev = rev[:rev.index('$$;') + 3]
        assert "can_access_secret(sid, 'reveal')" in rev
        src = Path(schema_mod.__file__).read_text()
        assert 'can_access_secret' in src
        assert 'can_access_secret_row' in src
        assert 'secret_acl' in src
        assert "NOT api.can_access_secret(sid, 'reveal')" in src

    def test_can_access_secret_row_modes_in_sql(self):
        """ACL mode branches exist for inherit/writers/admins/owners/custom."""
        from pathlib import Path
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        start = init.index('FUNCTION api.can_access_secret_row')
        body = init[start:start + 2500]
        for mode in ('inherit', 'writers', 'admins', 'owners', 'custom'):
            assert mode in body, f'mode {mode} missing from can_access_secret_row'
        for need in ("'read'", "'reveal'", "'write'"):
            assert need in body
        assert 'group_members' in body
        assert '_perm_rank' in body

    def test_export_filters_reveal_permission(self):
        """Plain export SQL must filter by can_access_secret reveal + can_reveal."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent / 'routes' / 'project_io.py').read_text()
        assert "can_access_secret(id, 'reveal')" in src
        assert 'can_reveal_secret(id)' in src
        bulk = src[src.index('def bulk_export'):]
        assert "can_access_secret(id, 'reveal')" in bulk

    def test_acl_management_routes_exist(self):
        """Secret ACL mode/grant routes registered and gated to admins."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent / 'routes' / 'secrets.py').read_text()
        assert 'def update_secret_acl_mode' in src
        assert 'def add_secret_acl_grant' in src
        assert 'def delete_secret_acl_grant' in src
        assert 'can_admin_project' in src
        assert 'tab="access"' in src

    def test_eso_pat_checks_acl_before_reveal(self):
        """ESO/PAT get-secret must check can_access_secret reveal before approval."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent / 'routes' / 'eso.py').read_text()
        i_acl = src.index("can_access_secret(%s, 'reveal')")
        i_rev = src.index('can_reveal_secret(%s)')
        assert i_acl < i_rev
        assert '"error": "forbidden"' in src
        assert '"error": "approval_required"' in src

    def test_eso_pat_bulk_export_filters_reveal_acl(self):
        """PAT bulk list-with-values must filter by can_access_secret(reveal)."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent / 'routes' / 'eso.py').read_text()
        start = src.index('def eso_list_secrets')
        body = src[start:start + 8000]
        assert 'cli/values' in body
        assert "can_access_secret(id, 'reveal')" in body
        assert 'can_reveal_secret(id)' in body
        assert not re.search('SELECT key, value_enc FROM api\\.secrets\\s+WHERE project_id = %s AND deleted_at IS NULL\\s*\\"\\"\\"', body)

    def test_group_team_role_cannot_be_owner(self):
        """Groups must not grant team owner (admin max)."""
        assert 'owner' not in config.GROUP_TEAM_ROLES
        assert 'admin' in config.GROUP_TEAM_ROLES
        from pathlib import Path
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        assert "team_role IN ('admin', 'member', 'viewer')" in init
        assert "team_role IN ('owner', 'admin', 'member', 'viewer')" not in init[init.index('CREATE TABLE api.groups'):init.index('CREATE TABLE api.group_members')]

    def test_can_access_secret_row_behavioral_matrix(self):
        """Expected outcomes for can_access_secret_row (mirrors SQL CASE).

        Pure-Python stand-in of the SECURITY DEFINER helper so we can assert
        mode × need without a live Postgres. Keep in sync with init.sql.
        """
        perm_rank = {'read': 1, 'reveal': 2, 'write': 3}

        def row_access(*, mode, need, deleted=False, can_read=True, can_write=False, can_admin=False, is_global=False, team_role=None, grants=None):
            if deleted or not need or need not in perm_rank:
                return False
            if not can_read and (not is_global):
                return False
            if is_global or can_admin:
                return True
            mode = mode or 'inherit'
            if mode == 'inherit':
                return can_write if need == 'write' else True
            if mode == 'writers':
                return can_write
            if mode == 'admins':
                return False
            if mode == 'owners':
                return team_role == 'owner'
            if mode == 'custom':
                grants = grants or []
                need_r = perm_rank[need]
                return any((perm_rank.get(g, 0) >= need_r for g in grants))
            return False
        assert row_access(mode='inherit', need='read', can_read=True)
        assert row_access(mode='inherit', need='reveal', can_read=True)
        assert not row_access(mode='inherit', need='write', can_read=True, can_write=False)
        assert row_access(mode='inherit', need='write', can_read=True, can_write=True)
        assert not row_access(mode='writers', need='read', can_read=True, can_write=False)
        assert row_access(mode='writers', need='read', can_read=True, can_write=True)
        assert not row_access(mode='admins', need='reveal', can_read=True, can_write=True)
        assert row_access(mode='admins', need='reveal', can_admin=True)
        assert not row_access(mode='owners', need='read', can_read=True, team_role='admin')
        assert row_access(mode='owners', need='read', can_read=True, team_role='owner')
        assert not row_access(mode='custom', need='reveal', can_read=True, grants=['read'])
        assert row_access(mode='custom', need='reveal', can_read=True, grants=['reveal'])
        assert row_access(mode='custom', need='read', can_read=True, grants=['write'])
        assert not row_access(mode='custom', need='write', can_read=True, grants=['reveal'])
        assert not row_access(mode='inherit', need='read', deleted=True)
        assert not row_access(mode='inherit', need='read', can_read=False)

    def test_org_groups_rbac_schema(self):
        """Groups tables, group-aware RBAC helpers, secret ACL group grants."""
        from pathlib import Path
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        assert 'CREATE TABLE api.groups' in init
        assert 'CREATE TABLE api.group_members' in init
        assert 'CREATE TABLE api.project_group_roles' in init
        assert 'external_key' in init
        assert 'api.project_role' in init
        assert 'api._role_rank' in init
        assert 'group_id' in init
        assert 'group_members gm' in init
        assert 'g.team_role IS NOT NULL' in init
        src = Path(schema_mod.__file__).read_text()
        assert 'CREATE TABLE IF NOT EXISTS api.groups' in src
        assert 'project_group_roles' in src
        assert 'team_group_rows' in src
        assert 'secret_acl_principal_check' in src
        teams_src = (Path(__file__).resolve().parent / 'routes' / 'teams.py').read_text()
        assert 'create_team_group' in teams_src
        assert 'apply_group_membership_maps' in Path(Path(__file__).resolve().parent / 'ldap_auth.py').read_text()
        seed = (Path(__file__).resolve().parents[1] / 'scripts' / 'seed_mock.py').read_text()
        assert 'GROUPS' in seed
        assert 'PROJECT_GROUP_ROLES' in seed

    def test_dir_sync_group_membership_maps(self):
        """Directory sync upserts/removes group_members for external_key matches."""
        from unittest.mock import MagicMock
        import dir_sync
        uid = str(uuid4())
        gid_match = str(uuid4())
        gid_other = str(uuid4())
        cur = MagicMock()
        cur.fetchall.return_value = [{'id': gid_match, 'external_key': 'cn=ops,ou=groups'}, {'id': gid_other, 'external_key': 'cn=other,ou=groups'}]
        cur.fetchone.return_value = None
        dir_sync.apply_group_membership_maps(cur, uid, ['cn=ops,ou=groups', 'cn=unrelated'], source='ldap')
        executed = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list)).lower()
        assert 'delete from api.group_members' in executed
        assert 'insert into api.group_members' in executed
        insert_calls = [c for c in cur.execute.call_args_list if 'INSERT INTO api.group_members' in str(c.args[0])]
        assert len(insert_calls) == 1
        assert insert_calls[0].args[1][0] == gid_match

    def test_members_tab_requires_login(self):
        r = store.app.test_client().get(f'/projects/{uuid4()}?tab=settings')
        assert r.status_code == 302

    def test_invite_redeem_requires_login(self):
        c = store.app.test_client()
        r = c.get('/invite/not-a-real-token')
        assert r.status_code == 302
        assert '/login' in (r.location or '')
        with c.session_transaction() as s:
            assert s.get('invite_token') == 'not-a-real-token'

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
        import secret_kinds as sk
        assert sk.detect_secret_kind('secret', 'type:ssh') == 'plain'
        assert sk.detect_secret_kind('postgresql://u:p@h/db') == 'database'
        assert sk.kind_from_legacy_note('prod (type:ssh)') == 'ssh'
        assert sk.strip_legacy_type_tags('prod (type:ssh)') == 'prod'
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
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
        assert 'audit_secret' in sql
        assert 'exported' in str(cur.execute.call_args_list)

    def test_import_preview(self):
        conn, cur = _conn()
        cur.fetchone.side_effect = [{'w': True}, {'name': 'prod', 'id': self.pid, 'team_name': 'T'}]
        cur.fetchall.return_value = [{'key': 'EXISTING'}]
        with patch.object(db, 'as_user', return_value=conn), patch('nav.nav_teams', return_value=[]):
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
        cur.fetchone.side_effect = [{'value_enc': enc, 'key': 'K', 'secret_id': sid}, {'a': True}]
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.get(f'/projects/{self.pid}/secrets/{sid}/versions/{vid}/reveal')
        assert r.status_code == 200
        assert b'prior-secret' in r.data

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

    def test_upsert_read_only_forbidden(self):
        fo = [{'ok': True}, {'role': 'read-only'}]
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        with patch.object(db, 'connect', return_value=conn):
            r = self.client.post(f'/eso/v1/projects/{self.pid}/secrets', json={'key': 'K', 'value': 'v'}, headers={'Authorization': 'Bearer ss_ro'})
        assert r.status_code == 403
        assert 'read-only' in r.get_json()['error']
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

    def test_delete_read_only_forbidden(self):
        fo = [{'ok': True}, {'role': 'read-only'}]
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

    def test_create_token_with_expiry(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s['user_id'] = str(uuid4())
            s['email'] = 'u@ex.com'
        conn, cur = _conn(fetchone={'w': True})
        cur.rowcount = 1
        with patch.object(db, 'as_user', return_value=conn):
            r = c.post(f'/projects/{self.pid}/tokens', data={'name': 'eso', 'role': 'read-only', 'expires_days': '30'}, follow_redirects=False)
        assert r.status_code == 302
        insert = [c for c in cur.execute.call_args_list if c.args and 'INSERT INTO api.machine_tokens' in str(c.args[0])][0]
        assert insert.args[1][5] is not None

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
        with patch.object(db, 'as_user', return_value=conn):
            r = c.post(f'/projects/{self.pid}/tokens', data={'name': 'eso', 'role': 'read-only', 'expires_days': str(config.MAX_EXPIRY_DAYS + 1)}, follow_redirects=False)
        assert r.status_code == 302
        inserts = [c for c in cur.execute.call_args_list if c.args and 'INSERT INTO api.machine_tokens' in str(c.args[0])]
        assert inserts == []

    def test_machine_token_roles_config(self):
        assert 'read-only' in config.MACHINE_TOKEN_ROLES
        assert 'write' in config.MACHINE_TOKEN_ROLES
        assert config.MAX_EXPIRY_DAYS == 3650
        assert config.MAX_CONTENT_LENGTH >= 64 * 1024
        assert store.app.config.get('MAX_CONTENT_LENGTH') == config.MAX_CONTENT_LENGTH

    def test_parse_expires_at_capped(self):
        from secret_ops import _parse_expires_at
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

class TestHealth:

    def test_ok(self):
        conn, _ = _conn()
        with patch.object(db, 'connect', return_value=conn):
            r = store.app.test_client().get('/health')
        assert r.status_code == 200
        assert r.get_json()['ok']

    def test_down(self):
        with patch.object(db, 'connect', side_effect=RuntimeError('db down')):
            r = store.app.test_client().get('/health')
        assert r.status_code == 503
        data = r.get_json()
        assert not data['ok']
        assert 'error' not in data

    def test_security_headers(self):
        conn, _ = _conn()
        with patch.object(db, 'connect', return_value=conn):
            r = store.app.test_client().get('/health')
        assert r.headers.get('X-Content-Type-Options') == 'nosniff'
        assert r.headers.get('X-Frame-Options') == 'DENY'
        assert r.headers.get('Referrer-Policy') == 'no-referrer'
        csp = r.headers.get('Content-Security-Policy', '')
        assert 'unpkg.com' in csp
        assert "frame-ancestors 'none'" in csp
        assert 'Strict-Transport-Security' not in r.headers

    def test_hsts_when_cookie_secure(self):
        conn, _ = _conn()
        with patch.object(db, 'connect', return_value=conn), patch.dict(os.environ, {'COOKIE_SECURE': '1'}, clear=False):
            r = store.app.test_client().get('/health')
        assert 'Strict-Transport-Security' in r.headers

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
        conn, _ = _conn(fetchone=fetchone, fetchall=[{'id': sid, 'key': 'DB_URL', 'note': '', 'kind': 'plain', 'updated_at': 'now', 'expires_at': None, 'acl_mode': 'inherit', 'project_id': pid, 'project_name': 'api'}, {'id': pid, 'name': 'api'}])
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
        assert 'Delete forever — this cannot be undone'.encode() in r.data
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

class TestTotp:

    def test_verify_code_window(self):
        import totp_svc
        import pyotp
        secret = pyotp.random_base32()
        code = pyotp.TOTP(secret).now()
        assert totp_svc.verify_code(secret, code)
        assert not totp_svc.verify_code(secret, '000000')
        assert not totp_svc.verify_code(secret, 'abcdef')

    def test_recovery_code_hash_roundtrip(self):
        import totp_svc
        codes = totp_svc.generate_recovery_codes(3)
        assert len(codes) == 3
        assert re.search('^([a-f0-9]{4}-){7}[a-f0-9]{4}$', codes[0])
        h = totp_svc.hash_recovery_code(codes[0])
        assert h == totp_svc.hash_recovery_code(codes[0].upper().replace('-', ''))
        assert totp_svc.recovery_hash_matches(codes[0], h)
        legacy = totp_svc._legacy_hash_recovery_code(codes[0])
        assert totp_svc.recovery_hash_matches(codes[0], legacy)

    def test_needs_challenge(self):
        import totp_svc
        uid = str(uuid4())
        with patch.object(totp_svc, 'is_enabled', return_value=True):
            assert totp_svc.needs_challenge(uid, False) == 'verify'
        with patch.object(totp_svc, 'is_enabled', return_value=False), patch.object(totp_svc, 'enforce_global_admins', return_value=True):
            assert totp_svc.needs_challenge(uid, True) == 'enroll'
            assert totp_svc.needs_challenge(uid, False) is None
        with patch.object(totp_svc, 'is_enabled', return_value=False), patch.object(totp_svc, 'enforce_global_admins', return_value=False):
            assert totp_svc.needs_challenge(uid, True) is None

    def test_user_totp_row_fails_closed(self):
        import totp_svc
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
        init = (Path(__file__).resolve().parents[1] / 'db' / 'init.sql').read_text()
        assert 'totp_secret_enc' in init
        assert 'totp_recovery_codes' in init
        assert 'totp_enforce_global_admins' in init

class TestMailer:

    def test_smtp_configured_requires_host_and_from(self):
        import mailer
        assert not mailer.smtp_configured({'smtp_enabled': 'true', 'smtp_host': '', 'smtp_from_email': 'a@b.c'})
        assert not mailer.smtp_configured({'smtp_enabled': 'false', 'smtp_host': 'h', 'smtp_from_email': 'a@b.c'})
        assert mailer.smtp_configured({'smtp_enabled': 'true', 'smtp_host': 'smtp.example.com', 'smtp_from_email': 'a@b.c'})

    def test_login_alerts_need_smtp(self):
        import mailer
        assert not mailer.login_alerts_enabled({'smtp_enabled': 'true', 'smtp_host': 'h', 'smtp_from_email': 'a@b.c', 'smtp_login_alerts': 'false'})
        assert mailer.login_alerts_enabled({'smtp_enabled': 'true', 'smtp_host': 'h', 'smtp_from_email': 'a@b.c', 'smtp_login_alerts': 'true'})

    def test_send_email_not_configured(self):
        import mailer
        ok, err = mailer.send_email('a@b.c', 'subj', 'body', cfg={'smtp_enabled': 'false', 'smtp_host': '', 'smtp_from_email': ''})
        assert not ok
        assert 'SMTP' in err

    def test_send_email_starttls(self):
        import mailer
        cfg = {'smtp_enabled': 'true', 'smtp_host': 'smtp.example.com', 'smtp_port': '587', 'smtp_encryption': 'starttls', 'smtp_username': 'u', 'smtp_password': '', 'smtp_from_email': 'from@ex.com', 'smtp_from_name': 'App'}
        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        with patch('mailer.smtplib.SMTP', return_value=mock_smtp) as SMTP:
            ok, err = mailer.send_email('to@ex.com', 'Hello', 'Body text', cfg=cfg)
        assert ok
        assert err == ''
        SMTP.assert_called_once()
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with('u', '')
        mock_smtp.send_message.assert_called_once()

    def test_forgot_password_sends_email(self):
        store.app.config['TESTING'] = True
        client = store.app.test_client()
        with patch('passwords.create_reset_token', return_value='tok123'), patch('mailer.smtp_configured', return_value=True), patch('mailer.send_password_reset', return_value=(True, '')) as send:
            r = client.post('/forgot-password', data={'email': 'user@ex.com'}, follow_redirects=False)
        assert r.status_code == 302
        send.assert_called_once()
        args = send.call_args[0]
        assert args[0] == 'user@ex.com'
        assert '/reset-password/tok123' in args[1]

    def test_login_sends_alert_when_enabled(self):
        store.app.config['TESTING'] = True
        client = store.app.test_client()
        uid = uuid4()
        conn, _ = _conn(fetchone={'id': uid, 'email': 'a@b.c', 'name': 'A'})
        with patch.object(db, 'connect', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch.object(settings_svc, 'setup_notice', return_value=None), patch.object(lockout, 'is_locked', return_value=False), patch.object(lockout, 'clear_failures'), patch.object(authz, 'is_global_admin', return_value=False), patch('totp_svc.needs_challenge', return_value=None), patch('mailer.login_alerts_enabled', return_value=True), patch('mailer.send_login_alert', return_value=(True, '')) as alert, patch.object(user_sessions, 'create_session', return_value=None):
            r = client.post('/login', data={'email': 'a@b.c', 'password': 'secret12'}, follow_redirects=False)
        assert r.status_code == 302
        alert.assert_called_once()
        assert alert.call_args[0][0] == 'a@b.c'

class TestLDAPHelpers:

    def test_group_tokens_cn(self):
        t = ldap_auth.group_tokens('CN=Admins,OU=Groups,DC=ex,DC=com')
        assert 'cn=admins,ou=groups,dc=ex,dc=com' in t
        assert 'admins' in t
        assert 'cn=admins' in t

    def test_group_matches_cn_or_dn(self):
        groups = ['CN=eng-secrets,OU=Groups,DC=ex,DC=com', 'other']
        assert ldap_auth.group_matches('eng-secrets', groups)
        assert ldap_auth.group_matches('CN=eng-secrets,OU=Groups,DC=ex,DC=com', groups)
        assert not ldap_auth.group_matches('nope', groups)

    def test_ldap_escape(self):
        assert ldap_auth.ldap_escape('a*b(c)') == 'a\\2ab\\28c\\29'

    def test_ldap_disabled_returns_none(self):
        with patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}):
            assert ldap_auth.ldap_authenticate('u', 'p') is None

class TestLDAPMaps:

    def setup_method(self, method=None):
        store.app.config['TESTING'] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        self.tid = uuid4()
        with self.client.session_transaction() as s:
            s['user_id'] = self.uid
            s['email'] = 'owner@ex.com'
            s['is_global_admin'] = False

    def test_add_team_ldap_map(self):
        conn, _ = _conn()
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{self.tid}/ldap-maps', data={'ldap_group': 'eng-secrets', 'role': 'member'}, follow_redirects=False)
        assert r.status_code == 302
        assert str(self.tid) in r.location

    def test_add_team_ldap_map_empty_group(self):
        r = self.client.post(f'/teams/{self.tid}/ldap-maps', data={'ldap_group': '  ', 'role': 'member'}, follow_redirects=False)
        assert r.status_code == 302

    def test_delete_team_ldap_map(self):
        mid = uuid4()
        conn, _ = _conn()
        with patch.object(db, 'as_user', return_value=conn):
            r = self.client.post(f'/teams/{self.tid}/ldap-maps/{mid}/delete', follow_redirects=False)
        assert r.status_code == 302

    def test_sync_ldap_user_applies_maps(self):
        uid = uuid4()
        tid = uuid4()
        # upsert id, then fetch_user_row at end
        fo = [
            {'id': uid},
            {
                'id': uid,
                'email': 'u@ex.com',
                'name': 'U',
                'is_global_admin': True,
            },
        ]
        # ldap role maps, team ldap maps, directory groups for membership maps
        fa = [
            [{'ldap_group': 'admins', 'role': 'global_admin'}],
            [
                {
                    'id': uuid4(),
                    'team_id': tid,
                    'ldap_group': 'admins',
                    'role': 'admin',
                }
            ],
            [],  # api.groups with external_key
        ]
        conn, cur = _conn()
        # cycle user row after first id so extra fetchones don't StopIteration
        def _fo():
            for row in fo:
                yield row
            while True:
                yield fo[-1]

        cur.fetchone.side_effect = _fo()
        cur.fetchall.side_effect = fa
        with patch.object(db, 'connect_admin', return_value=conn):
            user = ldap_auth.sync_ldap_user(
                'u@ex.com', 'U', ['CN=admins,OU=g,DC=x']
            )
        assert str(user['id']) == str(uid)
        assert user['is_global_admin']
        executed = ' '.join((str(c) for c in cur.execute.call_args_list)).lower()
        assert 'team_members' in executed
        assert 'upsert_ldap_user' in executed
