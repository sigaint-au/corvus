"""Unit tests per component. Mock DB — no Postgres required."""
import os
import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, patch
from uuid import uuid4

# Import-time env (app reads these at load)
os.environ.setdefault("DATABASE_URL", "postgres://test:test@localhost/test")
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
import paging  # noqa: E402
import schema as schema_mod  # noqa: E402
import settings_svc  # noqa: E402
import user_sessions  # noqa: E402
from routes import eso as eso_routes  # noqa: E402

# Skip real schema bootstrap (no Postgres in unit tests).
store.app.config["TESTING"] = True


# ── helpers ───────────────────────────────────────────────────────

_UNSET = object()


def _conn(fetchone=_UNSET, fetchall=_UNSET, side_effect=None):
    cur = MagicMock()
    if side_effect is not None:
        cur.execute.side_effect = side_effect
    if fetchone is not _UNSET:
        if callable(fetchone) and not isinstance(fetchone, dict):
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
    return conn, cur

# ── Crypto ─────────────────────────────────────────────────────────


class TestCrypto(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(crypto.decrypt(crypto.encrypt("ping")), "ping")

    def test_empty(self):
        self.assertEqual(crypto.decrypt(crypto.encrypt("")), "")

    def test_unicode(self):
        s = "héllo 🔐 日本語"
        self.assertEqual(crypto.decrypt(crypto.encrypt(s)), s)

    def test_ciphertext_differs(self):
        a, b = crypto.encrypt("x"), crypto.encrypt("x")
        self.assertNotEqual(a, b)  # Fernet includes random IV
        self.assertEqual(crypto.decrypt(a), crypto.decrypt(b))


# ── JWT ────────────────────────────────────────────────────────────


class TestJWT(unittest.TestCase):
    def test_make_jwt_claims(self):
        uid = str(uuid4())
        token = db.make_jwt(uid, hours=1)
        claims = pyjwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])
        self.assertEqual(claims["sub"], uid)
        self.assertEqual(claims["role"], "authenticated")
        self.assertIn("exp", claims)


# ── LDAP helpers ───────────────────────────────────────────────────


class TestLdapPassword(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(ldap_auth.ldap_password_plain({}), "")
        self.assertEqual(ldap_auth.ldap_password_plain({"ldap_bind_password": "  "}), "")

    def test_decrypts(self):
        enc = crypto.encrypt("bind-secret")
        self.assertEqual(
            ldap_auth.ldap_password_plain({"ldap_bind_password": enc}),
            "bind-secret",
        )

    def test_decrypt_failure_returns_empty_not_ciphertext(self):
        # Must not return the ciphertext (would be used as the bind password).
        bad = "not-valid-fernet-ciphertext"
        self.assertEqual(
            ldap_auth.ldap_password_plain({"ldap_bind_password": bad}),
            "",
        )


class TestLdapTlsPolicy(unittest.TestCase):
    def test_ldaps_ok_without_starttls(self):
        self.assertTrue(ldap_auth.ldap_tls_required_ok("ldaps://ipa.example.com", False))

    def test_ldap_requires_starttls(self):
        self.assertFalse(ldap_auth.ldap_tls_required_ok("ldap://ipa.example.com", False))
        self.assertTrue(ldap_auth.ldap_tls_required_ok("ldap://ipa.example.com", True))

    def test_empty_url_rejected(self):
        self.assertFalse(ldap_auth.ldap_tls_required_ok("", True))

    def test_authenticate_refuses_cleartext(self):
        with patch.object(
            ldap_auth,
            "ldap_cfg",
            return_value={
                "ldap_enabled": "true",
                "ldap_url": "ldap://ipa.example.com",
                "ldap_start_tls": "false",
                "ldap_user_base": "cn=users",
            },
        ):
            self.assertIsNone(ldap_auth.ldap_authenticate("user", "pass"))


class TestLdapStartTLS(unittest.TestCase):
    def test_open_start_tls_before_bind(self):
        order = []

        class FakeConn:
            def __init__(self, *a, **k):
                self.auto_bind = k.get("auto_bind", True)

            def open(self):
                order.append("open")
                return True

            def start_tls(self):
                order.append("start_tls")
                return True

            def bind(self):
                order.append("bind")
                return True

            def unbind(self):
                order.append("unbind")

        with patch.dict("sys.modules", {"ldap3": MagicMock()}):
            import ldap3 as ldap3_mod

            ldap3_mod.Connection = FakeConn
            conn = ldap_auth._ldap_bind(object(), user="cn=x", password="p", start_tls=True)
        self.assertEqual(order[:3], ["open", "start_tls", "bind"])
        self.assertFalse(conn.auto_bind)

    def test_start_tls_failure_fails_closed(self):
        bound = {"n": 0}

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
                bound["n"] += 1
                return True

        fake_mod = MagicMock()
        fake_mod.Connection = FakeConn
        with patch.dict("sys.modules", {"ldap3": fake_mod}):
            with self.assertRaises(RuntimeError) as cm:
                ldap_auth._ldap_bind(object(), start_tls=True)
        self.assertIn("StartTLS", str(cm.exception))
        self.assertEqual(bound["n"], 0)


# ── Schema ensure ──────────────────────────────────────────────────


class TestEnsureSchema(unittest.TestCase):
    def test_requires_admin_url(self):
        with patch.object(schema_mod, "DATABASE_ADMIN_URL", ""):
            with self.assertRaises(RuntimeError) as cm:
                schema_mod.ensure_schema()
        self.assertIn("DATABASE_ADMIN_URL", str(cm.exception))

    def test_uses_advisory_lock(self):
        conn, cur = _conn()
        with patch.object(schema_mod, "DATABASE_ADMIN_URL", "postgres://admin@x/db"), patch.object(
            db, "connect_admin", return_value=conn
        ), patch.object(schema_mod, "bootstrap_admin_email", return_value=""):
            schema_mod.ensure_schema()
        sqls = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        self.assertIn("pg_advisory_lock", sqls)
        self.assertIn("pg_advisory_unlock", sqls)


# ── Helpers ────────────────────────────────────────────────────────


class TestHelpers(unittest.TestCase):
    def test_htmx_false(self):
        with store.app.test_request_context("/"):
            self.assertFalse(authz.htmx())

    def test_htmx_true(self):
        with store.app.test_request_context("/", headers={"HX-Request": "true"}):
            self.assertTrue(authz.htmx())

    def test_login_required_redirects(self):
        @authz.login_required
        def protected():
            return "ok"

        with store.app.test_request_context("/x"):
            resp = protected()
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.location)

    def test_login_required_passes(self):
        c = store.app.test_client()
        with c.session_transaction() as sess:
            sess["user_id"] = str(uuid4())
            sess["email"] = "t@t.t"
        conn, _ = _conn(fetchall=[])
        with patch.object(db, "as_user", return_value=conn):
            r = c.get("/teams")
        self.assertEqual(r.status_code, 200)

    def test_safe_redirect_allows_relative(self):
        self.assertEqual(authz.safe_redirect_target("/teams", "/x"), "/teams")
        self.assertEqual(authz.safe_redirect_target(None, "/x"), "/x")

    def test_safe_redirect_blocks_open_redirect(self):
        self.assertEqual(authz.safe_redirect_target("//evil", "/x"), "/x")
        self.assertEqual(authz.safe_redirect_target("https://evil", "/x"), "/x")
        self.assertEqual(authz.safe_redirect_target("teams", "/x"), "/x")

    def test_page_window_basic(self):
        w = paging.page_window(100, 2, per_page=25)
        self.assertEqual(w["page"], 2)
        self.assertEqual(w["offset"], 25)
        self.assertEqual(w["pages"], 4)
        self.assertTrue(w["has_prev"])
        self.assertTrue(w["has_next"])

    def test_page_window_empty(self):
        w = paging.page_window(0, 1)
        self.assertEqual(w["pages"], 1)
        self.assertEqual(w["start"], 0)
        self.assertEqual(w["end"], 0)


class TestLockout(unittest.TestCase):
    def test_empty_email_not_locked(self):
        self.assertFalse(lockout.is_locked(""))
        self.assertFalse(lockout.is_locked("  "))

    def test_is_locked_when_at_threshold(self):
        conn, _ = _conn(fetchone={"n": lockout.MAX_ATTEMPTS})
        with patch.object(db, "connect_admin", return_value=conn):
            self.assertTrue(lockout.is_locked("a@b.c"))

    def test_not_locked_below_threshold(self):
        conn, _ = _conn(fetchone={"n": lockout.MAX_ATTEMPTS - 1})
        with patch.object(db, "connect_admin", return_value=conn):
            self.assertFalse(lockout.is_locked("a@b.c"))

    def test_db_error_fails_open(self):
        with patch.object(db, "connect_admin", side_effect=RuntimeError("db")):
            self.assertFalse(lockout.is_locked("a@b.c"))

    def test_record_and_clear(self):
        conn, cur = _conn()
        with patch.object(db, "connect_admin", return_value=conn):
            lockout.record_failure("A@B.C")
            lockout.clear_failures("A@B.C")
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list)
        self.assertIn("INSERT INTO private.login_failures", sql)
        self.assertIn("DELETE FROM private.login_failures", sql)
        # emails lowercased
        self.assertEqual(cur.execute.call_args_list[0].args[1], ("a@b.c",))


class TestRefuseInsecureDefaults(unittest.TestCase):
    def test_opt_in_allows(self):
        with patch.dict(os.environ, {"ALLOW_INSECURE_DEFAULTS": "1"}, clear=False):
            os.environ.pop("FLASK_ENV", None)
            config.refuse_insecure_defaults()  # must not raise

    def test_blocks_default_secrets(self):
        # Module-level SECRET_KEY etc. are fixed at import; force them to baked-ins.
        with patch.dict(os.environ, {"ALLOW_INSECURE_DEFAULTS": "0"}, clear=False), patch.object(
            config, "SECRET_KEY", config._DEFAULT_SECRET_KEY
        ), patch.object(config, "JWT_SECRET", config._DEFAULT_JWT_SECRET), patch.object(
            config, "MASTER_KEY", config._DEFAULT_MASTER_KEY
        ):
            os.environ.pop("FLASK_ENV", None)
            with self.assertRaises(SystemExit):
                config.refuse_insecure_defaults()


class TestAudit(unittest.TestCase):
    def test_describe_event_readable(self):
        s = audit.describe_event(
            {"actor_email": "a@b.c", "action": "revealed", "secret_key": "API_KEY"}
        )
        self.assertIn("a@b.c", s)
        self.assertIn("revealed", s)
        self.assertIn("API_KEY", s)

    def test_format_time_ago(self):
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        self.assertEqual(audit.format_time_ago(None), "—")
        self.assertEqual(audit.format_time_ago(now - timedelta(seconds=10)), "just now")
        self.assertEqual(audit.format_time_ago(now - timedelta(minutes=5)), "5 minutes ago")
        self.assertEqual(audit.format_time_ago(now - timedelta(hours=3)), "3 hours ago")
        self.assertEqual(audit.format_time_ago(now - timedelta(days=4)), "4 days ago")
        # Absolute remains available for tooltips
        abs_s = audit.format_when(now - timedelta(hours=1))
        self.assertIn("UTC", abs_s)

    def test_global_search_requires_login(self):
        r = store.app.test_client().get("/search?q=x")
        self.assertEqual(r.status_code, 302)

    def test_filter_clause_actor_action_dates(self):
        sql, params = audit._filter_clause(
            actor="bob", action="revealed", since="2026-01-01", until="2026-01-02"
        )
        self.assertIn("actor_email", sql)
        self.assertIn("action", sql)
        self.assertIn("created_at", sql)
        self.assertEqual(params[0], "%bob%")
        self.assertEqual(params[1], "revealed")

    def test_invalid_action_raises(self):
        cur = MagicMock()
        with store.app.test_request_context("/"):
            with self.assertRaises(ValueError):
                audit.log_secret(cur, project_id=uuid4(), action="nope")

    def test_log_secret_calls_audit_secret_fn(self):
        cur = MagicMock()
        pid, sid = uuid4(), uuid4()
        with store.app.test_request_context("/"):
            from flask import session

            session["user_id"] = str(uuid4())
            session["email"] = "a@b.c"
            audit.log_secret(
                cur, project_id=pid, secret_id=sid, secret_key="K", action="revealed"
            )
        self.assertEqual(cur.execute.call_count, 1)
        sql, params = cur.execute.call_args.args[0], cur.execute.call_args.args[1]
        self.assertIn("private.audit_secret", sql)
        self.assertIn("NULL::uuid", sql)
        self.assertNotIn("INSERT INTO api.secret_audit", sql)
        # actor email still passed; user_id is never supplied (JWT inside DB)
        self.assertEqual(params[-1], "a@b.c")

    def test_schema_revokes_secret_audit_insert(self):
        from pathlib import Path

        init = (Path(__file__).resolve().parents[1] / "db" / "init.sql").read_text()
        self.assertIn("REVOKE INSERT ON api.secret_audit FROM authenticated", init)
        self.assertIn("CREATE OR REPLACE FUNCTION private.audit_secret", init)
        self.assertIn("Never trust caller-supplied p_user_id", init)
        src = Path(schema_mod.__file__).read_text()
        self.assertIn("REVOKE INSERT ON api.secret_audit FROM authenticated", src)
        self.assertIn("private.audit_secret", src)
        self.assertIn("Never trust caller-supplied p_user_id", src)


# ── Auth routes ────────────────────────────────────────────────────


class TestAuth(unittest.TestCase):
    def setUp(self):
        store.app.config["TESTING"] = True
        store.app.config["CSRF_TESTING"] = False
        self.client = store.app.test_client()

    def test_index_anon_to_login(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.location)

    def test_index_authed_to_teams(self):
        with self.client.session_transaction() as s:
            s["user_id"] = str(uuid4())
        r = self.client.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/teams", r.location)

    def test_login_get(self):
        with patch.object(ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}), patch.object(
            settings_svc, "setup_notice", return_value=None
        ), patch.object(settings_svc, "registration_enabled", return_value=True):
            r = self.client.get("/login")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Sign in", r.data)

    def test_login_bad_creds(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, "connect", return_value=conn), patch.object(
            ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}
        ), patch("lockout.record_failure"), patch("lockout.is_locked", return_value=False):
            r = self.client.post("/login", data={"email": "a@b.c", "password": "nope"})
        self.assertEqual(r.status_code, 401)
        self.assertIn(b"Invalid", r.data)

    def test_login_locked(self):
        with patch("lockout.is_locked", return_value=True), patch.object(
            ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}
        ):
            r = self.client.post("/login", data={"email": "a@b.c", "password": "x"})
        self.assertEqual(r.status_code, 429)

    def test_login_ok(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={"id": uid, "email": "a@b.c", "name": "A"})
        with patch.object(db, "connect", return_value=conn), patch.object(
            ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}
        ), patch("lockout.is_locked", return_value=False), patch(
            "lockout.clear_failures"
        ), patch.object(authz, "is_global_admin", return_value=False), patch.object(
            settings_svc, "setup_notice", return_value=None
        ):
            r = self.client.post(
                "/login",
                data={"email": "a@b.c", "password": "secret12"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/teams", r.location)
        with self.client.session_transaction() as s:
            self.assertEqual(s["user_id"], str(uid))
            self.assertEqual(s["email"], "a@b.c")
            self.assertIn("jwt", s)

    def test_login_clears_session_first(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={"id": uid, "email": "a@b.c", "name": "A"})
        with self.client.session_transaction() as s:
            s["stale"] = "should-be-gone"
            s["_csrf"] = "old"
        with patch.object(db, "connect", return_value=conn), patch.object(
            ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}
        ), patch("lockout.is_locked", return_value=False), patch(
            "lockout.clear_failures"
        ), patch.object(authz, "is_global_admin", return_value=False), patch.object(
            settings_svc, "setup_notice", return_value=None
        ):
            r = self.client.post(
                "/login",
                data={"email": "a@b.c", "password": "secret12"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        with self.client.session_transaction() as s:
            self.assertNotIn("stale", s)
            self.assertEqual(s["user_id"], str(uid))

    def test_csrf_rejects_post_without_token(self):
        store.app.config["CSRF_TESTING"] = True
        try:
            with self.client.session_transaction() as s:
                s["_csrf"] = "good-token"
            r = self.client.post("/logout")
            self.assertEqual(r.status_code, 400)
        finally:
            store.app.config["CSRF_TESTING"] = False

    def test_csrf_accepts_valid_token(self):
        store.app.config["CSRF_TESTING"] = True
        try:
            with self.client.session_transaction() as s:
                s["_csrf"] = "good-token"
                s["user_id"] = str(uuid4())
            r = self.client.post("/logout", data={"_csrf": "good-token"}, follow_redirects=False)
            self.assertEqual(r.status_code, 302)
            self.assertIn("/login", r.location)
        finally:
            store.app.config["CSRF_TESTING"] = False

    def test_select_team_blocks_open_redirect(self):
        with self.client.session_transaction() as s:
            s["user_id"] = str(uuid4())
        r = self.client.post(
            "/select-team",
            data={"team_id": "", "next": "//evil.com"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 302)
        self.assertNotIn("evil", r.location)
        self.assertTrue(r.location.endswith("/projects") or "/projects" in r.location)

    def test_login_ldap_ok(self):
        uid = uuid4()
        ldap_user = {
            "email": "ldap@ex.com",
            "name": "LDAP User",
            "groups": ["CN=secretstore-admins,OU=groups,DC=ex,DC=com"],
        }
        synced = {
            "id": uid,
            "email": "ldap@ex.com",
            "name": "LDAP User",
            "is_global_admin": True,
        }
        conn, _ = _conn(fetchone=None)
        with patch.object(db, "connect", return_value=conn), patch.object(
            ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "true"}
        ), patch.object(ldap_auth, "ldap_authenticate", return_value=ldap_user), patch.object(
            ldap_auth, "sync_ldap_user", return_value=synced
        ), patch("lockout.is_locked", return_value=False), patch(
            "lockout.clear_failures"
        ), patch.object(authz, "is_global_admin", return_value=True), patch.object(
            settings_svc, "setup_notice", return_value=None
        ):
            r = self.client.post(
                "/login",
                data={"email": "ldapuser", "password": "dir-pass"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/teams", r.location)
        with self.client.session_transaction() as s:
            self.assertEqual(s["user_id"], str(uid))
            self.assertEqual(s["email"], "ldap@ex.com")
            self.assertTrue(s["is_global_admin"])

    def test_register_short_password(self):
        with patch.object(settings_svc, "registration_enabled", return_value=True), patch.object(
            settings_svc, "setup_notice", return_value=None
        ):
            r = self.client.post(
                "/register",
                data={"email": "a@b.c", "password": "short", "name": "A"},
            )
        self.assertEqual(r.status_code, 400)
        self.assertIn(b"8 characters", r.data)

    def test_register_ok(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={"id": uid})
        with patch.object(db, "connect", return_value=conn), patch.object(
            settings_svc, "registration_enabled", return_value=True
        ), patch.object(settings_svc, "setup_notice", return_value=None), patch.object(
            authz, "is_global_admin", return_value=False
        ):
            r = self.client.post(
                "/register",
                data={"email": "new@b.c", "password": "password1", "name": "N"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/teams", r.location)
        with self.client.session_transaction() as s:
            self.assertFalse(s.get("is_global_admin"))

    def test_register_does_not_auto_promote_first_user(self):
        """register_user SQL must set is_global_admin false (no first_user race)."""
        from pathlib import Path

        init = (Path(__file__).resolve().parents[1] / "db" / "init.sql").read_text()
        # Extract register_user body
        start = init.index("CREATE OR REPLACE FUNCTION private.register_user")
        end = init.index("$$;", start)
        body = init[start:end]
        self.assertIn("false, 'local'", body)
        self.assertNotIn("first_user", body)

    def test_bootstrap_email_promotes_on_register(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={"id": uid})
        admin_conn, admin_cur = _conn()
        with patch.object(db, "connect", return_value=conn), patch.object(
            db, "connect_admin", return_value=admin_conn
        ), patch.object(settings_svc, "registration_enabled", return_value=True), patch.object(
            settings_svc, "setup_notice", return_value=None
        ), patch(
            "routes.auth.bootstrap_admin_email", return_value="admin@ex.com"
        ), patch.object(authz, "is_global_admin", return_value=True):
            r = self.client.post(
                "/register",
                data={"email": "admin@ex.com", "password": "password1", "name": "A"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        sql = " ".join(str(c.args[0]) for c in admin_cur.execute.call_args_list)
        self.assertIn("is_global_admin = true", sql)

    def test_register_disabled(self):
        with patch.object(settings_svc, "registration_enabled", return_value=False):
            r = self.client.get("/register", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.location)
        with patch.object(settings_svc, "registration_enabled", return_value=False):
            r = self.client.post(
                "/register",
                data={"email": "new@b.c", "password": "password1", "name": "N"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.location)

    def test_login_hides_register_when_disabled(self):
        with patch.object(ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}), patch.object(
            settings_svc, "registration_enabled", return_value=False
        ), patch.object(settings_svc, "setup_notice", return_value=None):
            r = self.client.get("/login")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(b'href="/register"', r.data)

    def test_registration_disabled_without_bootstrap(self):
        with patch.object(settings_svc, "has_global_admin", return_value=False), patch(
            "settings_svc.bootstrap_admin_email", return_value=""
        ), patch.object(settings_svc, "get_settings", return_value={"registration_enabled": "true"}):
            self.assertFalse(settings_svc.registration_enabled())

    def test_logout(self):
        with self.client.session_transaction() as s:
            s["user_id"] = str(uuid4())
            s["email"] = "a@b.c"
        r = self.client.post("/logout")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.location)
        with self.client.session_transaction() as s:
            self.assertNotIn("user_id", s)

    def test_profile_requires_login(self):
        r = self.client.get("/profile")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.location)

    def test_forgot_password_get(self):
        r = self.client.get("/forgot-password")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Forgot password", r.data)

    def test_forgot_password_post_no_enumeration(self):
        with patch("passwords.create_reset_token", return_value=None):
            r = self.client.post(
                "/forgot-password",
                data={"email": "nobody@ex.com"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.location)

    def test_change_password_requires_login(self):
        r = self.client.post(
            "/profile/password",
            data={
                "current_password": "old",
                "new_password": "newpass12",
                "new_password_confirm": "newpass12",
            },
        )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.location)

    def test_change_password_ok(self):
        uid = str(uuid4())
        with self.client.session_transaction() as s:
            s["user_id"] = uid
            s["sid"] = str(uuid4())
        with patch("passwords.change_password", return_value=(True, "")), patch(
            "user_sessions.revoke_other_sessions", return_value=2
        ):
            r = self.client.post(
                "/profile/password",
                data={
                    "current_password": "oldpass12",
                    "new_password": "newpass12",
                    "new_password_confirm": "newpass12",
                },
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/profile", r.location)

    def test_change_password_mismatch(self):
        uid = str(uuid4())
        with self.client.session_transaction() as s:
            s["user_id"] = uid
        r = self.client.post(
            "/profile/password",
            data={
                "current_password": "oldpass12",
                "new_password": "newpass12",
                "new_password_confirm": "other",
            },
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 302)
        with self.client.session_transaction() as s:
            flashes = s.get("_flashes") or []
        self.assertTrue(any("match" in msg.lower() for _c, msg in flashes))

    def test_revoke_other_sessions(self):
        uid = str(uuid4())
        sid = str(uuid4())
        with self.client.session_transaction() as s:
            s["user_id"] = uid
            s["sid"] = sid
        with patch("user_sessions.revoke_other_sessions", return_value=3) as rev:
            r = self.client.post(
                "/profile/sessions/revoke-others", follow_redirects=False
            )
        self.assertEqual(r.status_code, 302)
        rev.assert_called_once_with(uid, sid)

    def test_reset_password_mismatch(self):
        r = self.client.post(
            "/reset-password/tok",
            data={"password": "newpass12", "password_confirm": "nope"},
        )
        self.assertEqual(r.status_code, 400)

    def test_reset_password_ok(self):
        with patch("passwords.consume_reset_token", return_value=(True, "")):
            r = self.client.post(
                "/reset-password/goodtoken",
                data={"password": "newpass12", "password_confirm": "newpass12"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.location)

    def test_password_schema_helpers(self):
        from pathlib import Path

        init = (Path(__file__).resolve().parents[1] / "db" / "init.sql").read_text()
        self.assertIn("private.change_password", init)
        self.assertIn("private.set_local_password", init)
        self.assertIn("private.user_sessions", init)
        self.assertIn("private.password_reset_tokens", init)

    def test_profile_ok(self):
        uid = uuid4()
        tid = uuid4()
        pid = uuid4()
        with self.client.session_transaction() as s:
            s["user_id"] = str(uid)
            s["email"] = "a@b.c"
            s["name"] = "Ada"
            s["is_global_admin"] = False

        admin_conn, _ = _conn(
            fetchone={
                "id": uid,
                "email": "a@b.c",
                "name": "Ada Lovelace",
                "is_global_admin": False,
                "auth_source": "local",
                "created_at": "2026-01-01",
            }
        )
        last_sql = {"s": ""}

        def execute(sql, params=None):
            last_sql["s"] = " ".join(str(sql).lower().split())

        def fetchone():
            s = last_sql["s"]
            if "from api.secrets" in s and "count" in s:
                return {"n": 3}
            if "from api.secret_pins" in s and "count" in s:
                return {"n": 1}
            return None

        def fetchall():
            s = last_sql["s"]
            if "from api.teams t" in s and "team_members" in s:
                return [
                    {
                        "id": tid,
                        "name": "Platform",
                        "role": "owner",
                        "source": "manual",
                        "created_at": "2026-01-02",
                        "project_count": 1,
                    }
                ]
            if "from api.projects p" in s:
                return [
                    {
                        "id": pid,
                        "name": "API",
                        "created_at": "2026-01-03",
                        "team_id": tid,
                        "team_name": "Platform",
                        "team_role": "owner",
                        "project_role": None,
                        "secret_count": 3,
                    }
                ]
            if "team_join_requests" in s:
                return []
            if "secret_pins pin" in s or "from api.secret_pins pin" in s:
                return []
            if "secret_recent" in s:
                return []
            return []

        user_conn, cur = _conn(fetchone=fetchone)
        cur.execute.side_effect = execute
        cur.fetchall.side_effect = fetchall
        with patch.object(db, "connect_admin", return_value=admin_conn), patch.object(
            db, "as_user", return_value=user_conn
        ), patch("user_sessions.list_sessions", return_value=[]):
            r = self.client.get("/profile")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"My profile", r.data)
        self.assertIn(b"Ada Lovelace", r.data)
        self.assertIn(b"a@b.c", r.data)
        self.assertIn(b"Local password", r.data)
        self.assertIn(b"Change password", r.data)
        self.assertIn(b"Active sessions", r.data)
        self.assertIn(b"Platform", r.data)
        self.assertIn(b"API", r.data)
        self.assertIn(b"At a glance", r.data)

    def test_profile_shows_ldap_and_admin(self):
        uid = uuid4()
        with self.client.session_transaction() as s:
            s["user_id"] = str(uid)
            s["email"] = "admin@ex.com"
            s["is_global_admin"] = True
        admin_conn, _ = _conn(
            fetchone={
                "id": uid,
                "email": "admin@ex.com",
                "name": "Admin",
                "is_global_admin": True,
                "auth_source": "ldap",
                "created_at": "2025-06-01",
            }
        )
        user_conn, _ = _conn(fetchone={"n": 0}, fetchall=[])
        with patch.object(db, "connect_admin", return_value=admin_conn), patch.object(
            db, "as_user", return_value=user_conn
        ), patch("user_sessions.list_sessions", return_value=[]):
            r = self.client.get("/profile")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"LDAP directory", r.data)
        self.assertIn(b"Global admin", r.data)
        self.assertIn(b"LDAP", r.data)
        self.assertNotIn(b"name=\"current_password\"", r.data)


# ── Teams ──────────────────────────────────────────────────────────


class TestTeams(unittest.TestCase):
    def setUp(self):
        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "u@ex.com"

    def test_list_requires_login(self):
        c = store.app.test_client()
        r = c.get("/teams")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.location)

    def test_list_teams(self):
        tid = uuid4()
        conn, _ = _conn(
            fetchall=[
                {
                    "id": tid,
                    "name": "Platform",
                    "role": "owner",
                    "project_count": 2,
                }
            ]
        )
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get("/teams")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Platform", r.data)
        self.assertIn(b"sidebar", r.data)  # modernised shell

    def test_create_team_empty_name(self):
        with patch.object(settings_svc, "can_create_team", return_value=True):
            r = self.client.post("/teams", data={"name": "  "}, follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/teams", r.location)

    def test_create_team(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={"id": tid})
        with patch.object(db, "connect", return_value=conn), patch.object(
            settings_svc, "can_create_team", return_value=True
        ):
            r = self.client.post("/teams", data={"name": "Ops"}, follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn(str(tid), r.location)

    def test_create_team_restricted(self):
        with patch.object(settings_svc, "can_create_team", return_value=False):
            r = self.client.post("/teams", data={"name": "Ops"}, follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/teams", r.location)
        self.assertNotIn("Ops", r.headers.get("Location", ""))

    def test_team_detail_404(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get(f"/teams/{uuid4()}")
        self.assertEqual(r.status_code, 404)

    def test_team_detail_ok(self):
        tid = uuid4()
        last_sql = {"s": ""}

        def execute(sql, params=None):
            last_sql["s"] = " ".join(str(sql).lower().split())

        def fetchone():
            s = last_sql["s"]
            # Per-query stubs (order-independent)
            if "from api.teams" in s and "where id" in s:
                return {"id": tid, "name": "T"}
            if "select role from api.team_members" in s:
                return {"role": "owner"}
            return None

        conn, cur = _conn(fetchone=fetchone, fetchall=[])
        cur.execute.side_effect = execute
        with patch.object(db, "as_user", return_value=conn), patch.object(
            ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}
        ):
            r = self.client.get(f"/teams/{tid}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b">T<", r.data)
        self.assertIn(b"?tab=projects", r.data)
        self.assertIn(b"?tab=members", r.data)
        self.assertIn(b"?tab=settings", r.data)
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        # Default tab loads projects, not members
        self.assertIn("from api.projects", sql)
        self.assertNotIn("team_member_rows", sql)

    def test_team_detail_members_tab(self):
        tid = uuid4()
        last_sql = {"s": ""}

        def execute(sql, params=None):
            last_sql["s"] = " ".join(str(sql).lower().split())

        def fetchone():
            s = last_sql["s"]
            if "from api.teams" in s and "where id" in s:
                return {"id": tid, "name": "T"}
            if "select role from api.team_members" in s:
                return {"role": "owner"}
            return None

        conn, cur = _conn(fetchone=fetchone, fetchall=[])
        cur.execute.side_effect = execute
        with patch.object(db, "as_user", return_value=conn), patch.object(
            ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}
        ):
            r = self.client.get(f"/teams/{tid}?tab=members")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Invites", r.data)
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        self.assertIn("team_member_rows", sql)

    def test_add_member_user_missing(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={"id": None})
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{tid}/members",
                data={"email": "nope@x.com", "role": "member"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)

    def test_add_member_uses_lookup_user(self):
        tid, uid = uuid4(), uuid4()
        conn, cur = _conn(fetchone={"id": uid})
        cur.rowcount = 1
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{tid}/members",
                data={"email": "u@ex.com", "role": "member"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list)
        self.assertIn("private.lookup_user", sql)
        self.assertNotIn("user_directory", sql)

    def test_user_directory_not_granted_to_authenticated(self):
        from pathlib import Path

        init = (Path(__file__).resolve().parents[1] / "db" / "init.sql").read_text()
        # Must not grant directory SELECT to authenticated (enumeration risk)
        self.assertNotIn(
            "GRANT SELECT ON api.user_directory TO authenticated",
            init,
        )
        self.assertIn("private.lookup_user", init)
        self.assertIn("private.team_member_rows", init)

    def test_non_member_cannot_self_join(self):
        """RLS must reject self-insert into a team the user does not admin."""
        tid = uuid4()
        # Lookup succeeds (user exists / is self); INSERT fails as RLS would.
        rls_err = Exception(
            'new row violates row-level security policy for table "team_members"'
        )

        def execute(sql, params=None):
            if "INSERT INTO api.team_members" in str(sql):
                raise rls_err

        conn, cur = _conn(fetchone={"id": self.uid})
        cur.execute.side_effect = execute
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{tid}/members",
                data={"email": "u@ex.com", "role": "owner"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        # Must not commit a successful membership grant
        conn.commit.assert_not_called()
        with self.client.session_transaction() as s:
            flashes = s.get("_flashes") or []
        self.assertTrue(
            any("row-level security" in msg for _cat, msg in flashes),
            f"expected RLS error flash, got {flashes!r}",
        )

    def test_tm_insert_policy_forbids_self_join(self):
        """Policy must require owner/admin — no user_id = current_user escape hatch."""
        from pathlib import Path

        init_sql = (Path(__file__).resolve().parents[1] / "db" / "init.sql").read_text()
        # Extract the tm_insert policy body
        start = init_sql.index("CREATE POLICY tm_insert ON api.team_members")
        end = init_sql.index(";", start)
        policy = init_sql[start:end]
        self.assertIn("api.team_role(team_id) IN ('owner', 'admin')", policy)
        self.assertNotIn("user_id = api.current_user_id()", policy)

        # ensure_schema must re-apply the same fix on existing volumes
        src = Path(schema_mod.__file__).read_text()
        self.assertIn("DROP POLICY IF EXISTS tm_insert ON api.team_members", src)
        ensure_start = src.index("DROP POLICY IF EXISTS tm_insert ON api.team_members")
        ensure_chunk = src[ensure_start : ensure_start + 280]
        self.assertIn("api.team_role(team_id) IN ('owner', 'admin')", ensure_chunk)
        self.assertNotIn("user_id = api.current_user_id()", ensure_chunk)

    def test_team_roles_include_viewer(self):
        self.assertIn("viewer", config.TEAM_ROLES)
        self.assertLess(config.ROLE_RANK["viewer"], config.ROLE_RANK["member"])

    def test_add_member_viewer_role(self):
        tid, uid = uuid4(), uuid4()
        conn, cur = _conn(fetchone={"id": uid})
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{tid}/members",
                data={"email": "ro@ex.com", "role": "viewer"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        sql = " ".join(str(c) for c in cur.execute.call_args_list)
        self.assertIn("viewer", sql)

    def test_create_project(self):
        tid, pid = uuid4(), uuid4()
        conn, _ = _conn(fetchone={"id": pid})
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{tid}/projects",
                data={"name": "prod"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn(str(pid), r.location)

    def test_delete_team_owner_ok(self):
        tid = uuid4()
        conn, cur = _conn(fetchone={"r": "owner"})
        cur.rowcount = 1
        with self.client.session_transaction() as s:
            s["team_id"] = str(tid)
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(f"/teams/{tid}/delete", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/teams", r.location)
        self.assertNotIn(str(tid), r.location)
        conn.commit.assert_called()
        with self.client.session_transaction() as s:
            self.assertNotEqual(s.get("team_id"), str(tid))

    def test_delete_team_non_owner_denied(self):
        tid = uuid4()
        for role in ("admin", "member", "viewer"):
            conn, cur = _conn(fetchone={"r": role})
            with patch.object(db, "as_user", return_value=conn):
                r = self.client.post(f"/teams/{tid}/delete", follow_redirects=False)
            self.assertEqual(r.status_code, 302)
            self.assertIn(str(tid), r.location)
            conn.commit.assert_not_called()
            with self.client.session_transaction() as s:
                flashes = s.get("_flashes") or []
            self.assertTrue(
                any("owner" in msg.lower() for _c, msg in flashes),
                f"role={role} flashes={flashes!r}",
            )

    def test_delete_project_admin_ok(self):
        tid, pid = uuid4(), uuid4()
        conn, cur = _conn(fetchone={"r": "admin"})
        cur.rowcount = 1
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{tid}/projects/{pid}/delete",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn(str(tid), r.location)
        conn.commit.assert_called()

    def test_delete_project_member_denied(self):
        tid, pid = uuid4(), uuid4()
        conn, _ = _conn(fetchone={"r": "member"})
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{tid}/projects/{pid}/delete",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        conn.commit.assert_not_called()
        with self.client.session_transaction() as s:
            flashes = s.get("_flashes") or []
        self.assertTrue(any("owner" in msg.lower() or "admin" in msg.lower() for _c, msg in flashes))


# ── Projects / secrets ─────────────────────────────────────────────


class TestSecrets(unittest.TestCase):
    def setUp(self):
        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        self.pid = uuid4()
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "u@ex.com"

    def _project_conn(
        self,
        tab="secrets",
        can_write=True,
        can_admin=None,
        team_role="owner",
        secrets=None,
        tokens=None,
        audit_log=None,
        total=None,
    ):
        """as_user used by project_detail (tab-scoped queries)."""
        project = {
            "id": self.pid,
            "name": "prod",
            "team_name": "Ops",
            "team_id": uuid4(),
        }
        if can_admin is None:
            can_admin = team_role in ("owner", "admin")
        rows = secrets or [] if tab == "secrets" else (audit_log or [] if tab == "audit" else (tokens or []))
        if total is None:
            total = len(rows)
        fo = [project, {"w": can_write}, {"a": can_admin}, {"r": team_role}]
        if tab in ("secrets", "audit"):
            fo.append({"n": total})
        if tab == "settings":
            fa = [[]]  # project_member_rows
        elif tab == "secrets":
            fa = [rows, []]  # secrets page + pin lookup
        else:
            fa = [rows] if tab in ("audit", "tokens") else []
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        cur.fetchall.side_effect = fa if fa else [[]]
        return conn

    def test_project_detail(self):
        with patch.object(db, "as_user", return_value=self._project_conn()):
            r = self.client.get(f"/projects/{self.pid}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"prod", r.data)
        self.assertIn(b"Secrets", r.data)
        self.assertIn(b"Audit log", r.data)

    def test_project_audit_tab(self):
        audit_rows = [
            {
                "id": uuid4(),
                "secret_id": uuid4(),
                "secret_key": "API_KEY",
                "action": "revealed",
                "created_at": "2026-01-01",
                "actor_email": "u@ex.com",
                "user_id": self.uid,
                "actor_name": "User",
            }
        ]
        with patch.object(
            db,
            "as_user",
            return_value=self._project_conn(tab="audit", audit_log=audit_rows),
        ):
            r = self.client.get(f"/projects/{self.pid}?tab=audit")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"API_KEY", r.data)
        self.assertIn(b"revealed", r.data)
        self.assertIn(b"u@ex.com", r.data)

    def test_project_404(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get(f"/projects/{uuid4()}")
        self.assertEqual(r.status_code, 404)

    def test_delete_project_route_owner_ok(self):
        tid = uuid4()
        conn, cur = _conn(fetchone={"team_id": tid, "r": "owner"})
        cur.rowcount = 1
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/delete",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn(str(tid), r.location)
        conn.commit.assert_called()

    def test_delete_project_route_viewer_denied(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={"team_id": tid, "r": "viewer"})
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/delete",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn(str(self.pid), r.location)
        conn.commit.assert_not_called()

    def test_project_settings_tab_shows_members_and_delete_for_owner(self):
        with patch.object(
            db, "as_user", return_value=self._project_conn(tab="settings", team_role="owner")
        ):
            r = self.client.get(f"/projects/{self.pid}?tab=settings")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Members", r.data)
        self.assertIn(b"Danger zone", r.data)
        self.assertIn(b"Delete project", r.data)
        self.assertIn(b"Settings", r.data)  # tab nav
        self.assertNotIn(b"Project settings", r.data)

    def test_project_settings_hidden_for_writer_without_admin(self):
        """Project write without admin cannot manage members; Settings tab hidden."""
        with patch.object(
            db,
            "as_user",
            return_value=self._project_conn(
                team_role="member", can_write=True, can_admin=False
            ),
        ):
            r = self.client.get(f"/projects/{self.pid}")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(b"?tab=settings", r.data)
        self.assertNotIn(b"Delete project", r.data)

    def test_project_settings_tab_hidden_for_viewer(self):
        with patch.object(
            db,
            "as_user",
            return_value=self._project_conn(
                team_role="viewer", can_write=False, can_admin=False
            ),
        ):
            r = self.client.get(f"/projects/{self.pid}")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(b"?tab=settings", r.data)
        self.assertNotIn(b"Delete project", r.data)

    def test_project_admin_settings_members_without_delete(self):
        """Project admin can manage members; team member cannot delete project."""
        with patch.object(
            db,
            "as_user",
            return_value=self._project_conn(
                tab="settings",
                team_role="member",
                can_write=True,
                can_admin=True,
            ),
        ):
            r = self.client.get(f"/projects/{self.pid}?tab=settings")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Members", r.data)
        self.assertNotIn(b"Delete project", r.data)

    def test_project_secrets_tab_no_danger_zone(self):
        with patch.object(db, "as_user", return_value=self._project_conn(team_role="owner")):
            r = self.client.get(f"/projects/{self.pid}?tab=secrets")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Settings", r.data)
        self.assertNotIn(b"Danger zone", r.data)

    def test_create_secret(self):
        sid = uuid4()
        # existing lookup, RETURNING id
        conn, cur = _conn()
        cur.fetchone.side_effect = [None, {"id": sid}]
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/secrets",
                data={"key": "API_KEY", "value": "sekrit", "note": ""},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn(str(self.pid), r.location)
        self.assertTrue(conn.cursor.called)

    def test_create_secret_missing_key(self):
        r = self.client.post(
            f"/projects/{self.pid}/secrets",
            data={"key": "", "value": "x"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 302)

    def test_delete_secret(self):
        sid = uuid4()
        conn, cur = _conn(fetchone={"id": sid, "key": "API_KEY"})
        cur.rowcount = 1
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/secrets/{sid}/delete",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        conn.commit.assert_called()

    def test_delete_secret_read_only_no_op(self):
        """Read (SELECT) ok but write (UPDATE) blocked — must flash, not silent success."""
        sid = uuid4()
        conn, cur = _conn(fetchone={"id": sid, "key": "API_KEY"})
        cur.rowcount = 0  # RLS WITH CHECK / USING blocked the UPDATE
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/secrets/{sid}/delete",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        conn.commit.assert_not_called()
        conn.rollback.assert_called()
        with self.client.session_transaction() as s:
            flashes = s.get("_flashes") or []
        self.assertTrue(
            any("permission" in msg.lower() for _cat, msg in flashes),
            f"expected permission flash, got {flashes!r}",
        )

    def test_reveal_secret(self):
        sid = uuid4()
        enc = crypto.encrypt("super-secret")
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            {"id": sid, "key": "API_KEY", "value_enc": enc},
            {"w": True},
        ]
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get(f"/projects/{self.pid}/secrets/{sid}/reveal")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"super-secret", r.data)
        self.assertIn(b"Save", r.data)
        self.assertIn(b"/value", r.data)

    def test_update_secret_value(self):
        sid = uuid4()
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            {"w": True},
            {"id": sid, "key": "API_KEY"},
        ]
        cur.rowcount = 1
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/secrets/{sid}/value",
                data={"value": "new-secret"},
                headers={"HX-Request": "true"},
            )
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(b"new-secret", r.data)
        self.assertIn(b"*******", r.data)
        self.assertIn(b"Updated", r.data)
        conn.commit.assert_called()

    def test_reveal_missing(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get(f"/projects/{self.pid}/secrets/{uuid4()}/reveal")
        self.assertEqual(r.status_code, 404)


# ── Machine tokens ─────────────────────────────────────────────────


class TestTokens(unittest.TestCase):
    def setUp(self):
        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        with self.client.session_transaction() as s:
            s["user_id"] = str(uuid4())
            s["email"] = "u@ex.com"

    def test_create_token(self):
        conn, cur = _conn(fetchone={"w": True})
        cur.rowcount = 1
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/tokens",
                data={"name": "openshift"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        with self.client.session_transaction() as s:
            self.assertTrue(s.get("new_token", "").startswith("ss_"))
        sql = " ".join(str(c) for c in cur.execute.call_args_list)
        self.assertIn("read-only", sql)

    def test_create_token_write_role(self):
        conn, cur = _conn(fetchone={"w": True})
        cur.rowcount = 1
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/tokens",
                data={"name": "ci-writer", "role": "write"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        # INSERT args: project_id, name, hash, prefix, role, expires
        insert_calls = [
            c for c in cur.execute.call_args_list
            if c.args and "INSERT INTO api.machine_tokens" in str(c.args[0])
        ]
        self.assertTrue(insert_calls)
        self.assertEqual(insert_calls[0].args[1][4], "write")

    def test_create_token_invalid_role_defaults_read_only(self):
        conn, cur = _conn(fetchone={"w": True})
        cur.rowcount = 1
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/tokens",
                data={"name": "x", "role": "owner"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        insert_calls = [
            c for c in cur.execute.call_args_list
            if c.args and "INSERT INTO api.machine_tokens" in str(c.args[0])
        ]
        self.assertEqual(insert_calls[0].args[1][4], "read-only")

    def test_create_token_read_only_denied(self):
        conn, _ = _conn(fetchone={"w": False})
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/tokens",
                data={"name": "openshift"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        conn.commit.assert_not_called()
        with self.client.session_transaction() as s:
            self.assertNotIn("new_token", s)
            flashes = s.get("_flashes") or []
        self.assertTrue(
            any("permission" in msg.lower() for _cat, msg in flashes),
            f"expected permission flash, got {flashes!r}",
        )

    def test_delete_token(self):
        conn, cur = _conn(fetchone={"w": True})
        cur.rowcount = 1
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/tokens/{uuid4()}/delete",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)

    def test_delete_token_read_only_denied(self):
        conn, _ = _conn(fetchone={"w": False})
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/tokens/{uuid4()}/delete",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        with self.client.session_transaction() as s:
            flashes = s.get("_flashes") or []
        self.assertTrue(
            any("permission" in msg.lower() for _cat, msg in flashes),
            f"expected permission flash, got {flashes!r}",
        )

    def test_mt_select_policy_allows_readers(self):
        """Read-only may list tokens; only writers insert/delete."""
        from pathlib import Path

        init_sql = (Path(__file__).resolve().parents[1] / "db" / "init.sql").read_text()
        sel_start = init_sql.index("CREATE POLICY mt_select ON api.machine_tokens")
        sel_end = init_sql.index(";", sel_start)
        self.assertIn("can_read_project", init_sql[sel_start:sel_end])
        ins_start = init_sql.index("CREATE POLICY mt_insert ON api.machine_tokens")
        ins_end = init_sql.index(";", ins_start)
        self.assertIn("can_write_project", init_sql[ins_start:ins_end])

    def test_pm_policies_use_can_admin_project(self):
        """Member management requires project admin, not mere write."""
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        init_sql = (root / "db" / "init.sql").read_text()
        schema_src = (root / "app" / "schema.py").read_text()
        for name in ("pm_insert", "pm_update", "pm_delete"):
            start = init_sql.index(f"CREATE POLICY {name} ON api.project_members")
            end = init_sql.index(";", start)
            chunk = init_sql[start:end]
            self.assertIn("can_admin_project", chunk, msg=name)
            self.assertNotIn("can_write_project", chunk, msg=name)
        self.assertIn("can_admin_project", schema_src)
        self.assertIn("pm_insert ON api.project_members", schema_src)
        self.assertIn("pm_delete ON api.project_members", schema_src)

    def test_can_write_project_most_specific_wins(self):
        """Project role overrides team default when a project_members row exists."""
        from pathlib import Path

        init_sql = (Path(__file__).resolve().parents[1] / "db" / "init.sql").read_text()
        start = init_sql.index("CREATE OR REPLACE FUNCTION api.can_write_project")
        end = init_sql.index("$$;", start) + 3
        body = init_sql[start:end]
        # Project write/admin grants write
        self.assertIn("role IN ('admin', 'write')", body)
        # Team default only when NOT a project member
        self.assertIn("NOT EXISTS", body)
        self.assertIn("tm.role IN ('owner', 'admin', 'member')", body)
        # Old OR-both-paths pattern is gone (no bare team join without NOT EXISTS guard)
        # Presence of project_members check before team fallback is the authority rule.
        self.assertLess(
            body.index("FROM api.project_members"),
            body.index("FROM api.projects p"),
        )

    def test_can_read_project_most_specific_wins(self):
        from pathlib import Path

        init_sql = (Path(__file__).resolve().parents[1] / "db" / "init.sql").read_text()
        start = init_sql.index("CREATE OR REPLACE FUNCTION api.can_read_project")
        end = init_sql.index("$$;", start) + 3
        body = init_sql[start:end]
        self.assertIn("NOT EXISTS", body)
        self.assertIn("FROM api.project_members", body)

    def test_can_admin_project_defined(self):
        from pathlib import Path

        init_sql = (Path(__file__).resolve().parents[1] / "db" / "init.sql").read_text()
        self.assertIn("CREATE OR REPLACE FUNCTION api.can_admin_project", init_sql)
        start = init_sql.index("CREATE OR REPLACE FUNCTION api.can_admin_project")
        end = init_sql.index("$$;", start) + 3
        body = init_sql[start:end]
        self.assertIn("role = 'admin'", body)
        self.assertIn("tm.role IN ('owner', 'admin')", body)
        self.assertIn("NOT EXISTS", body)

    def test_add_project_member_requires_admin(self):
        """Project write members cannot add project members."""
        conn, cur = _conn(fetchone={"a": False})
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/members",
                data={"email": "x@ex.com", "role": "read"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        self.assertIn("can_admin_project", sql)
        self.assertNotIn("insert into api.project_members", sql)
        with self.client.session_transaction() as s:
            flashes = s.get("_flashes") or []
        self.assertTrue(
            any("permission" in msg.lower() for _c, msg in flashes),
            f"expected permission flash, got {flashes!r}",
        )

    def test_add_project_member_ok_for_admin(self):
        uid = uuid4()
        tid = uuid4()
        last = {"s": ""}

        def execute(sql, params=None):
            last["s"] = " ".join(str(sql).lower().split())

        def fetchone():
            s = last["s"]
            if "can_admin_project" in s:
                return {"a": True}
            if "lookup_user" in s:
                return {"id": uid}
            if "from api.projects" in s and "team_id" in s:
                return {"team_id": tid}
            if "from api.project_members" in s and "select role" in s:
                return None
            return None

        conn, cur = _conn(fetchone=fetchone)
        cur.execute.side_effect = execute
        cur.rowcount = 1
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/members",
                data={"email": "x@ex.com", "role": "write"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        self.assertIn("insert into api.project_members", sql)
        self.assertIn("can_admin_project", sql)

    def test_remove_project_member_requires_admin(self):
        conn, cur = _conn(fetchone={"a": False})
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/members/{uuid4()}/remove",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        self.assertIn("can_admin_project", sql)
        self.assertNotIn("delete from api.project_members", sql)

    def test_secrets_updated_at_trigger_defined(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        init_sql = (root / "db" / "init.sql").read_text()
        self.assertIn("CREATE TRIGGER secrets_touch_updated_at", init_sql)
        self.assertIn("api.touch_updated_at", init_sql)
        # App upserts/restores must not hand-set updated_at (trigger owns it)
        routes = (Path(__file__).resolve().parent / "routes" / "projects.py").read_text()
        self.assertNotIn("updated_at = now()", routes)
        self.assertNotIn("updated_at=now()", routes)

    def test_secret_versions_schema(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        init = (root / "db" / "init.sql").read_text()
        self.assertIn("CREATE TABLE api.secret_versions", init)
        self.assertIn("archive_secret_version", init)
        self.assertIn("expires_at", init)
        self.assertNotIn("rotate_days", init)
        src = Path(schema_mod.__file__).read_text()
        self.assertIn("api.secret_versions", src)
        self.assertIn("archive_secret_version", src)
        self.assertNotIn("rotate_days", src)

    def test_token_prefix_unique_constraint(self):
        from pathlib import Path

        init = (Path(__file__).resolve().parents[1] / "db" / "init.sql").read_text()
        self.assertIn("token_prefix text NOT NULL UNIQUE", init)
        src = Path(schema_mod.__file__).read_text()
        self.assertIn("machine_tokens_token_prefix_key", src)


class TestOrgAccess(unittest.TestCase):
    """Project members, invites, org audit schema (no live DB)."""

    def test_schema_has_invites_and_org_audit(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        init = (root / "db" / "init.sql").read_text()
        self.assertIn("CREATE TABLE api.team_invites", init)
        self.assertIn("CREATE TABLE api.team_join_requests", init)
        self.assertIn("CREATE TABLE api.org_audit", init)
        self.assertIn("guard_last_team_owner", init)
        # Cascade team delete must not be blocked by last-owner guard
        self.assertIn("NOT EXISTS (SELECT 1 FROM api.teams WHERE id = OLD.team_id)", init)
        self.assertIn(
            "NOT EXISTS (SELECT 1 FROM api.teams WHERE id = OLD.team_id)",
            Path(schema_mod.__file__).read_text(),
        )
        self.assertIn("private.project_member_rows", init)
        self.assertIn("private.audit_org", init)
        self.assertIn("default_token_days", init)
        self.assertIn("'exported'", init)
        src = Path(schema_mod.__file__).read_text()
        self.assertIn("api.team_invites", src)
        self.assertIn("private.audit_org", src)
        self.assertIn("exported", src)

    def test_log_org_calls_fn(self):
        cur = MagicMock()
        with store.app.test_request_context("/"):
            from flask import session

            session["email"] = "a@b.c"
            audit.log_org(cur, team_id=uuid4(), action=audit.ORG_MEMBER_ADD, detail="x")
        sql = cur.execute.call_args.args[0]
        self.assertIn("private.audit_org", sql)

    def test_project_roles_config(self):
        self.assertIn("write", config.PROJECT_ROLES)
        self.assertIn("member", config.INVITE_ROLES)
        self.assertNotIn("owner", config.INVITE_ROLES)

    def test_members_tab_requires_login(self):
        r = store.app.test_client().get(f"/projects/{uuid4()}?tab=settings")
        self.assertEqual(r.status_code, 302)

    def test_invite_redeem_requires_login(self):
        c = store.app.test_client()
        r = c.get("/invite/not-a-real-token")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.location or "")
        with c.session_transaction() as s:
            self.assertEqual(s.get("invite_token"), "not-a-real-token")


class TestSecretLifecycle(unittest.TestCase):
    """Versioning helpers, expiry status, import parse (no DB)."""

    def setUp(self):
        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        self.pid = uuid4()
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "u@ex.com"

    def test_parse_env(self):
        from routes.projects import parse_secret_pairs

        pairs = parse_secret_pairs("FOO=bar\n# c\nBAZ='qux'\nexport Q=1\n")
        self.assertEqual(pairs, [("FOO", "bar"), ("BAZ", "qux"), ("Q", "1")])

    def test_parse_json_object(self):
        from routes.projects import parse_secret_pairs

        pairs = parse_secret_pairs('{"A": "1", "B": {"value": "2"}}')
        self.assertEqual(pairs, [("A", "1"), ("B", "2")])

    def test_parse_json_enc(self):
        from routes.projects import parse_secret_pairs

        pairs = parse_secret_pairs('{"K": {"value_enc": "gAAAA", "note": "n"}}')
        self.assertEqual(pairs[0][0], "K")
        self.assertEqual(pairs[0][1]["_enc"], "gAAAA")

    def test_parse_csv(self):
        from routes.projects import parse_secret_pairs

        pairs = parse_secret_pairs("key,value\nX,y\n")
        self.assertEqual(pairs, [("X", "y")])

    def test_due_status(self):
        from datetime import datetime, timedelta, timezone

        from routes.projects import expires_status, secret_due_status

        now = datetime.now(timezone.utc)
        self.assertEqual(
            secret_due_status({"expires_at": now - timedelta(days=1)}), "overdue"
        )
        self.assertEqual(
            secret_due_status({"expires_at": now + timedelta(days=3)}), "soon"
        )
        self.assertIsNone(secret_due_status({"expires_at": now + timedelta(days=60)}))
        self.assertIsNone(secret_due_status({"updated_at": now - timedelta(days=10)}))
        self.assertEqual(expires_status(now - timedelta(hours=1)), "overdue")
        self.assertEqual(expires_status(now + timedelta(days=2)), "soon")
        self.assertIsNone(expires_status(None))

    def test_history_requires_login(self):
        r = store.app.test_client().get(
            f"/projects/{uuid4()}/secrets/{uuid4()}/history"
        )
        self.assertEqual(r.status_code, 302)

    def test_export_plain_env(self):
        enc = crypto.encrypt("secret-val")
        conn, cur = _conn()
        cur.fetchone.return_value = {"r": True}
        cur.fetchall.return_value = [{"key": "K", "value_enc": enc, "note": ""}]
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get(f"/projects/{self.pid}/export?format=env&mode=plain")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"K=secret-val", r.data)
        conn.commit.assert_called()
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list)
        self.assertIn("audit_secret", sql)
        self.assertIn("exported", str(cur.execute.call_args_list))

    def test_import_env(self):
        sid = uuid4()
        conn, cur = _conn()
        cur.fetchone.side_effect = [{"w": True}, None, {"id": sid}]
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/import",
                data={"payload": "NEW_KEY=hello"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        conn.commit.assert_called()

    def test_history_page(self):
        sid, vid = uuid4(), uuid4()
        conn, cur = _conn()
        cur.fetchone.side_effect = [
            {
                "id": sid,
                "key": "K",
                "note": "current note",
                "updated_at": "2026-01-02",
                "expires_at": None,
            },
            {"w": True},
            {
                "name": "prod",
                "id": self.pid,
                "team_name": "Ops",
                "team_id": uuid4(),
            },
        ]
        cur.fetchall.return_value = [
            {"id": vid, "note": "old note", "created_at": "2020-01-01"}
        ]
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get(f"/projects/{self.pid}/secrets/{sid}/history")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Current", r.data)
        self.assertIn(b"Prior versions", r.data)
        self.assertIn(b"current note", r.data)
        self.assertIn(b"old note", r.data)
        self.assertIn(b"Reveal", r.data)
        self.assertIn(b"Rollback", r.data)
        self.assertIn(b"versions/", r.data)  # version reveal URL

    def test_reveal_secret_version(self):
        sid, vid = uuid4(), uuid4()
        enc = crypto.encrypt("prior-secret")
        conn, cur = _conn(
            fetchone={"value_enc": enc, "key": "K", "secret_id": sid}
        )
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get(
                f"/projects/{self.pid}/secrets/{sid}/versions/{vid}/reveal"
            )
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"prior-secret", r.data)


# ── PostgREST token API ────────────────────────────────────────────


class TestApiToken(unittest.TestCase):
    def test_requires_login(self):
        r = store.app.test_client().get("/api/token")
        self.assertEqual(r.status_code, 302)

    def test_returns_jwt(self):
        c = store.app.test_client()
        uid = str(uuid4())
        with c.session_transaction() as s:
            s["user_id"] = uid
        r = c.get("/api/token")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["token_type"], "bearer")
        claims = pyjwt.decode(data["access_token"], config.JWT_SECRET, algorithms=["HS256"])
        self.assertEqual(claims["sub"], uid)


# ── ESO webhook ────────────────────────────────────────────────────


class TestESO(unittest.TestCase):
    def setUp(self):
        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.pid = uuid4()

    def test_get_no_auth(self):
        r = self.client.get(f"/eso/v1/projects/{self.pid}/secrets/KEY")
        self.assertEqual(r.status_code, 401)

    def test_get_secret_ok(self):
        enc = crypto.encrypt("val")
        conn, _ = _conn(fetchone={"value_enc": enc})
        with patch.object(db, "connect", return_value=conn):
            r = self.client.get(
                f"/eso/v1/projects/{self.pid}/secrets/KEY",
                headers={"Authorization": "Bearer ss_testtoken"},
            )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["value"], "val")
        self.assertEqual(r.get_json()["key"], "KEY")

    def test_get_secret_not_found(self):
        # first fetch: no value; second: auth ok (same connection)
        state = {"n": 0}

        def fetchone():
            state["n"] += 1
            if state["n"] == 1:
                return {"value_enc": None}
            return {"ok": True}

        conn, _ = _conn(fetchone=fetchone)
        with patch.object(db, "connect", return_value=conn):
            r = self.client.get(
                f"/eso/v1/projects/{self.pid}/secrets/MISSING",
                headers={"Authorization": "Bearer ss_x"},
            )
        self.assertEqual(r.status_code, 404)

    def test_list_unauthorized(self):
        conn, _ = _conn(fetchone={"ok": False})
        with patch.object(db, "connect", return_value=conn):
            r = self.client.get(
                f"/eso/v1/projects/{self.pid}/secrets",
                headers={"Authorization": "Bearer bad"},
            )
        self.assertEqual(r.status_code, 401)

    def test_list_ok(self):
        state = {"n": 0}

        def fetchone():
            state["n"] += 1
            return {"ok": True}

        enc = crypto.encrypt("v1")
        conn, cur = _conn(fetchone=fetchone, fetchall=[{"key": "A", "value_enc": enc}])
        with patch.object(db, "connect", return_value=conn):
            r = self.client.get(
                f"/eso/v1/projects/{self.pid}/secrets",
                headers={"Authorization": "Bearer ss_ok"},
            )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["secrets"], {"A": "v1"})

    def test_bearer_hash_none(self):
        with store.app.test_request_context("/", headers={}):
            self.assertIsNone(eso_routes.bearer_hash())

    def test_upsert_read_only_forbidden(self):
        conn, _ = _conn(fetchone={"role": "read-only"})
        with patch.object(db, "connect", return_value=conn):
            r = self.client.post(
                f"/eso/v1/projects/{self.pid}/secrets",
                json={"key": "K", "value": "v"},
                headers={"Authorization": "Bearer ss_ro"},
            )
        self.assertEqual(r.status_code, 403)
        self.assertIn("read-only", r.get_json()["error"])
        conn.commit.assert_not_called()

    def test_upsert_write_ok(self):
        sid = uuid4()
        fo = [{"role": "write"}, {"id": sid}, None]  # role, upsert id, audit_secret
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        with patch.object(db, "connect", return_value=conn):
            r = self.client.post(
                f"/eso/v1/projects/{self.pid}/secrets",
                json={"key": "K", "value": "secret"},
                headers={"Authorization": "Bearer ss_write"},
            )
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["key"], "K")
        conn.commit.assert_called()
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list)
        self.assertIn("audit_secret", sql)
        self.assertIn("machine_upsert", sql)

    def test_eso_post_exempt_from_csrf(self):
        """Bearer ESO upsert must not require session CSRF when CSRF_TESTING is on."""
        store.app.config["CSRF_TESTING"] = True
        try:
            sid = uuid4()
            fo = [{"role": "write"}, {"id": sid}, None]
            conn, cur = _conn()
            cur.fetchone.side_effect = fo
            with patch.object(db, "connect", return_value=conn):
                r = self.client.post(
                    f"/eso/v1/projects/{self.pid}/secrets",
                    json={"key": "K", "value": "v"},
                    headers={"Authorization": "Bearer ss_write"},
                )
            self.assertNotEqual(r.status_code, 400)
            self.assertEqual(r.status_code, 200)
        finally:
            store.app.config["CSRF_TESTING"] = False

    def test_upsert_no_auth(self):
        r = self.client.post(
            f"/eso/v1/projects/{self.pid}/secrets",
            json={"key": "K", "value": "v"},
        )
        self.assertEqual(r.status_code, 401)

    def test_upsert_missing_key_value(self):
        r = self.client.post(
            f"/eso/v1/projects/{self.pid}/secrets",
            json={"key": "", "value": "v"},
            headers={"Authorization": "Bearer ss_x"},
        )
        self.assertEqual(r.status_code, 400)

    def test_create_token_with_expiry(self):
        # reuse token create path with expires_days (writer)
        c = store.app.test_client()
        with c.session_transaction() as s:
            s["user_id"] = str(uuid4())
            s["email"] = "u@ex.com"
        conn, cur = _conn(fetchone={"w": True})
        cur.rowcount = 1
        with patch.object(db, "as_user", return_value=conn):
            r = c.post(
                f"/projects/{self.pid}/tokens",
                data={"name": "eso", "role": "read-only", "expires_days": "30"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        insert = [
            c for c in cur.execute.call_args_list
            if c.args and "INSERT INTO api.machine_tokens" in str(c.args[0])
        ][0]
        self.assertIsNotNone(insert.args[1][5])  # expires_at set

    def test_create_token_rejects_huge_expiry(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s["user_id"] = str(uuid4())
            s["email"] = "u@ex.com"
        conn, cur = _conn(fetchone={"w": True})
        with patch.object(db, "as_user", return_value=conn):
            r = c.post(
                f"/projects/{self.pid}/tokens",
                data={
                    "name": "eso",
                    "role": "read-only",
                    "expires_days": str(config.MAX_EXPIRY_DAYS + 1),
                },
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        inserts = [
            c
            for c in cur.execute.call_args_list
            if c.args and "INSERT INTO api.machine_tokens" in str(c.args[0])
        ]
        self.assertEqual(inserts, [])

    def test_machine_token_roles_config(self):
        self.assertIn("read-only", config.MACHINE_TOKEN_ROLES)
        self.assertIn("write", config.MACHINE_TOKEN_ROLES)
        self.assertEqual(config.MAX_EXPIRY_DAYS, 3650)
        self.assertGreaterEqual(config.MAX_CONTENT_LENGTH, 64 * 1024)
        self.assertEqual(store.app.config.get("MAX_CONTENT_LENGTH"), config.MAX_CONTENT_LENGTH)

    def test_parse_expires_at_capped(self):
        from routes.projects import _parse_expires_at
        from datetime import datetime, timezone, timedelta
        from werkzeug.datastructures import MultiDict

        far = (datetime.now(timezone.utc) + timedelta(days=config.MAX_EXPIRY_DAYS + 30)).date().isoformat()
        with self.assertRaises(ValueError):
            _parse_expires_at(MultiDict({"expires_at": far}))

    def test_import_file_size_cap(self):
        from io import BytesIO

        c = store.app.test_client()
        with c.session_transaction() as s:
            s["user_id"] = str(uuid4())
            s["email"] = "u@ex.com"
        # Slightly over import cap; Flask may 413 if over MAX_CONTENT_LENGTH
        big = b"K=" + (b"x" * (config.MAX_IMPORT_BYTES + 10))
        conn, _ = _conn(fetchone={"w": True})
        with patch.object(db, "as_user", return_value=conn):
            r = c.post(
                f"/projects/{self.pid}/import",
                data={"file": (BytesIO(big), "big.env")},
                content_type="multipart/form-data",
                follow_redirects=False,
            )
        self.assertIn(r.status_code, (302, 413))
        if r.status_code == 302:
            with c.session_transaction() as s:
                flashes = s.get("_flashes") or []
            self.assertTrue(
                any("large" in msg.lower() for _c, msg in flashes),
                flashes,
            )


# ── Health ─────────────────────────────────────────────────────────


class TestHealth(unittest.TestCase):
    def test_ok(self):
        conn, _ = _conn()
        with patch.object(db, "connect", return_value=conn):
            r = store.app.test_client().get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])

    def test_down(self):
        with patch.object(db, "connect", side_effect=RuntimeError("db down")):
            r = store.app.test_client().get("/health")
        self.assertEqual(r.status_code, 503)
        data = r.get_json()
        self.assertFalse(data["ok"])
        self.assertNotIn("error", data)

    def test_security_headers(self):
        conn, _ = _conn()
        with patch.object(db, "connect", return_value=conn):
            r = store.app.test_client().get("/health")
        self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(r.headers.get("Referrer-Policy"), "no-referrer")
        csp = r.headers.get("Content-Security-Policy", "")
        self.assertIn("unpkg.com", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("Strict-Transport-Security", r.headers)

    def test_hsts_when_cookie_secure(self):
        conn, _ = _conn()
        with patch.object(db, "connect", return_value=conn), patch.dict(
            os.environ, {"COOKIE_SECURE": "1"}, clear=False
        ):
            r = store.app.test_client().get("/health")
        self.assertIn("Strict-Transport-Security", r.headers)


# ── UI shell ───────────────────────────────────────────────────────


class TestUIShell(unittest.TestCase):
    def test_login_is_auth_layout(self):
        r = store.app.test_client().get("/login")
        self.assertIn(b'class="auth"', r.data)
        self.assertIn(b"auth-card", r.data)
        self.assertNotIn(b'class="sidebar"', r.data)
        self.assertIn(b"Sigaint", r.data)
        self.assertIn(b"Secret Server", r.data)
        self.assertIn(b"light-dark(#000000, #f5f5f5)", r.data)  # primary black/white

    def test_app_has_sidebar(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s["user_id"] = str(uuid4())
            s["email"] = "x@y.z"
        conn, _ = _conn(fetchall=[])
        with patch.object(db, "as_user", return_value=conn), patch.object(
            authz, "is_global_admin", return_value=False
        ):
            r = c.get("/teams")
        self.assertIn(b'class="app"', r.data)
        self.assertIn(b"sidebar", r.data)
        self.assertIn(b"x@y.z", r.data)
        self.assertIn(b"Log out", r.data)
        self.assertIn(b"Projects", r.data)
        self.assertIn(b"Secrets", r.data)
        self.assertIn(b"Machine accounts", r.data)
        self.assertIn(b"Trash", r.data)
        self.assertIn(b"side-team-select", r.data)
        self.assertNotIn(b"Active team", r.data)
        self.assertNotIn(b"Server settings", r.data)

    def test_global_admin_sees_settings_nav(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s["user_id"] = str(uuid4())
            s["email"] = "admin@ex.com"
            s["is_global_admin"] = True
        conn, _ = _conn(fetchall=[])
        with patch.object(db, "as_user", return_value=conn), patch.object(
            authz, "is_global_admin", return_value=True
        ):
            r = c.get("/teams")
        self.assertIn(b"Server settings", r.data)
        self.assertIn(b"Global admin", r.data)


class TestNav(unittest.TestCase):
    def setUp(self):
        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        self.tid = uuid4()
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "u@ex.com"
            s["team_id"] = str(self.tid)

    def test_select_team(self):
        r = self.client.post(
            "/select-team",
            data={"team_id": str(self.tid), "next": "/projects"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/projects", r.location)
        with self.client.session_transaction() as s:
            self.assertEqual(s["team_id"], str(self.tid))

    def test_projects_list(self):
        pid = uuid4()
        state = {"n": 0}

        def fetchone():
            state["n"] += 1
            return {"id": self.tid, "name": "Ops"}

        conn, cur = _conn(fetchone=fetchone, fetchall=[{"id": pid, "name": "api"}])
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get("/projects")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"api", r.data)

    def test_secrets_list(self):
        conn, _ = _conn(
            fetchone={"id": self.tid, "name": "Ops"},
            fetchall=[
                {
                    "id": uuid4(),
                    "key": "DB_URL",
                    "note": "",
                    "updated_at": "now",
                    "project_id": uuid4(),
                    "project_name": "api",
                }
            ],
        )
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get("/secrets")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"DB_URL", r.data)

    def test_machines_list(self):
        conn, _ = _conn(
            fetchone={"id": self.tid, "name": "Ops"},
            fetchall=[
                {
                    "id": uuid4(),
                    "name": "eso",
                    "token_prefix": "ss_abc",
                    "created_at": "now",
                    "project_id": uuid4(),
                    "project_name": "api",
                }
            ],
        )
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get("/machines")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"eso", r.data)
        self.assertIn(b"Machine accounts", r.data)

    def test_trash_empty_no_team(self):
        conn, _ = _conn(fetchall=[])
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get("/trash")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Trash", r.data)
        self.assertIn(b"Select a team", r.data)

    def test_trash_empty_with_team(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={"id": tid, "name": "Ops"}, fetchall=[])
        with self.client.session_transaction() as s:
            s["team_id"] = str(tid)
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get("/trash")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Nothing in trash", r.data)

    def test_trash_with_items(self):
        tid = uuid4()
        pid = uuid4()
        sid = uuid4()
        conn, _ = _conn(
            fetchone={"id": tid, "name": "Ops"},
            fetchall=[
                {
                    "id": sid,
                    "key": "DB_URL",
                    "note": "old",
                    "deleted_at": "2026-01-01",
                    "project_id": pid,
                    "project_name": "prod",
                    "can_write": True,
                }
            ],
        )
        with self.client.session_transaction() as s:
            s["team_id"] = str(tid)
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get("/trash")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"DB_URL", r.data)
        self.assertIn(b"Restore", r.data)
        self.assertIn(b"Delete forever", r.data)
        # Two-step confirm for permanent purge
        self.assertIn("Delete forever — this cannot be undone".encode(), r.data)
        self.assertIn(b"&& confirm(", r.data)

    def test_restore_secret(self):
        conn, cur = _conn()
        cur.rowcount = 1
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/trash/secrets/{uuid4()}/restore",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/trash", r.location)

    def test_restore_secret_denied(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/trash/secrets/{uuid4()}/restore",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        with self.client.session_transaction() as s:
            flashes = s.get("_flashes") or []
        self.assertTrue(
            any("could not" in msg.lower() or "permission" in msg.lower() for _c, msg in flashes),
            f"expected deny flash, got {flashes!r}",
        )

    def test_purge_secret(self):
        conn, _ = _conn()
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/trash/secrets/{uuid4()}/purge",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/trash", r.location)


# ── Global admin / settings ───────────────────────────────────────


class TestSettings(unittest.TestCase):
    def setUp(self):
        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())

    def test_settings_requires_login(self):
        r = self.client.get("/settings")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.location)

    def test_settings_requires_global_admin(self):
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "u@ex.com"
            s["is_global_admin"] = False
        conn, _ = _conn(fetchall=[])
        with patch.object(db, "as_user", return_value=conn), patch.object(
            authz, "is_global_admin", return_value=False
        ):
            r = self.client.get("/settings", follow_redirects=False)
        self.assertEqual(r.status_code, 302)

    def test_demoted_admin_denied_despite_session_flag(self):
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "was-admin@ex.com"
            s["is_global_admin"] = True
        with patch.object(authz, "is_global_admin", return_value=False):
            r = self.client.get("/settings", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/projects", r.location)
        with self.client.session_transaction() as s:
            self.assertFalse(s.get("is_global_admin"))

    def test_settings_ok_for_global_admin(self):
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "admin@ex.com"
            s["is_global_admin"] = True
        settings = {
            "registration_enabled": "true",
            "user_team_creation_enabled": "true",
            "classification_enabled": "true",
            "classification_text": "SECRET",
            "classification_color": "#c62828",
            "classification_fg": "#ffffff",
        }
        with patch.object(db, "as_user", return_value=_conn(fetchall=[])[0]), patch.object(
            db, "connect_admin", return_value=_conn(fetchall=[])[0]
        ), patch.object(authz, "is_global_admin", return_value=True), patch.object(
            settings_svc, "get_settings", return_value=settings
        ), patch.object(
            settings_svc,
            "classification",
            return_value={
                "enabled": True,
                "text": "SECRET",
                "color": "#c62828",
                "fg": "#ffffff",
            },
        ):
            r = self.client.get("/settings")
        self.assertEqual(r.status_code, 200)
        # Tab navigation present
        self.assertIn(b"?tab=general", r.data)
        self.assertIn(b"?tab=banner", r.data)
        self.assertIn(b"?tab=admins", r.data)
        self.assertIn(b"?tab=ldap", r.data)
        self.assertIn(b"?tab=email", r.data)
        # Default tab is general
        self.assertIn(b"Account registration", r.data)
        self.assertIn(b"Team creation", r.data)
        self.assertNotIn(b"Save banner", r.data)
        self.assertNotIn(b"Make global admin", r.data)

    def test_settings_banner_tab(self):
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "admin@ex.com"
            s["is_global_admin"] = True
        settings = {
            "classification_enabled": "true",
            "classification_text": "SECRET",
            "classification_color": "#c62828",
            "classification_fg": "#ffffff",
        }
        with patch.object(db, "as_user", return_value=_conn(fetchall=[])[0]), patch.object(
            db, "connect_admin", return_value=_conn(fetchall=[])[0]
        ), patch.object(authz, "is_global_admin", return_value=True), patch.object(
            settings_svc, "get_settings", return_value=settings
        ), patch.object(
            settings_svc,
            "classification",
            return_value={
                "enabled": True,
                "text": "SECRET",
                "color": "#c62828",
                "fg": "#ffffff",
            },
        ):
            r = self.client.get("/settings?tab=banner")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Classification banner", r.data)
        self.assertIn(b"SECRET", r.data)

    def test_settings_admins_tab(self):
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "admin@ex.com"
            s["is_global_admin"] = True
        conn, _ = _conn(
            fetchall=[
                {
                    "id": self.uid,
                    "email": "admin@ex.com",
                    "name": "Admin",
                    "is_global_admin": True,
                    "created_at": "now",
                }
            ]
        )
        with patch.object(db, "as_user", return_value=conn), patch.object(
            db, "connect_admin", return_value=conn
        ), patch.object(authz, "is_global_admin", return_value=True), patch.object(
            settings_svc, "get_settings", return_value={}
        ), patch.object(
            settings_svc,
            "classification",
            return_value={"enabled": False, "text": "", "color": "#000", "fg": "#fff"},
        ):
            r = self.client.get("/settings?tab=admins")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Global admins", r.data)

    def test_save_classification(self):
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "admin@ex.com"
            s["is_global_admin"] = True
        sets = []

        def set_setting(k, v):
            sets.append((k, v))

        with patch.object(authz, "is_global_admin", return_value=True), patch.object(
            settings_svc, "set_setting", side_effect=set_setting
        ), patch.object(db, "as_user", return_value=_conn(fetchall=[])[0]):
            r = self.client.post(
                "/settings",
                data={
                    "action": "classification",
                    "classification_enabled": "1",
                    "classification_text": "OFFICIAL",
                    "classification_color": "#677381",
                    "classification_fg": "#ffffff",
                },
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/settings", r.location)
        self.assertIn("tab=banner", r.location)
        self.assertEqual(
            dict(sets),
            {
                "classification_enabled": "true",
                "classification_text": "OFFICIAL",
                "classification_color": "#677381",
                "classification_fg": "#ffffff",
            },
        )

    def test_settings_email_tab(self):
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "admin@ex.com"
            s["is_global_admin"] = True
        settings = {
            "smtp_enabled": "true",
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "smtp_encryption": "starttls",
            "smtp_username": "mailer",
            "smtp_password": "enc",
            "smtp_from_email": "noreply@example.com",
            "smtp_from_name": "Secret Store",
            "smtp_login_alerts": "true",
        }
        with patch.object(db, "as_user", return_value=_conn(fetchall=[])[0]), patch.object(
            db, "connect_admin", return_value=_conn(fetchall=[])[0]
        ), patch.object(authz, "is_global_admin", return_value=True), patch.object(
            settings_svc, "get_settings", return_value=settings
        ), patch.object(
            settings_svc,
            "classification",
            return_value={"enabled": False, "text": "", "color": "#000", "fg": "#fff"},
        ):
            r = self.client.get("/settings?tab=email")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Email (SMTP)", r.data)
        self.assertIn(b"smtp.example.com", r.data)
        self.assertIn(b"login alert", r.data.lower())
        self.assertIn(b"Send test", r.data)

    def test_save_smtp(self):
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "admin@ex.com"
            s["is_global_admin"] = True
        sets = []

        def set_setting(k, v):
            sets.append((k, v))

        with patch.object(authz, "is_global_admin", return_value=True), patch.object(
            settings_svc, "set_setting", side_effect=set_setting
        ), patch.object(db, "as_user", return_value=_conn(fetchall=[])[0]), patch.object(
            crypto, "encrypt", return_value="encrypted-pw"
        ):
            r = self.client.post(
                "/settings",
                data={
                    "action": "smtp",
                    "smtp_enabled": "1",
                    "smtp_host": "smtp.example.com",
                    "smtp_port": "465",
                    "smtp_encryption": "ssl",
                    "smtp_username": "user",
                    "smtp_password": "secret",
                    "smtp_from_email": "noreply@example.com",
                    "smtp_from_name": "SS",
                    "smtp_login_alerts": "1",
                },
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("tab=email", r.location)
        d = dict(sets)
        self.assertEqual(d["smtp_enabled"], "true")
        self.assertEqual(d["smtp_host"], "smtp.example.com")
        self.assertEqual(d["smtp_port"], "465")
        self.assertEqual(d["smtp_encryption"], "ssl")
        self.assertEqual(d["smtp_password"], "encrypted-pw")
        self.assertEqual(d["smtp_login_alerts"], "true")

    def test_smtp_test_action(self):
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "admin@ex.com"
            s["is_global_admin"] = True
        with patch.object(authz, "is_global_admin", return_value=True), patch.object(
            db, "as_user", return_value=_conn(fetchall=[])[0]
        ), patch("mailer.send_test_email", return_value=(True, "")) as send:
            r = self.client.post(
                "/settings",
                data={"action": "smtp_test", "test_email": "admin@ex.com"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("tab=email", r.location)
        send.assert_called_once_with("admin@ex.com")


class TestTotp(unittest.TestCase):
    def test_verify_code_window(self):
        import totp_svc
        import pyotp

        secret = pyotp.random_base32()
        code = pyotp.TOTP(secret).now()
        self.assertTrue(totp_svc.verify_code(secret, code))
        self.assertFalse(totp_svc.verify_code(secret, "000000"))
        self.assertFalse(totp_svc.verify_code(secret, "abcdef"))

    def test_recovery_code_hash_roundtrip(self):
        import totp_svc

        codes = totp_svc.generate_recovery_codes(3)
        self.assertEqual(len(codes), 3)
        self.assertRegex(codes[0], r"^[a-f0-9]{4}-[a-f0-9]{4}$")
        h = totp_svc.hash_recovery_code(codes[0])
        self.assertEqual(h, totp_svc.hash_recovery_code(codes[0].upper().replace("-", "")))

    def test_needs_challenge(self):
        import totp_svc

        uid = str(uuid4())
        with patch.object(totp_svc, "is_enabled", return_value=True):
            self.assertEqual(totp_svc.needs_challenge(uid, False), "verify")
        with patch.object(totp_svc, "is_enabled", return_value=False), patch.object(
            totp_svc, "enforce_global_admins", return_value=True
        ):
            self.assertEqual(totp_svc.needs_challenge(uid, True), "enroll")
            self.assertIsNone(totp_svc.needs_challenge(uid, False))
        with patch.object(totp_svc, "is_enabled", return_value=False), patch.object(
            totp_svc, "enforce_global_admins", return_value=False
        ):
            self.assertIsNone(totp_svc.needs_challenge(uid, True))

    def test_login_redirects_to_2fa(self):
        store.app.config["TESTING"] = True
        client = store.app.test_client()
        uid = uuid4()
        conn, _ = _conn(fetchone={"id": uid, "email": "a@b.c", "name": "A"})
        with patch.object(db, "connect", return_value=conn), patch.object(
            ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}
        ), patch("lockout.is_locked", return_value=False), patch(
            "lockout.clear_failures"
        ), patch.object(authz, "is_global_admin", return_value=False), patch(
            "totp_svc.needs_challenge", return_value="verify"
        ):
            r = client.post(
                "/login",
                data={"email": "a@b.c", "password": "secret12"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login/2fa", r.location)
        with client.session_transaction() as s:
            self.assertEqual(s.get("pending_2fa_uid"), str(uid))
            self.assertNotIn("user_id", s)

    def test_login_2fa_ok(self):
        store.app.config["TESTING"] = True
        client = store.app.test_client()
        uid = str(uuid4())
        with client.session_transaction() as s:
            s["pending_2fa_uid"] = uid
            s["pending_2fa_email"] = "a@b.c"
            s["pending_2fa_name"] = "A"
            s["pending_2fa_admin"] = False
        with patch("totp_svc.verify_user_code", return_value=(True, "totp")), patch(
            "lockout.is_locked", return_value=False
        ), patch("lockout.clear_failures"), patch(
            "user_sessions.create_session", return_value=None
        ), patch("mailer.login_alerts_enabled", return_value=False):
            r = client.post(
                "/login/2fa",
                data={"code": "123456"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/teams", r.location)
        with client.session_transaction() as s:
            self.assertEqual(s.get("user_id"), uid)
            self.assertNotIn("pending_2fa_uid", s)

    def test_login_enroll_admin(self):
        store.app.config["TESTING"] = True
        client = store.app.test_client()
        uid = uuid4()
        conn, _ = _conn(fetchone={"id": uid, "email": "admin@b.c", "name": "A"})
        with patch.object(db, "connect", return_value=conn), patch.object(
            ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}
        ), patch("lockout.is_locked", return_value=False), patch(
            "lockout.clear_failures"
        ), patch.object(authz, "is_global_admin", return_value=True), patch(
            "totp_svc.needs_challenge", return_value="enroll"
        ), patch("user_sessions.create_session", return_value=None):
            r = client.post(
                "/login",
                data={"email": "admin@b.c", "password": "secret12"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/profile/2fa", r.location)
        with client.session_transaction() as s:
            self.assertEqual(s.get("user_id"), str(uid))
            self.assertTrue(s.get("totp_setup_required"))

    def test_save_totp_enforce_setting(self):
        store.app.config["TESTING"] = True
        client = store.app.test_client()
        uid = str(uuid4())
        with client.session_transaction() as s:
            s["user_id"] = uid
            s["email"] = "admin@ex.com"
            s["is_global_admin"] = True
        sets = []
        with patch.object(authz, "is_global_admin", return_value=True), patch.object(
            settings_svc, "set_setting", side_effect=lambda k, v: sets.append((k, v))
        ), patch.object(db, "as_user", return_value=_conn(fetchall=[])[0]):
            r = client.post(
                "/settings",
                data={"action": "totp_enforce", "totp_enforce_global_admins": "1"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertEqual(dict(sets).get("totp_enforce_global_admins"), "true")

    def test_schema_has_totp(self):
        from pathlib import Path

        init = (Path(__file__).resolve().parents[1] / "db" / "init.sql").read_text()
        self.assertIn("totp_secret_enc", init)
        self.assertIn("totp_recovery_codes", init)
        self.assertIn("totp_enforce_global_admins", init)


class TestMailer(unittest.TestCase):
    def test_smtp_configured_requires_host_and_from(self):
        import mailer

        self.assertFalse(
            mailer.smtp_configured(
                {
                    "smtp_enabled": "true",
                    "smtp_host": "",
                    "smtp_from_email": "a@b.c",
                }
            )
        )
        self.assertFalse(
            mailer.smtp_configured(
                {
                    "smtp_enabled": "false",
                    "smtp_host": "h",
                    "smtp_from_email": "a@b.c",
                }
            )
        )
        self.assertTrue(
            mailer.smtp_configured(
                {
                    "smtp_enabled": "true",
                    "smtp_host": "smtp.example.com",
                    "smtp_from_email": "a@b.c",
                }
            )
        )

    def test_login_alerts_need_smtp(self):
        import mailer

        self.assertFalse(
            mailer.login_alerts_enabled(
                {
                    "smtp_enabled": "true",
                    "smtp_host": "h",
                    "smtp_from_email": "a@b.c",
                    "smtp_login_alerts": "false",
                }
            )
        )
        self.assertTrue(
            mailer.login_alerts_enabled(
                {
                    "smtp_enabled": "true",
                    "smtp_host": "h",
                    "smtp_from_email": "a@b.c",
                    "smtp_login_alerts": "true",
                }
            )
        )

    def test_send_email_not_configured(self):
        import mailer

        ok, err = mailer.send_email(
            "a@b.c",
            "subj",
            "body",
            cfg={"smtp_enabled": "false", "smtp_host": "", "smtp_from_email": ""},
        )
        self.assertFalse(ok)
        self.assertIn("SMTP", err)

    def test_send_email_starttls(self):
        import mailer

        cfg = {
            "smtp_enabled": "true",
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "smtp_encryption": "starttls",
            "smtp_username": "u",
            "smtp_password": "",
            "smtp_from_email": "from@ex.com",
            "smtp_from_name": "App",
        }
        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        with patch("mailer.smtplib.SMTP", return_value=mock_smtp) as SMTP:
            ok, err = mailer.send_email("to@ex.com", "Hello", "Body text", cfg=cfg)
        self.assertTrue(ok, err)
        self.assertEqual(err, "")
        SMTP.assert_called_once()
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("u", "")
        mock_smtp.send_message.assert_called_once()

    def test_forgot_password_sends_email(self):
        store.app.config["TESTING"] = True
        client = store.app.test_client()
        with patch("passwords.create_reset_token", return_value="tok123"), patch(
            "mailer.smtp_configured", return_value=True
        ), patch("mailer.send_password_reset", return_value=(True, "")) as send:
            r = client.post(
                "/forgot-password",
                data={"email": "user@ex.com"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        send.assert_called_once()
        args = send.call_args[0]
        self.assertEqual(args[0], "user@ex.com")
        self.assertIn("/reset-password/tok123", args[1])

    def test_login_sends_alert_when_enabled(self):
        store.app.config["TESTING"] = True
        client = store.app.test_client()
        uid = uuid4()
        conn, _ = _conn(fetchone={"id": uid, "email": "a@b.c", "name": "A"})
        with patch.object(db, "connect", return_value=conn), patch.object(
            ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}
        ), patch.object(settings_svc, "setup_notice", return_value=None), patch.object(
            lockout, "is_locked", return_value=False
        ), patch.object(lockout, "clear_failures"), patch.object(
            authz, "is_global_admin", return_value=False
        ), patch("mailer.login_alerts_enabled", return_value=True), patch(
            "mailer.send_login_alert", return_value=(True, "")
        ) as alert, patch.object(user_sessions, "create_session", return_value=None):
            r = client.post(
                "/login",
                data={"email": "a@b.c", "password": "secret12"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        alert.assert_called_once()
        self.assertEqual(alert.call_args[0][0], "a@b.c")


if __name__ == "__main__":
    unittest.main()


# ── LDAP helpers / maps ────────────────────────────────────────────


class TestLDAPHelpers(unittest.TestCase):
    def test_group_tokens_cn(self):
        t = ldap_auth.group_tokens("CN=Admins,OU=Groups,DC=ex,DC=com")
        self.assertIn("cn=admins,ou=groups,dc=ex,dc=com", t)
        self.assertIn("admins", t)
        self.assertIn("cn=admins", t)

    def test_group_matches_cn_or_dn(self):
        groups = ["CN=eng-secrets,OU=Groups,DC=ex,DC=com", "other"]
        self.assertTrue(ldap_auth.group_matches("eng-secrets", groups))
        self.assertTrue(
            ldap_auth.group_matches("CN=eng-secrets,OU=Groups,DC=ex,DC=com", groups)
        )
        self.assertFalse(ldap_auth.group_matches("nope", groups))

    def test_ldap_escape(self):
        self.assertEqual(ldap_auth.ldap_escape("a*b(c)"), "a\\2ab\\28c\\29")

    def test_ldap_disabled_returns_none(self):
        with patch.object(ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}):
            self.assertIsNone(ldap_auth.ldap_authenticate("u", "p"))


class TestLDAPMaps(unittest.TestCase):
    def setUp(self):
        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        self.tid = uuid4()
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["email"] = "owner@ex.com"
            s["is_global_admin"] = False

    def test_add_team_ldap_map(self):
        conn, _ = _conn()
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{self.tid}/ldap-maps",
                data={"ldap_group": "eng-secrets", "role": "member"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn(str(self.tid), r.location)

    def test_add_team_ldap_map_empty_group(self):
        r = self.client.post(
            f"/teams/{self.tid}/ldap-maps",
            data={"ldap_group": "  ", "role": "member"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 302)

    def test_delete_team_ldap_map(self):
        mid = uuid4()
        conn, _ = _conn()
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{self.tid}/ldap-maps/{mid}/delete",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)

    def test_sync_ldap_user_applies_maps(self):
        uid = uuid4()
        tid = uuid4()
        fo = [
            {"id": uid},  # upsert_ldap_user
            {  # final user select
                "id": uid,
                "email": "u@ex.com",
                "name": "U",
                "is_global_admin": True,
            },
            None,  # existing membership lookup
        ]
        fa = [
            [{"ldap_group": "admins", "role": "global_admin"}],
            [{"id": uuid4(), "team_id": tid, "ldap_group": "admins", "role": "admin"}],
        ]
        conn, cur = _conn()
        cur.fetchone.side_effect = fo
        cur.fetchall.side_effect = fa
        with patch.object(db, "connect_admin", return_value=conn):
            user = ldap_auth.sync_ldap_user("u@ex.com", "U", ["CN=admins,OU=g,DC=x"])
        self.assertEqual(str(user["id"]), str(uid))
        self.assertTrue(user["is_global_admin"])
        executed = " ".join(str(c) for c in cur.execute.call_args_list).lower()
        self.assertIn("team_members", executed)
        self.assertIn("upsert_ldap_user", executed)
