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
import authz  # noqa: E402
import config  # noqa: E402
import crypto  # noqa: E402
import db  # noqa: E402
import ldap_auth  # noqa: E402
import schema as schema_mod  # noqa: E402
import settings_svc  # noqa: E402
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
        ), patch.object(schema_mod, "GLOBAL_ADMIN_EMAIL", ""):
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
        with patch.object(ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}):
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
        ), patch("lockout.is_locked", return_value=False), patch("lockout.clear_failures"):
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
        ), patch("lockout.is_locked", return_value=False), patch("lockout.clear_failures"):
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
        with patch.object(settings_svc, "registration_enabled", return_value=True):
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
        ):
            r = self.client.post(
                "/register",
                data={"email": "new@b.c", "password": "password1", "name": "N"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/teams", r.location)

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
        ):
            r = self.client.get("/login")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(b'href="/register"', r.data)

    def test_logout(self):
        with self.client.session_transaction() as s:
            s["user_id"] = str(uuid4())
            s["email"] = "a@b.c"
        r = self.client.post("/logout")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.location)
        with self.client.session_transaction() as s:
            self.assertNotIn("user_id", s)


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

    def test_add_member_user_missing(self):
        tid = uuid4()
        conn, _ = _conn(fetchone=None)
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{tid}/members",
                data={"email": "nope@x.com", "role": "member"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)

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

    def test_team_roles_include_read_only(self):
        self.assertIn("read-only", config.TEAM_ROLES)
        self.assertLess(config.ROLE_RANK["read-only"], config.ROLE_RANK["member"])

    def test_add_member_read_only_role(self):
        tid, uid = uuid4(), uuid4()
        conn, cur = _conn(fetchone={"id": uid})
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{tid}/members",
                data={"email": "ro@ex.com", "role": "read-only"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        sql = " ".join(str(c) for c in cur.execute.call_args_list)
        self.assertIn("read-only", sql)

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

    def _project_conn(self, tab="secrets", can_write=True, secrets=None, tokens=None, audit_log=None, total=None):
        """as_user used by project_detail (tab-scoped queries)."""
        project = {
            "id": self.pid,
            "name": "prod",
            "team_name": "Ops",
            "team_id": uuid4(),
        }
        rows = secrets or [] if tab == "secrets" else (audit_log or [] if tab == "audit" else (tokens or []))
        if total is None:
            total = len(rows)
        fo = [project, {"w": can_write}]
        if tab in ("secrets", "audit"):
            fo.append({"n": total})
        fa = [rows] if tab in ("secrets", "audit", "tokens") else []
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
        conn, _ = _conn(
            fetchone={"id": sid, "key": "API_KEY", "value_enc": enc}
        )
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.get(f"/projects/{self.pid}/secrets/{sid}/reveal")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"super-secret", r.data)

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

    def test_settings_ok_for_global_admin(self):
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
        settings = {
            "classification_enabled": "true",
            "classification_text": "SECRET",
            "classification_color": "#c62828",
            "classification_fg": "#ffffff",
        }
        with patch.object(db, "as_user", return_value=conn), patch.object(
            db, "connect_admin", return_value=conn
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
        self.assertIn(b"Classification banner", r.data)
        self.assertIn(b"SECRET", r.data)
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
        self.assertEqual(
            dict(sets),
            {
                "classification_enabled": "true",
                "classification_text": "OFFICIAL",
                "classification_color": "#677381",
                "classification_fg": "#ffffff",
            },
        )


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
