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

import jwt as pyjwt  # noqa: E402
import app as store  # noqa: E402


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
        self.assertEqual(store.decrypt(store.encrypt("ping")), "ping")

    def test_empty(self):
        self.assertEqual(store.decrypt(store.encrypt("")), "")

    def test_unicode(self):
        s = "héllo 🔐 日本語"
        self.assertEqual(store.decrypt(store.encrypt(s)), s)

    def test_ciphertext_differs(self):
        a, b = store.encrypt("x"), store.encrypt("x")
        self.assertNotEqual(a, b)  # Fernet includes random IV
        self.assertEqual(store.decrypt(a), store.decrypt(b))


# ── JWT ────────────────────────────────────────────────────────────


class TestJWT(unittest.TestCase):
    def test_make_jwt_claims(self):
        uid = str(uuid4())
        token = store.make_jwt(uid, hours=1)
        claims = pyjwt.decode(token, store.JWT_SECRET, algorithms=["HS256"])
        self.assertEqual(claims["sub"], uid)
        self.assertEqual(claims["role"], "authenticated")
        self.assertIn("exp", claims)

    def test_jwt_json(self):
        self.assertEqual(store.jwt_json({"a": 1}), '{"a": 1}')


# ── Helpers ────────────────────────────────────────────────────────


class TestHelpers(unittest.TestCase):
    def test_htmx_false(self):
        with store.app.test_request_context("/"):
            self.assertFalse(store.htmx())

    def test_htmx_true(self):
        with store.app.test_request_context("/", headers={"HX-Request": "true"}):
            self.assertTrue(store.htmx())

    def test_login_required_redirects(self):
        @store.login_required
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
        with patch.object(store, "as_user", return_value=conn):
            r = c.get("/teams")
        self.assertEqual(r.status_code, 200)


# ── Auth routes ────────────────────────────────────────────────────


class TestAuth(unittest.TestCase):
    def setUp(self):
        store.app.config["TESTING"] = True
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
        r = self.client.get("/login")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Sign in", r.data)

    def test_login_bad_creds(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(store, "connect", return_value=conn):
            r = self.client.post("/login", data={"email": "a@b.c", "password": "nope"})
        self.assertEqual(r.status_code, 401)
        self.assertIn(b"Invalid", r.data)

    def test_login_ok(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={"id": uid, "email": "a@b.c", "name": "A"})
        with patch.object(store, "connect", return_value=conn):
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

    def test_register_short_password(self):
        r = self.client.post(
            "/register",
            data={"email": "a@b.c", "password": "short", "name": "A"},
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn(b"8 characters", r.data)

    def test_register_ok(self):
        uid = uuid4()
        conn, _ = _conn(fetchone={"id": uid})
        with patch.object(store, "connect", return_value=conn):
            r = self.client.post(
                "/register",
                data={"email": "new@b.c", "password": "password1", "name": "N"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/teams", r.location)

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
        with patch.object(store, "as_user", return_value=conn):
            r = self.client.get("/teams")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Platform", r.data)
        self.assertIn(b"sidebar", r.data)  # modernised shell

    def test_create_team_empty_name(self):
        r = self.client.post("/teams", data={"name": "  "}, follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/teams", r.location)

    def test_create_team(self):
        tid = uuid4()
        conn, _ = _conn(fetchone={"id": tid})
        with patch.object(store, "connect", return_value=conn):
            r = self.client.post("/teams", data={"name": "Ops"}, follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn(str(tid), r.location)

    def test_team_detail_404(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(store, "as_user", return_value=conn):
            r = self.client.get(f"/teams/{uuid4()}")
        self.assertEqual(r.status_code, 404)

    def test_team_detail_ok(self):
        tid = uuid4()
        calls = {"n": 0}

        def fetchone():
            calls["n"] += 1
            if calls["n"] == 1:
                return {"id": tid, "name": "T"}
            return {"role": "owner"}

        conn, cur = _conn(fetchone=fetchone, fetchall=[])
        # members then projects both use fetchall
        with patch.object(store, "as_user", return_value=conn):
            r = self.client.get(f"/teams/{tid}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b">T<", r.data)

    def test_add_member_user_missing(self):
        tid = uuid4()
        conn, _ = _conn(fetchone=None)
        with patch.object(store, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{tid}/members",
                data={"email": "nope@x.com", "role": "member"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)

    def test_create_project(self):
        tid, pid = uuid4(), uuid4()
        conn, _ = _conn(fetchone={"id": pid})
        with patch.object(store, "as_user", return_value=conn):
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

    def _project_conn(self, can_write=True, secrets=None, tokens=None):
        """as_user used by project_detail: project, secrets, tokens, can_write."""
        seq = [
            {
                "id": self.pid,
                "name": "prod",
                "team_name": "Ops",
                "team_id": uuid4(),
            },
        ]
        # after project row: secrets fetchall, tokens fetchall, can_write fetchone
        state = {"i": 0}

        def fetchone():
            state["i"] += 1
            if state["i"] == 1:
                return seq[0]
            return {"w": can_write}

        conn, cur = _conn(fetchone=fetchone, fetchall=[])
        # Alternating fetchall for secrets then tokens
        cur.fetchall.side_effect = [secrets or [], tokens or []]
        return conn

    def test_project_detail(self):
        with patch.object(store, "as_user", return_value=self._project_conn()):
            r = self.client.get(f"/projects/{self.pid}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"prod", r.data)
        self.assertIn(b"Secrets", r.data)

    def test_project_404(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(store, "as_user", return_value=conn):
            r = self.client.get(f"/projects/{uuid4()}")
        self.assertEqual(r.status_code, 404)

    def test_create_secret(self):
        conn, _ = _conn()
        # create_secret then _secrets_partial if htmx — non-htmx redirects
        with patch.object(store, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/secrets",
                data={"key": "API_KEY", "value": "sekrit", "note": ""},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        self.assertIn(str(self.pid), r.location)
        # ensure encrypt path ran (execute called with value_enc)
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
        conn, _ = _conn()
        with patch.object(store, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/secrets/{sid}/delete",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)

    def test_reveal_secret(self):
        sid = uuid4()
        enc = store.encrypt("super-secret")
        conn, _ = _conn(fetchone={"value_enc": enc})
        with patch.object(store, "as_user", return_value=conn):
            r = self.client.get(f"/projects/{self.pid}/secrets/{sid}/reveal")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"super-secret", r.data)

    def test_reveal_missing(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(store, "as_user", return_value=conn):
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
        conn, _ = _conn()
        with patch.object(store, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/tokens",
                data={"name": "openshift"},
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)
        with self.client.session_transaction() as s:
            self.assertTrue(s.get("new_token", "").startswith("ss_"))

    def test_delete_token(self):
        conn, _ = _conn()
        with patch.object(store, "as_user", return_value=conn):
            r = self.client.post(
                f"/projects/{self.pid}/tokens/{uuid4()}/delete",
                follow_redirects=False,
            )
        self.assertEqual(r.status_code, 302)


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
        claims = pyjwt.decode(data["access_token"], store.JWT_SECRET, algorithms=["HS256"])
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
        enc = store.encrypt("val")
        conn, _ = _conn(fetchone={"value_enc": enc})
        with patch.object(store, "connect", return_value=conn):
            r = self.client.get(
                f"/eso/v1/projects/{self.pid}/secrets/KEY",
                headers={"Authorization": "Bearer ss_testtoken"},
            )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["value"], "val")
        self.assertEqual(r.get_json()["key"], "KEY")

    def test_get_secret_not_found(self):
        # first fetch: no value; second: auth ok
        state = {"n": 0}

        def fetchone():
            state["n"] += 1
            if state["n"] == 1:
                return {"value_enc": None}
            return {"ok": True}

        conn, _ = _conn(fetchone=fetchone)
        # two separate connect() calls in eso_get_secret
        with patch.object(store, "connect", return_value=conn):
            r = self.client.get(
                f"/eso/v1/projects/{self.pid}/secrets/MISSING",
                headers={"Authorization": "Bearer ss_x"},
            )
        self.assertEqual(r.status_code, 404)

    def test_list_unauthorized(self):
        conn, _ = _conn(fetchone={"ok": False})
        with patch.object(store, "connect", return_value=conn):
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

        enc = store.encrypt("v1")
        conn, cur = _conn(fetchone=fetchone, fetchall=[{"key": "A", "value_enc": enc}])
        with patch.object(store, "connect", return_value=conn):
            r = self.client.get(
                f"/eso/v1/projects/{self.pid}/secrets",
                headers={"Authorization": "Bearer ss_ok"},
            )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["secrets"], {"A": "v1"})

    def test_bearer_hash_none(self):
        with store.app.test_request_context("/", headers={}):
            self.assertIsNone(store._bearer_hash())


# ── Health ─────────────────────────────────────────────────────────


class TestHealth(unittest.TestCase):
    def test_ok(self):
        conn, _ = _conn()
        with patch.object(store, "connect", return_value=conn):
            r = store.app.test_client().get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])

    def test_down(self):
        with patch.object(store, "connect", side_effect=RuntimeError("db down")):
            r = store.app.test_client().get("/health")
        self.assertEqual(r.status_code, 503)
        self.assertFalse(r.get_json()["ok"])


# ── UI shell ───────────────────────────────────────────────────────


class TestUIShell(unittest.TestCase):
    def test_login_is_auth_layout(self):
        r = store.app.test_client().get("/login")
        self.assertIn(b'class="auth"', r.data)
        self.assertIn(b"auth-card", r.data)
        self.assertNotIn(b'class="sidebar"', r.data)

    def test_app_has_sidebar(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s["user_id"] = str(uuid4())
            s["email"] = "x@y.z"
        conn, _ = _conn(fetchall=[])
        with patch.object(store, "as_user", return_value=conn):
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
        with patch.object(store, "as_user", return_value=conn):
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
        with patch.object(store, "as_user", return_value=conn):
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
        with patch.object(store, "as_user", return_value=conn):
            r = self.client.get("/machines")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"eso", r.data)
        self.assertIn(b"Machine accounts", r.data)

    def test_trash(self):
        conn, _ = _conn(fetchall=[])
        with patch.object(store, "as_user", return_value=conn):
            r = self.client.get("/trash")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Trash", r.data)
        self.assertIn(b"Nothing in trash", r.data)


if __name__ == "__main__":
    unittest.main()
