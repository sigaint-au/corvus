"""Unit tests (pytest). Mock DB — no Postgres required."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

import app as store
import crypto
from core import db
from integrations import ldap_auth
from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True


class TestLdapPassword:
    def test_empty(self):
        assert ldap_auth.ldap_password_plain({}) == ""
        assert ldap_auth.ldap_password_plain({"ldap_bind_password": "  "}) == ""

    def test_decrypts(self):
        enc = crypto.encrypt("bind-secret")
        assert ldap_auth.ldap_password_plain({"ldap_bind_password": enc}) == "bind-secret"

    def test_decrypt_failure_returns_empty_not_ciphertext(self):
        bad = "not-valid-fernet-ciphertext"
        assert ldap_auth.ldap_password_plain({"ldap_bind_password": bad}) == ""


class TestLdapTlsPolicy:
    def test_ldaps_ok_without_starttls(self):
        assert ldap_auth.ldap_tls_required_ok("ldaps://ipa.example.com", False)

    def test_ldap_requires_starttls(self):
        assert not ldap_auth.ldap_tls_required_ok("ldap://ipa.example.com", False)
        assert ldap_auth.ldap_tls_required_ok("ldap://ipa.example.com", True)

    def test_empty_url_rejected(self):
        assert not ldap_auth.ldap_tls_required_ok("", True)

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
            assert ldap_auth.ldap_authenticate("user", "pass") is None


class TestLdapStartTLS:
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
        assert order[:3] == ["open", "start_tls", "bind"]
        assert not conn.auto_bind

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
            with pytest.raises(RuntimeError) as cm:
                ldap_auth._ldap_bind(object(), start_tls=True)
        assert "StartTLS" in str(cm.value)
        assert bound["n"] == 0


class TestLDAPHelpers:
    def test_group_tokens_cn(self):
        t = ldap_auth.group_tokens("CN=Admins,OU=Groups,DC=ex,DC=com")
        assert "cn=admins,ou=groups,dc=ex,dc=com" in t
        assert "admins" in t
        assert "cn=admins" in t

    def test_group_matches_cn_or_dn(self):
        groups = ["CN=eng-secrets,OU=Groups,DC=ex,DC=com", "other"]
        assert ldap_auth.group_matches("eng-secrets", groups)
        assert ldap_auth.group_matches("CN=eng-secrets,OU=Groups,DC=ex,DC=com", groups)
        assert not ldap_auth.group_matches("nope", groups)

    def test_ldap_escape(self):
        assert ldap_auth.ldap_escape("a*b(c)") == "a\\2ab\\28c\\29"

    def test_ldap_disabled_returns_none(self):
        with patch.object(ldap_auth, "ldap_cfg", return_value={"ldap_enabled": "false"}):
            assert ldap_auth.ldap_authenticate("u", "p") is None


class TestLDAPMaps:
    def setup_method(self, method=None):
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
                data={"ldap_group": "eng-secrets", "role": "team-member"},
                follow_redirects=False,
            )
        assert r.status_code == 302
        assert str(self.tid) in r.location

    def test_add_team_ldap_map_empty_group(self):
        r = self.client.post(
            f"/teams/{self.tid}/ldap-maps",
            data={"ldap_group": "  ", "role": "team-member"},
            follow_redirects=False,
        )
        assert r.status_code == 302

    def test_delete_team_ldap_map(self):
        mid = uuid4()
        conn, _ = _conn()
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{self.tid}/ldap-maps/{mid}/delete", follow_redirects=False
            )
        assert r.status_code == 302

    def test_add_team_ldap_map_accepts_team_scope_role(self):
        # 'auditor' is a team-scope role in rbac.roles, so directory maps accept it.
        conn, cur = _conn()
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{self.tid}/ldap-maps",
                data={"ldap_group": "eng-secrets", "role": "auditor"},
                follow_redirects=False,
            )
        assert r.status_code == 302
        executed = " ".join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        assert "insert into api.team_ldap_maps" in executed

    def test_add_team_oidc_map_ok(self):
        conn, cur = _conn()
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{self.tid}/oidc-maps",
                data={"oidc_group": "eng-secrets", "role": "team-viewer"},
                follow_redirects=False,
            )
        assert r.status_code == 302
        executed = " ".join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        assert "insert into api.team_oidc_maps" in executed

    def test_add_team_oidc_map_rejects_unknown_role(self):
        # Unknown roles are rejected inside the request (no map INSERT).
        conn, cur = _conn()
        with patch.object(db, "as_user", return_value=conn):
            r = self.client.post(
                f"/teams/{self.tid}/oidc-maps",
                data={"oidc_group": "eng-secrets", "role": "superuser"},
                follow_redirects=False,
            )
        assert r.status_code == 302
        assert str(self.tid) in r.location
        executed = " ".join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        assert "insert into api.team_oidc_maps" not in executed

    def test_team_rbac_rank_matches_directory_roles(self):
        from auth.roles import team_role_rank

        conn, cur = _conn()
        assert team_role_rank(cur) == {
            "team-owner": 4,
            "team-admin": 3,
            "team-member": 2,
            "team-viewer": 1,
        }

    def test_apply_team_membership_maps_skips_unranked_role(self):
        from integrations import dir_sync

        tid = uuid4()
        conn, cur = _conn()
        dir_sync.apply_team_membership_maps(
            cur,
            str(uuid4()),
            ["eng-secrets"],
            [{"team_id": tid, "ldap_group": "eng-secrets", "role": "auditor"}],
            group_key="ldap_group",
            source="ldap",
        )
        executed = " ".join(str(c.args[0]) for c in cur.execute.call_args_list).lower()
        assert "insert into rbac.bindings" not in executed

    def test_sync_ldap_user_applies_maps(self):
        uid = uuid4()
        tid = uuid4()
        # upsert id, then fetch_user_row at end
        fo = [
            {"id": uid},
            {
                "id": uid,
                "email": "u@ex.com",
                "name": "U",
                "is_global_admin": True,
            },
        ]
        # ldap role maps, team ldap maps, directory groups for membership maps
        fa = [
            [{"ldap_group": "admins", "role": "global_admin"}],
            [
                {
                    "id": uuid4(),
                    "team_id": tid,
                    "ldap_group": "admins",
                    "role": "team-admin",
                }
            ],
            [],  # api.groups with external_key
        ]
        conn, cur = _conn()

        # cycle user row after first id so extra fetchones don't StopIteration
        def _fo():
            yield from fo
            while True:
                yield fo[-1]

        cur.fetchone.side_effect = _fo()

        def _fa():
            yield from fa
            while True:
                yield []

        cur.fetchall.side_effect = _fa()
        with patch.object(db, "connect_admin", return_value=conn):
            user = ldap_auth.sync_ldap_user("u@ex.com", "U", ["CN=admins,OU=g,DC=x"])
        assert str(user["id"]) == str(uid)
        assert user["is_global_admin"]
        executed = " ".join(str(c) for c in cur.execute.call_args_list).lower()
        assert "rbac.bindings" in executed
        assert "upsert_ldap_user" in executed
