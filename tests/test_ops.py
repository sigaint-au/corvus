"""Operational job tests."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from core import db
from ops import (
    _ldap_entry_locked,
    due_notifications,
    ldap_active_emails,
    send_due_notifications,
    sync_directory,
)
from tests.helpers import mock_conn as _conn


def test_due_notifications_groups_admin_and_token_owner():
    conn, cur = _conn()
    cur.fetchall.side_effect = [
        [{"email": "admin@example.com"}],
        [{"project_name": "prod", "key": "API_KEY", "expires_at": "soon"}],
        [{"project_name": "prod", "name": "eso", "token_prefix": "ss_abc", "expires_at": "soon"}],
        [{"email": "alice@example.com", "name": "laptop", "token_prefix": "pat_abc", "expires_at": "soon"}],
        [{"project_name": "prod", "key": "DB", "requester": "bob@example.com", "created_at": "now"}],
    ]
    with conn.cursor() as c:
        out = due_notifications(c, 14)
    assert "admin@example.com" in out
    assert any("Secret prod/API_KEY" in line for line in out["admin@example.com"])
    assert any("Machine token prod/eso" in line for line in out["admin@example.com"])
    assert any("Pending reveal approval prod/DB" in line for line in out["admin@example.com"])
    assert out["alice@example.com"] == ["Personal access token laptop (pat_abc) expires soon"]


def test_due_notifications_excludes_secrets_with_exclude_due_notify_meta():
    conn, cur = _conn()
    cur.fetchall.side_effect = [
        [{"email": "admin@example.com"}],
        [], [], [], [],
    ]
    with conn.cursor() as c:
        due_notifications(c, 14)
    sql = " ".join(str(a.args[0]) for a in cur.execute.call_args_list if a.args)
    assert "exclude-due-notify" in sql and "exclude_due_notify" in sql
    assert "NOT EXISTS" in sql


def test_send_due_notifications_dry_run_does_not_send():
    conn, cur = _conn()
    cur.fetchall.side_effect = [[{"email": "admin@example.com"}], [], [], [], []]
    with patch.object(db, "connect_admin", return_value=conn), patch("integrations.mailer.send_email") as send:
        result = send_due_notifications(dry_run=True)
    assert result == {"recipients": 0, "sent": 0, "failed": 0}
    send.assert_not_called()


def test_sync_directory_disables_stale_users(tmp_path):
    uid = uuid4()
    active = tmp_path / "active.txt"
    active.write_text("active@example.com\n", encoding="utf-8")
    conn, cur = _conn(fetchall=[{"id": uid, "email": "gone@example.com", "is_global_admin": False}])
    cur.rowcount = 1
    with patch.object(db, "connect_admin", return_value=conn):
        result = sync_directory(source="oidc", active_email_file=str(active))
    assert result["disabled"] == 1
    assert result["disabled_emails"] == ["gone@example.com"]
    assert result["revoked_sessions"] == 1
    assert result["revoked_cli_tokens"] == 1
    assert "revoked_tokens" not in result
    sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
    assert "disabled_at = now()" in sql
    assert "DELETE FROM private.cli_session_tokens" in sql
    assert "personal_access_tokens" not in sql
    assert "audit_org" in sql


def test_sync_directory_refuses_empty_roster(tmp_path):
    active = tmp_path / "active.txt"
    active.write_text("\n", encoding="utf-8")
    try:
        sync_directory(source="oidc", active_email_file=str(active))
    except ValueError as exc:
        assert "empty" in str(exc)
    else:
        raise AssertionError("empty roster accepted")


def test_sync_directory_dry_run_lists_emails_without_writing(tmp_path):
    uid = uuid4()
    active = tmp_path / "active.txt"
    active.write_text("active@example.com\n", encoding="utf-8")
    conn, cur = _conn(fetchall=[{"id": uid, "email": "gone@example.com", "is_global_admin": False}])
    with patch.object(db, "connect_admin", return_value=conn):
        result = sync_directory(source="oidc", active_email_file=str(active), dry_run=True)
    assert result["disabled"] == 1
    assert result["disabled_emails"] == ["gone@example.com"]
    assert result["revoked_sessions"] == 0
    assert result["revoked_cli_tokens"] == 0
    sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
    assert "UPDATE" not in sql
    assert "DELETE" not in sql


def test_sync_directory_refuses_small_roster(tmp_path):
    active = tmp_path / "active.txt"
    active.write_text("active@example.com\n", encoding="utf-8")
    conn, cur = _conn(fetchall=[])
    cur.fetchone.side_effect = [{"n": 10}, {"n": 0}]
    with patch.object(db, "connect_admin", return_value=conn):
        try:
            sync_directory(source="oidc", active_email_file=str(active))
        except ValueError as exc:
            assert "80%" in str(exc)
        else:
            raise AssertionError("truncated roster accepted")


def test_sync_directory_force_overrides_small_roster(tmp_path):
    uid = uuid4()
    active = tmp_path / "active.txt"
    active.write_text("active@example.com\n", encoding="utf-8")
    conn, cur = _conn(fetchall=[{"id": uid, "email": "gone@example.com", "is_global_admin": False}])
    cur.fetchone.side_effect = [{"n": 10}, {"n": 0}]
    cur.rowcount = 1
    with patch.object(db, "connect_admin", return_value=conn):
        result = sync_directory(source="oidc", active_email_file=str(active), force=True)
    assert result["disabled"] == 1


def test_sync_directory_force_allows_empty_roster(tmp_path):
    active = tmp_path / "active.txt"
    active.write_text("\n", encoding="utf-8")
    conn, cur = _conn()
    with patch.object(db, "connect_admin", return_value=conn):
        result = sync_directory(source="oidc", active_email_file=str(active), force=True)
    assert result == {
        "source": "oidc",
        "disabled": 0,
        "disabled_emails": [],
        "revoked_sessions": 0,
        "revoked_cli_tokens": 0,
    }


def test_sync_directory_refuses_last_admin(tmp_path):
    uid = uuid4()
    active = tmp_path / "active.txt"
    active.write_text("active@example.com\nsecond@example.com\n", encoding="utf-8")
    for kwargs in ({}, {"force": True}):
        conn, cur = _conn(fetchall=[{"id": uid, "email": "admin@example.com", "is_global_admin": True}])
        cur.fetchone.side_effect = [{"n": 2}, {"n": 1}]
        with patch.object(db, "connect_admin", return_value=conn):
            try:
                sync_directory(source="oidc", active_email_file=str(active), **kwargs)
            except ValueError as exc:
                assert "last active global admin" in str(exc)
            else:
                raise AssertionError(f"last admin disabled ({kwargs})")


def test_sync_directory_allows_admin_when_successor_remains(tmp_path):
    uid = uuid4()
    active = tmp_path / "active.txt"
    active.write_text("active@example.com\n", encoding="utf-8")
    conn, cur = _conn(fetchall=[{"id": uid, "email": "gone-admin@example.com", "is_global_admin": True}])
    cur.fetchone.side_effect = [{"n": 1}, {"n": 2}]
    cur.rowcount = 0
    with patch.object(db, "connect_admin", return_value=conn):
        result = sync_directory(source="oidc", active_email_file=str(active))
    assert result["disabled"] == 1


def test_sync_directory_rejects_malformed_roster_lines(tmp_path):
    active = tmp_path / "active.txt"
    active.write_text("# leavers 2026-01\nactive@example.com\nnot-an-email\n", encoding="utf-8")
    try:
        sync_directory(source="oidc", active_email_file=str(active))
    except ValueError as exc:
        assert "invalid email" in str(exc)
    else:
        raise AssertionError("mangled roster accepted")


def test_sync_directory_source_order_insensitive(tmp_path):
    active = tmp_path / "active.txt"
    active.write_text("active@example.com\n", encoding="utf-8")
    conn, cur = _conn(fetchall=[])
    with patch.object(db, "connect_admin", return_value=conn):
        result = sync_directory(source="oidc,ldap", active_email_file=str(active))
    assert result["source"] == "ldap,oidc"
    assert result["disabled"] == 0


def _entry(attrs):
    return SimpleNamespace(entry_attributes_as_dict=attrs)


def test_ldap_entry_locked_cases():
    assert not _ldap_entry_locked(_entry({"userAccountControl": ["512"]}))
    assert _ldap_entry_locked(_entry({"userAccountControl": ["514"]}))
    assert _ldap_entry_locked(_entry({"userAccountControl": ["66050"]}))
    assert not _ldap_entry_locked(_entry({}))
    assert not _ldap_entry_locked(_entry({"userAccountControl": ["not-a-number"]}))
    assert _ldap_entry_locked(_entry({"nsAccountLock": ["true"]}))
    assert not _ldap_entry_locked(_entry({"nsAccountLock": ["false"]}))
    assert _ldap_entry_locked(_entry({"pwdAccountLockedTime": ["20260101000000Z"]}))


def test_ldap_active_emails_pages_and_skips_locked():
    import ops as ops_mod

    locked = _entry({"mail": ["b@example.com"], "userAccountControl": ["514"]})
    page1 = ([_entry({"mail": ["a@example.com"], "userAccountControl": ["512"]}), locked], b"cookie-1")
    page2 = ([_entry({"mail": ["C@example.com"]})], b"")

    class FakeConn:
        def __init__(self):
            self.entries = []
            self.result = {"controls": {}}
            self.pages = [page1, page2]
            self.searches = 0

        def search(self, *args, **kwargs):
            entries, cookie = self.pages[self.searches]
            self.searches += 1
            self.entries = entries
            self.result = {"controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": cookie}}}}

        def unbind(self):
            pass

    fake = FakeConn()
    cfg = {
        "ldap_enabled": True,
        "ldap_url": "ldaps://dir.example.com",
        "ldap_user_base": "dc=example,dc=com",
        "ldap_start_tls": False,
        "ldap_bind_dn": "",
        "ldap_email_attr": "mail",
    }
    with (
        patch.object(ops_mod.ldap_auth, "ldap_cfg", return_value=cfg),
        patch.object(ops_mod.ldap_auth, "ldap_tls_required_ok", return_value=True),
        patch.object(ops_mod.ldap_auth, "ldap_password_plain", return_value=""),
        patch.object(ops_mod.ldap_auth, "_ldap_bind", return_value=fake),
        patch("ldap3.Server", return_value=object()),
    ):
        assert ldap_active_emails() == {"a@example.com", "c@example.com"}
    assert fake.searches == 2
