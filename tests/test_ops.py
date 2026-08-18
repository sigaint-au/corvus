"""Operational job tests."""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

from core import db
from ops import due_notifications, send_due_notifications, sync_directory
from tests.helpers import mock_conn as _conn


def test_due_notifications_groups_admin_and_token_owner():
    conn, cur = _conn()
    cur.fetchall.side_effect = [
        [{"email": "admin@example.com"}],
        [{"project_name": "prod", "key": "API_KEY", "expires_at": "soon"}],
        [{"project_name": "prod", "name": "eso", "token_prefix": "ss_abc", "expires_at": "soon"}],
        [
            {
                "email": "alice@example.com",
                "name": "laptop",
                "token_prefix": "pat_abc",
                "expires_at": "soon",
            }
        ],
        [
            {
                "project_name": "prod",
                "key": "DB",
                "requester": "bob@example.com",
                "created_at": "now",
            }
        ],
    ]
    with conn.cursor() as c:
        out = due_notifications(c, 14)
    assert "admin@example.com" in out
    assert any("Secret prod/API_KEY" in line for line in out["admin@example.com"])
    assert any("Machine token prod/eso" in line for line in out["admin@example.com"])
    assert any("Pending reveal approval prod/DB" in line for line in out["admin@example.com"])
    assert out["alice@example.com"] == ["Personal access token laptop (pat_abc) expires soon"]


def test_send_due_notifications_dry_run_does_not_send():
    conn, cur = _conn()
    cur.fetchall.side_effect = [[{"email": "admin@example.com"}], [], [], [], []]
    with (
        patch.object(db, "connect_admin", return_value=conn),
        patch("integrations.mailer.send_email") as send,
    ):
        result = send_due_notifications(dry_run=True)
    assert result == {"recipients": 0, "sent": 0, "failed": 0}
    send.assert_not_called()


def test_sync_directory_disables_stale_users(tmp_path):
    uid = uuid4()
    active = tmp_path / "active.txt"
    active.write_text("active@example.com\n", encoding="utf-8")
    conn, cur = _conn(fetchall=[{"id": uid, "email": "gone@example.com"}])
    cur.rowcount = 1
    with patch.object(db, "connect_admin", return_value=conn):
        result = sync_directory(source="oidc", active_email_file=str(active))
    assert result["disabled"] == 1
    assert result["revoked_sessions"] == 1
    assert result["revoked_tokens"] == 1
    sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
    assert "disabled_at = now()" in sql
    assert "DELETE FROM private.personal_access_tokens" in sql


def test_sync_directory_refuses_empty_roster(tmp_path):
    active = tmp_path / "active.txt"
    active.write_text("\n", encoding="utf-8")
    try:
        sync_directory(source="oidc", active_email_file=str(active))
    except ValueError as exc:
        assert "empty" in str(exc)
    else:
        raise AssertionError("empty roster accepted")
