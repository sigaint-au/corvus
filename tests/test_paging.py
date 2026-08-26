"""Pagination, team secrets filters, and machine token scope helpers."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

from core import config, db, settings_svc
from routes.project_tokens import insert_token_scopes, parse_token_scope_lines
from secret_svc.secret_ops import _load_team_secrets_page
from ui import nav, paging


def test_page_window_basic():
    w = paging.page_window(100, 2, per_page=25)
    assert w["page"] == 2
    assert w["offset"] == 25
    assert w["start"] == 26
    assert w["end"] == 50
    assert w["has_prev"] is True
    assert w["has_next"] is True
    assert w["prev_page"] == 1
    assert w["next_page"] == 3


def test_page_window_clamps_high_page():
    w = paging.page_window(10, 99, per_page=25)
    assert w["page"] == 1
    assert w["pages"] == 1


def test_page_window_empty_and_last_page():
    empty = paging.page_window(0, 1, per_page=25)
    assert empty["total"] == 0
    assert empty["pages"] == 1
    assert empty["start"] == 0
    assert empty["end"] == 0
    assert empty["has_prev"] is False
    assert empty["has_next"] is False

    last = paging.page_window(26, 2, per_page=25)
    assert last["page"] == 2
    assert last["offset"] == 25
    assert last["start"] == 26
    assert last["end"] == 26
    assert last["has_prev"] is True
    assert last["has_next"] is False


def test_page_window_clamps_zero_page():
    w = paging.page_window(50, 0, per_page=10)
    assert w["page"] == 1
    assert w["offset"] == 0


def test_parse_token_scope_lines_mixed():
    pairs = parse_token_scope_lines(
        """
        API_KEY
        # ignore
        prod/*
        DB_?
        API_KEY
        """
    )
    assert pairs == [
        ("key", "API_KEY"),
        ("pattern", "prod/*"),
        ("pattern", "DB_?"),
    ]


def test_parse_token_scope_lines_empty():
    assert parse_token_scope_lines("") == []
    assert parse_token_scope_lines("  \n# only\n") == []


def test_parse_token_scope_lines_skips_long_and_dedupes_patterns():
    long_key = "K" * 300
    pairs = parse_token_scope_lines(f"a*\na*\n{long_key}\nexact")
    assert pairs == [("pattern", "a*"), ("key", "exact")]


def test_insert_token_scopes_writes_key_and_pattern():
    cur = MagicMock()
    tid = str(uuid4())
    insert_token_scopes(
        cur,
        tid,
        [("key", "API_KEY"), ("pattern", "prod/*")],
    )
    assert cur.execute.call_count == 2
    sql0, params0 = cur.execute.call_args_list[0].args
    sql1, params1 = cur.execute.call_args_list[1].args
    assert "secret_key" in sql0
    assert params0 == (tid, "API_KEY")
    assert "key_pattern" in sql1
    assert params1 == (tid, "prod/*")


def test_create_token_persists_scopes(client):
    """Creating a machine token with scope_keys inserts scope rows."""
    from contextlib import contextmanager
    from unittest.mock import MagicMock

    pid = uuid4()
    token_id = uuid4()
    uid = str(uuid4())

    cur = MagicMock()
    cur.fetchone.side_effect = [
        {"w": True},  # can_write_project
        {"id": token_id},  # INSERT RETURNING
    ]

    def cursor(*_a, **_k):
        @contextmanager
        def cm():
            yield cur

        return cm()

    conn = MagicMock()
    conn.cursor.side_effect = cursor
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)

    with client.session_transaction() as s:
        s["user_id"] = uid
        s["email"] = "u@ex.com"

    with patch.object(db, "as_user", return_value=conn), patch.object(settings_svc, "token_expiry_policy", return_value=(False, 3650)):
        r = client.post(
            f"/projects/{pid}/tokens",
            data={
                "name": "eso",
                "role": "reveal",
                "expires_days": "30",
                "scope_keys": "API_KEY\nprod/*\n",
            },
            follow_redirects=False,
        )
    assert r.status_code == 302
    insert_sqls = [
        str(c.args[0]) for c in cur.execute.call_args_list if c.args
    ]
    assert any("INSERT INTO api.machine_tokens" in s for s in insert_sqls)
    assert any("machine_token_scope" in s and "secret_key" in s for s in insert_sqls)
    assert any("machine_token_scope" in s and "key_pattern" in s for s in insert_sqls)
    conn.commit.assert_called()


def test_load_team_secrets_page_applies_filters():
    cur = MagicMock()
    # count then page then projects list
    cur.fetchone.side_effect = [{"n": 2}]
    cur.fetchall.side_effect = [
        [
            {
                "id": uuid4(),
                "key": "DB_URL",
                "note": "",
                "kind": "database",
                "updated_at": None,
                "expires_at": None,
                "access_mode": "inherit",
                "project_id": uuid4(),
                "project_name": "api",
            }
        ],
        [],
        [{"id": uuid4(), "name": "api"}],
    ]
    tid = str(uuid4())
    rows, pager, projects = _load_team_secrets_page(
        cur, tid, page=1, q="db", kind="database", due=None, access_mode="inherit"
    )
    assert pager["total"] == 2
    assert pager["endpoint"] == "secrets_list"
    assert pager["kind"] == "database"
    assert len(rows) == 1
    assert rows[0]["key"] == "DB_URL"
    assert rows[0]["access_restricted"] is False
    assert projects and projects[0]["name"] == "api"
    # count query includes kind + acl filters
    count_sql = cur.execute.call_args_list[0].args[0]
    assert "s.kind = %s" in count_sql
    assert "access_mode" in count_sql


def test_redirect_after_team_switch_from_other_project(app):
    pid = "c29f6ab5-6ec7-4484-beb5-8b0741b54713"
    with app.test_request_context("/"):
        with patch.object(nav, "_project_team_id", return_value="other-team"):
            assert (
                nav.redirect_after_team_switch(
                    f"/projects/{pid}?tab=secrets", "new-team"
                )
                == "/secrets"
            )
            assert (
                nav.redirect_after_team_switch(
                    f"/projects/{pid}?tab=settings", "new-team"
                )
                == "/projects"
            )
        assert nav.redirect_after_team_switch("/secrets", "new-team") == "/secrets"


def test_secret_kinds_config():
    assert "database" in config.SECRET_KINDS
    assert "plain" in config.SECRET_KINDS


def test_machine_key_allowed_empty_scope_denies():
    """0011: no scope rows deny; restricted keys need an exact secret_key."""
    from tests.helpers import REPO_ROOT

    sql = (REPO_ROOT / "db" / "migrations" / "0011_machine_token_scope_deny.sql").read_text()
    start = sql.index("CREATE OR REPLACE FUNCTION private.machine_key_allowed")
    end = sql.index("$$;", start) + 3
    body = sql[start:end]
    assert "THEN false" in body
    assert "access_mode" in body
    assert "'restricted'" in body
    assert "glob_to_like" in body
    assert "secret_key = p_key" in body


def test_force_rls_on_core_tables():
    from tests.helpers import REPO_ROOT

    init = (REPO_ROOT / "db" / "migrations" / "0001_init.sql").read_text()
    for table in (
        "api.teams",
        "api.projects",
        "api.secrets",
        "api.machine_tokens",
        "api.machine_token_scope",
    ):
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in init
    assert "ALTER TABLE api.secret_acl FORCE ROW LEVEL SECURITY" not in init
