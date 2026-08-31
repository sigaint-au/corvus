"""Unit tests for folder paths, commands, RBAC scope, and schema (mock DB)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from werkzeug.exceptions import Forbidden, NotFound

from lib.folders import (
    join_key,
    segments,
    split_key,
    validate_key,
    validate_path,
)
from secret_svc.folder_ops import (
    create_folder,
    delete_folder,
    move_folder,
)
from tests.helpers import APP_ROOT, REPO_ROOT, mock_conn, migrations_src, routes_module_src


# ── Path utilities ────────────────────────────────────────────────────────
def test_split_key_leaves_and_folders():
    assert split_key("a/b/c") == ("a/b", "c")
    assert split_key("API_KEY") == (None, "API_KEY")
    assert split_key("prod") == (None, "prod")


def test_join_and_segments():
    assert join_key("a/b", "c") == "a/b/c"
    assert join_key(None, "c") == "c"
    assert segments("a/b/c") == ["a", "b", "c"]
    assert segments("/a/b/") == ["a", "b"]


@pytest.mark.parametrize(
    "bad",
    ["", "/a", "a/", "a//b", "a/./b", "a/../b", "..", ".", "a b", "a b/c",
     "/".join(f"s{i}" for i in range(17)), "a..", "-", "_", "heavy/slash/../x"],
)
def test_validate_path_rejects(bad):
    with pytest.raises(ValueError):
        validate_path(bad)


def test_validate_path_normalizes_and_allows():
    assert validate_path("prod/db") == "prod/db"
    assert validate_path("/prod/db/") == "prod/db"
    assert validate_path("hosts.web01") == "hosts.web01"


def test_validate_key_rejects_bad_leaf():
    with pytest.raises(ValueError):
        validate_key("prod/")
    with pytest.raises(ValueError):
        validate_key("prod//x")
    with pytest.raises(ValueError):
        validate_key("")
    assert validate_key("prod/db/password") == "prod/db/password"


# ── SQL source ───────────────────────────────────────────────────────────
def test_folders_sql_ships_in_migrations():
    src = (REPO_ROOT / "db" / "migrations" / "0003_folders.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS api.folders" in src
    assert "ADD COLUMN IF NOT EXISTS folder_id" in src
    assert "UNIQUE (project_id, path)" in src
    assert "FORCE ROW LEVEL SECURITY" in src
    assert "ensure_folder_path" in src
    assert "rbac_scope_chain" in src
    assert "can_manage_rbac" in src


def test_rbac_scope_chain_walks_folder_parents():
    src = (REPO_ROOT / "db" / "migrations" / "0001_init.sql").read_text()
    assert "api.rbac_scope_chain(" in src
    chain = (REPO_ROOT / "db" / "migrations" / "0003_folders.sql").read_text()
    assert "WITH RECURSIVE folder_chain" in chain
    assert "WHERE f.id = p_scope_id" in chain


def test_validate_binding_scope_allows_folder_for_secret_roles():
    src = (REPO_ROOT / "db" / "migrations" / "0003_folders.sql").read_text()
    assert "r_name LIKE 'secret-%'" in src
    assert "NOT IN ('secret', 'folder')" in src


def test_folder_routes_registered(app):
    rules = {r.rule for r in app.url_map.iter_rules()}
    assert "/projects/<uuid:project_id>/folders" in rules
    assert "/projects/<uuid:project_id>/folders/<uuid:folder_id>/delete" in rules
    assert "/projects/<uuid:project_id>/folders/<uuid:folder_id>/move" in rules
    assert "/projects/<uuid:project_id>/folders/<uuid:folder_id>" in rules


def test_mgmt_api_folder_routes_registered(app):
    rules = {r.rule for r in app.url_map.iter_rules()}
    assert "/api/v1/manage/projects/<project_ref>/folders" in rules
    assert "/api/v1/manage/projects/<project_ref>/folders/<folder_ref>/move" in rules
    assert "/api/v1/manage/projects/<project_ref>/folders/<folder_ref>" in rules


# ── RBAC helper scope mapping ────────────────────────────────────────────
def test_folder_scope_uses_secret_role_dropdown_and_allowed():
    from routes.rbac.helpers import _role_allowed_at_scope, _role_dropdown_for_scope

    names = [n for n, _ in _role_dropdown_for_scope("folder")]
    assert names == ["secret-write", "secret-reveal", "secret-read"]
    assert _role_allowed_at_scope("secret-reveal", "folder")
    assert _role_allowed_at_scope("secret-read", "folder")
    assert not _role_allowed_at_scope("project-write", "folder")


def test_config_has_folder_scope_and_events():
    from core import config

    assert "folder" in config.RBAC_SCOPE_KINDS
    assert "org.folder_created" in config.WEBHOOK_EVENTS["Project events"]
    assert "org.folder_deleted" in config.WEBHOOK_EVENTS["Project events"]
    assert "org.folder_moved" in config.WEBHOOK_EVENTS["Project events"]


# ── Commands (mocked cursor) ─────────────────────────────────────────────
def test_create_folder_validates_and_ensures():
    cur = MagicMock()
    cur.fetchone.return_value = {"fid": "abc"}
    fid = create_folder(cur, uuid4(), "/prod/db/", actor_email="t@e.st")
    assert fid == "abc"
    called = " ".join(str(c.args[0]) for c in cur.execute.call_args_list)
    assert "ensure_folder_path" in called
    assert "audit_org" in called


def test_create_folder_rejects_bad_path():
    cur = MagicMock()
    with pytest.raises(ValueError):
        create_folder(cur, uuid4(), "a/../b", actor_email="t@e.st")


def test_delete_folder_refuses_nonempty_without_recursive():
    cur = MagicMock()
    cur.fetchone.side_effect = [{"id": "f1"}, {"n": 3}, {"n": 0}]
    with pytest.raises(Forbidden):
        delete_folder(cur, "f1", project_id=uuid4(), actor_email="t@e.st")


def test_delete_empty_folder_ok():
    cur = MagicMock()
    cur.fetchone.side_effect = [{"id": "f1"}, {"n": 0}, {"n": 0}]
    delete_folder(cur, "f1", project_id=uuid4(), actor_email="t@e.st")
    executed = " ".join(str(c.args[0]) for c in cur.execute.call_args_list)
    assert "DELETE FROM api.folders WHERE id = %s" in executed


def test_recursive_delete_trashes_descendants():
    cur = MagicMock()
    cur.fetchone.side_effect = [{"id": "f1"}, {"n": 5}, {"n": 1}]
    cur.fetchall.return_value = [{"id": "abc"}]
    delete_folder(cur, "f1", project_id=uuid4(), recursive=True, actor_email="t@e.st")
    executed = "\n".join(str(c.args[0]) for c in cur.execute.call_args_list)
    assert "WITH RECURSIVE subtree" in executed
    assert "SET deleted_at = now()" in executed
    assert "RETURNING id" in executed


def test_move_folder_refuses_collision():
    cur = MagicMock()
    cur.fetchone.side_effect = [
        {"id": "f1", "path": "prod", "project_id": "p1"},  # folder lookup
        {"n": 2},  # secret collision count
    ]
    with pytest.raises(Forbidden):
        move_folder(cur, "f1", "staging", project_id="p1", actor_email="t@e.st")


def test_move_folder_rewrites_keys():
    cur = MagicMock()
    cur.fetchone.side_effect = [
        {"id": "f1", "path": "prod", "project_id": "p1"},
        {"n": 0},  # no collision
        {"n": 0},  # no folder collision
    ]
    result = move_folder(cur, "f1", "staging", project_id="p1", actor_email="t@e.st")
    assert result == "f1"
    executed = "\n".join(str(c.args[0]) for c in cur.execute.call_args_list)
    assert "substr(path, %s)" in executed
    assert "substr(key, %s)" in executed
    assert "folder_moved" in str(cur.execute.call_args_list)


def test_bindings_route_handles_folder_scope():
    src = routes_module_src("rbac")
    assert 'scope_kind == "folder"' in src
    assert "folders" in src


def test_secret_upsert_hooks_folder_ensure():
    src = (APP_ROOT / "secret_svc" / "commands.py").read_text()
    assert "split_key" in src
    assert "ensure_path" in src


def test_detail_passes_folder_params():
    src = (APP_ROOT / "routes" / "projects" / "detail.py").read_text()
    assert "list_children" in src
    assert "current_folder" in src
    assert "folder_crumbs" in src