from __future__ import annotations

import pytest
from unittest.mock import patch
from uuid import uuid4

import app as store
from core import db, settings_svc
from tests.helpers import mock_conn
from secret_svc.folders import parse_secret_path


store.app.config["TESTING"] = True


def test_folder_access_tab_renders_shared_binding_panel():
    project_id = uuid4()
    folder_id = uuid4()
    conn, cur = mock_conn()
    cur.fetchone.side_effect = [
        {"id": folder_id, "project_id": project_id, "path": "ops"},
        {"id": project_id, "name": "prod", "team_name": "Ops", "team_id": uuid4()},
        {"a": True},
        {"a": True},
    ]
    cur.fetchall.side_effect = [[], [], []]
    with store.app.test_client() as client:
        with client.session_transaction() as session:
            session["user_id"] = str(uuid4())
            session["email"] = "folder@example.test"
            session["is_global_admin"] = False
        with patch.object(settings_svc, "get_settings", return_value={}), patch.object(
            db, "as_user", return_value=conn
        ):
            response = client.get(f"/projects/{project_id}/folders/{folder_id}?tab=access")

    assert response.status_code == 200
    assert b"Access" in response.data
    assert b"Add binding" in response.data


def test_parse_secret_path_splits_root_and_nested_keys():
    assert parse_secret_path("folder/1/2/3/secret") == (("folder", "1", "2", "3"), "secret")
    assert parse_secret_path("secret") == ((), "secret")


@pytest.mark.parametrize("key", ["/secret", "folder//secret", "folder/./secret", "folder/../secret", "folder\\secret"])
def test_parse_secret_path_rejects_unsafe_segments(key):
    with pytest.raises(ValueError):
        parse_secret_path(key)


def test_materialize_folder_path_returns_existing_leaf():
    from secret_svc.folders import materialize_folder_path

    cur = pytest.importorskip("unittest.mock").MagicMock()
    cur.fetchone.side_effect = [
        {"id": "root-id"},
        {"id": "leaf-id"},
    ]

    assert materialize_folder_path(cur, "project-id", ("root", "child")) == "leaf-id"
    assert cur.execute.call_count == 2


def test_materialize_root_path_has_no_folder():
    from secret_svc.folders import materialize_folder_path

    cur = pytest.importorskip("unittest.mock").MagicMock()

    assert materialize_folder_path(cur, "project-id", ()) is None
    cur.execute.assert_not_called()


def test_upsert_secret_uses_materialized_folder_identity():
    from secret_svc.secret_ops import _upsert_secret

    cur = pytest.importorskip("unittest.mock").MagicMock()
    cur.fetchone.side_effect = [
        {"id": "folder-id"},
        None,
        {"id": "secret-id"},
    ]

    assert _upsert_secret(
        cur,
        "project-id",
        "folder/secret",
        "ciphertext",
        already_enc=True,
    ) == ("secret-id", True)
    assert any("folder_id" in call.args[0] for call in cur.execute.call_args_list)


def test_upsert_root_secret_uses_null_safe_unique_conflict_target():
    from secret_svc.secret_ops import _upsert_secret

    cur = pytest.importorskip("unittest.mock").MagicMock()
    cur.fetchone.side_effect = [None, {"id": "secret-id"}]

    assert _upsert_secret(
        cur,
        "project-id",
        "secret",
        "ciphertext",
        already_enc=True,
    ) == ("secret-id", True)
    insert_sql = cur.execute.call_args_list[-1].args[0]
    assert "ON CONFLICT (project_id, key)" in insert_sql
    assert "folder_id IS NULL" in insert_sql


def test_delete_folder_rejects_live_descendant_secrets():
    from secret_svc.folders import delete_empty_folder

    cur = pytest.importorskip("unittest.mock").MagicMock()
    cur.fetchone.return_value = {"blocked": True}

    with pytest.raises(ValueError, match="contains secrets"):
        delete_empty_folder(cur, "project-id", "folder-id")
    assert cur.execute.call_count == 1


def test_delete_folder_rejects_trashed_descendant_secrets():
    from secret_svc.folders import delete_empty_folder

    cur = pytest.importorskip("unittest.mock").MagicMock()
    cur.fetchone.return_value = {"blocked": True}

    with pytest.raises(ValueError, match="contains secrets"):
        delete_empty_folder(cur, "project-id", "folder-id")
    assert "s.deleted_at IS NULL" not in cur.execute.call_args.args[0]


def test_delete_empty_folder_removes_empty_subtree():
    from secret_svc.folders import delete_empty_folder

    cur = pytest.importorskip("unittest.mock").MagicMock()
    cur.fetchone.side_effect = [{"blocked": False}, {"id": "folder-id"}]

    assert delete_empty_folder(cur, "project-id", "folder-id") == "folder-id"
    assert cur.execute.call_count == 2


def test_visible_folder_paths_only_uses_returned_secret_rows():
    from secret_svc.folders import visible_folder_paths

    assert visible_folder_paths([{"key": "ops/prod/API_KEY"}, {"key": "root"}]) == [
        "ops",
        "ops/prod",
    ]
