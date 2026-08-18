"""Unit tests (pytest). Mock DB — no Postgres required."""

from __future__ import annotations

import os
from unittest.mock import patch
from uuid import uuid4

import pytest

import app as store
from auth import authz
from core import config, db
from tests.helpers import mock_conn as _conn
from ui import paging

store.app.config["TESTING"] = True


class TestHelpers:
    def test_htmx_false(self):
        with store.app.test_request_context("/"):
            assert not authz.htmx()

    def test_htmx_true(self):
        with store.app.test_request_context("/", headers={"HX-Request": "true"}):
            assert authz.htmx()

    def test_login_required_redirects(self):

        @authz.login_required
        def protected():
            return "ok"

        with store.app.test_request_context("/x"):
            resp = protected()
            assert resp.status_code == 302
            assert "/login" in resp.location

    def test_login_required_passes(self):
        c = store.app.test_client()
        with c.session_transaction() as sess:
            sess["user_id"] = str(uuid4())
            sess["email"] = "t@t.t"
        conn, _ = _conn(fetchall=[])
        with patch.object(db, "as_user", return_value=conn):
            r = c.get("/teams")
        assert r.status_code == 200

    def test_safe_redirect_allows_relative(self):
        assert authz.safe_redirect_target("/teams", "/x") == "/teams"
        assert authz.safe_redirect_target(None, "/x") == "/x"

    def test_safe_redirect_blocks_open_redirect(self):
        assert authz.safe_redirect_target("//evil", "/x") == "/x"
        assert authz.safe_redirect_target("https://evil", "/x") == "/x"
        assert authz.safe_redirect_target("teams", "/x") == "/x"

    def test_page_window_basic(self):
        w = paging.page_window(100, 2, per_page=25)
        assert w["page"] == 2
        assert w["offset"] == 25
        assert w["pages"] == 4
        assert w["has_prev"]
        assert w["has_next"]

    def test_page_window_empty(self):
        w = paging.page_window(0, 1)
        assert w["pages"] == 1
        assert w["start"] == 0
        assert w["end"] == 0


class TestRefuseInsecureDefaults:
    def test_opt_in_allows(self):
        with patch.dict(os.environ, {"ALLOW_INSECURE_DEFAULTS": "1"}, clear=False):
            os.environ.pop("FLASK_ENV", None)
            config.refuse_insecure_defaults()

    def test_blocks_default_secrets(self):
        with (
            patch.dict(os.environ, {"ALLOW_INSECURE_DEFAULTS": "0"}, clear=False),
            patch.object(config, "SECRET_KEY", config._DEFAULT_SECRET_KEY),
            patch.object(config, "JWT_SECRET", config._DEFAULT_JWT_SECRET),
            patch.object(config, "MASTER_KEY", config._DEFAULT_MASTER_KEY),
        ):
            os.environ.pop("FLASK_ENV", None)
            with pytest.raises(SystemExit):
                config.refuse_insecure_defaults()
