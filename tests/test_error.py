"""Unit tests for the minimal WebUI error pages (pytest, mocked DB)."""

from __future__ import annotations

from uuid import uuid4

import app as store

store.app.config["TESTING"] = True


class TestErrorPages:
    def test_404_renders_minimal_themed_page(self):
        c = store.app.test_client()
        r = c.get("/definitely/not/a/route")
        assert r.status_code == 404
        assert b'class="error-code"' in r.data
        assert b">404</p>" in r.data
        assert b"Not found" in r.data

    def test_404_has_no_sidebar(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s["user_id"] = str(uuid4())
        r = c.get("/definitely/not/a/route")
        assert r.status_code == 404
        assert b"sidebar" not in r.data

    def test_404_has_no_action_buttons(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s["user_id"] = str(uuid4())
        r = c.get("/definitely/not/a/route")
        assert b"Back to Projects" not in r.data
        assert b"Sign in" not in r.data

    def test_404_api_returns_json(self):
        c = store.app.test_client()
        r = c.get("/api/definitely/not/real", headers={"Accept": "application/json"})
        assert r.status_code == 404
        data = r.get_json()
        assert data["error"] == "Not found"
        assert data["status"] == 404

    def test_404_htmx_returns_json_not_html(self):
        c = store.app.test_client()
        r = c.get("/nope/nope", headers={"X-Requested-With": "XMLHttpRequest"})
        assert r.status_code == 404
        body = r.get_json(silent=True)
        assert body is not None and body["error"] == "Not found"
        assert b"error-code" not in r.data
