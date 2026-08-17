"""Unit tests for the themed WebUI error pages (pytest, mocked DB)."""
from __future__ import annotations

from uuid import uuid4

import app as store

store.app.config["TESTING"] = True


class TestErrorPages:

    def test_404_renders_themed_html(self):
        c = store.app.test_client()
        r = c.get("/definitely/not/a/route")
        assert r.status_code == 404
        assert b"Not found" in r.data
        assert b'class="list-panel error-panel"' in r.data
        assert b'class="error-code"' in r.data
        assert b"Sign in" in r.data

    def test_404_logged_in_shows_nav_actions(self):
        c = store.app.test_client()
        with c.session_transaction() as s:
            s["user_id"] = str(uuid4())
        r = c.get("/definitely/not/a/route")
        assert r.status_code == 404
        assert b"Back to Projects" in r.data

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
        assert b'class="list-panel error-panel"' not in r.data