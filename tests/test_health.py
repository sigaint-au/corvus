"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

import app as store
from core import config
from core import db

from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestEsoHealth:
    """Tests for the ESO ``/health`` endpoint and security headers.

    ``/healthz`` (liveness) and ``/readyz`` (readiness) are the container
    probes; ``/health`` here is the ESO (external service) DB-backed one.
    """

    def test_ok(self):
        conn, _ = _conn()
        with patch.object(db, 'connect', return_value=conn):
            r = store.app.test_client().get('/health')
        assert r.status_code == 200
        assert r.get_json()['ok']

    def test_down(self):
        with patch.object(db, 'connect', side_effect=RuntimeError('db down')):
            r = store.app.test_client().get('/health')
        assert r.status_code == 503
        data = r.get_json()
        assert not data['ok']
        assert 'error' not in data

    def test_readyz_rejects_failed_schema_initialization(self):
        app = store.create_app()
        app.config["TESTING"] = False
        with patch("app.ensure_schema", side_effect=RuntimeError("schema down")):
            response = app.test_client().get("/readyz")
        assert response.status_code == 503
        assert response.get_json()["status"] == "not ready"

    def test_security_headers(self):
        conn, _ = _conn()
        with patch.object(db, 'connect', return_value=conn), patch.dict(
            os.environ, {"COOKIE_SECURE": "0", "FLASK_ENV": "development"}, clear=False
        ):
            r = store.app.test_client().get('/health')
        assert r.headers.get('X-Content-Type-Options') == 'nosniff'
        assert r.headers.get('X-Frame-Options') == 'DENY'
        assert r.headers.get('Referrer-Policy') == 'no-referrer'
        csp = r.headers.get('Content-Security-Policy', '')
        assert 'unpkg.com' not in csp
        assert "frame-ancestors 'none'" in csp
        assert 'Strict-Transport-Security' not in r.headers

    def test_hsts_when_cookie_secure(self):
        conn, _ = _conn()
        with patch.object(db, 'connect', return_value=conn), patch.dict(os.environ, {'COOKIE_SECURE': '1'}, clear=False):
            r = store.app.test_client().get('/health')
        assert 'Strict-Transport-Security' in r.headers

