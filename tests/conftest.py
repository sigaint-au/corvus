"""Pytest configuration and shared fixtures for unit tests."""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

# Must set env before any app module import.
# connect_timeout=1 so accidental unmocked connects fail fast (no DNS hang).
_FAKE_DSN = "postgres://test:test@127.0.0.1:1/test?connect_timeout=1"
os.environ.setdefault("DATABASE_URL", _FAKE_DSN)
os.environ.setdefault("DATABASE_ADMIN_URL", _FAKE_DSN)
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-change-me-32chars!!")
os.environ.setdefault("MASTER_KEY", "test-master-key-change-in-prod!!")
os.environ.setdefault("SECRET_KEY", "test-flask-session-secret")
os.environ.setdefault("ALLOW_INSECURE_DEFAULTS", "1")

from tests.helpers import mock_conn as make_conn  # noqa: E402


@pytest.fixture(autouse=True)
def close_db_pool():
    yield
    from core import db

    db.close_pools()


@pytest.fixture
def app():
    """Flask application with TESTING enabled (no real schema bootstrap)."""
    import app as store

    store.app.config["TESTING"] = True
    return store.app


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def uid():
    return str(uuid4())


@pytest.fixture
def tid():
    return uuid4()


@pytest.fixture
def mock_conn():
    """Factory fixture: ``conn, cur = mock_conn(fetchone=..., fetchall=...)``."""
    return make_conn
