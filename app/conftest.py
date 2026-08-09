"""Pytest configuration and shared fixtures for unit tests."""
from __future__ import annotations

import os
from contextlib import contextmanager
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

# Must set env before any app module import (also mirrored in test modules).
# connect_timeout=1 so accidental unmocked connects fail fast (no DNS hang).
_FAKE_DSN = "postgres://test:test@127.0.0.1:1/test?connect_timeout=1"
os.environ.setdefault("DATABASE_URL", _FAKE_DSN)
os.environ.setdefault("DATABASE_ADMIN_URL", _FAKE_DSN)
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-change-me-32chars!!")
os.environ.setdefault("MASTER_KEY", "test-master-key-change-in-prod!!")
os.environ.setdefault("SECRET_KEY", "test-flask-session-secret")
os.environ.setdefault("ALLOW_INSECURE_DEFAULTS", "1")


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


_UNSET = object()


def make_conn(fetchone=_UNSET, fetchall=_UNSET, side_effect=None):
    """Build a mock DB connection/cursor pair used across unit tests."""
    cur = MagicMock()
    if side_effect is not None:
        cur.execute.side_effect = side_effect
    if fetchone is not _UNSET:
        if callable(fetchone) and not isinstance(fetchone, dict):
            cur.fetchone.side_effect = fetchone
        else:
            cur.fetchone.return_value = fetchone
    else:
        cur.fetchone.return_value = None
    if fetchall is not _UNSET:
        cur.fetchall.return_value = fetchall
    else:
        cur.fetchall.return_value = []

    def cursor(*_a, **_k):
        @contextmanager
        def cm():
            yield cur

        return cm()

    conn = MagicMock()
    conn.cursor.side_effect = cursor
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)
    return conn, cur


@pytest.fixture
def mock_conn():
    """Factory fixture: ``conn, cur = mock_conn(fetchone=..., fetchall=...)``."""
    return make_conn
