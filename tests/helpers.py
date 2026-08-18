"""Shared test helpers (mock DB connections, etc.)."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock

# Repo root (…/secretserver) and flat app module tree (…/secretserver/app).
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"

_UNSET = object()


def routes_module_src(name: str) -> str:
    """Return the concatenated source of a routes module (package or file).

    Route modules may be split into packages; this reads either the package
    directory's ``*.py`` files or the flat ``<name>.py`` module.
    """
    pkg = APP_ROOT / "routes" / name
    if pkg.is_dir():
        return "\n".join(f.read_text() for f in sorted(pkg.glob("*.py")))
    return (pkg.with_suffix(".py")).read_text()


def migrations_src() -> str:
    """Return the concatenated versioned migration SQL (db/migrations/*.sql)."""
    d = REPO_ROOT / "db" / "migrations"
    return "\n".join(f.read_text() for f in sorted(d.glob("*.sql")))


def mock_conn(fetchone=_UNSET, fetchall=_UNSET, side_effect=None):
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
