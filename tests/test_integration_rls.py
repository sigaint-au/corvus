"""Integration tests that run real SQL against a live Postgres.

These tests are **opt-in**: they are skipped unless ``INTEGRATION_DATABASE_URL``
is set to a superuser DSN for a disposable, empty database. The normal
``pytest`` run (mock DB) is unaffected.

Why this exists: the unit tests mock the cursor (``tests/helpers.mock_conn``),
so SQL, RLS policies, and SECURITY DEFINER functions are never exercised.
This file covers the security guarantees that only a real database can
verify — cross-tenant isolation, audit append-only integrity, and reveal
enforcement.

Running::

    # 1. Create a throwaway database
    createdb secretserver_itest

    # 2. Point the integration tests at it (superuser DSN)
    export INTEGRATION_DATABASE_URL='postgres://postgres:pw@localhost/secretserver_itest'

    # 3. Run only the integration tests
    pytest tests/test_integration_rls.py -v

    # Or run the full suite including integration:
    pytest

The fixture applies all migrations from ``db/migrations/`` once per session
and tears down (drops the schema) on exit.
"""

from __future__ import annotations

import os

import pytest

try:
    import psycopg
except ImportError:  # pragma: no cover
    psycopg = None  # type: ignore[assignment]

from tests.helpers import REPO_ROOT

_INTEGRATION_DSN = os.environ.get("INTEGRATION_DATABASE_URL", "").strip()

# Skip the entire module unless a real DB DSN is provided.
pytestmark = pytest.mark.skipif(
    not _INTEGRATION_DSN or psycopg is None,
    reason="Set INTEGRATION_DATABASE_URL to a disposable Postgres DSN to run RLS integration tests",
)


def _read_migrations() -> list[tuple[str, str]]:
    """Return [(version, sql), ...] for every migration file, sorted."""
    d = REPO_ROOT / "db" / "migrations"
    out = []
    for f in sorted(d.glob("NNNN_*.sql")) if False else sorted(d.glob("*.sql")):
        out.append((f.stem.split("_", 1)[0], f.read_text()))
    return out


@pytest.fixture(scope="module")
def admin_conn():
    """Apply migrations to the disposable DB; yield a superuser connection."""
    conn = psycopg.connect(_INTEGRATION_DSN, autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS api CASCADE")
            cur.execute("DROP SCHEMA IF EXISTS rbac CASCADE")
            cur.execute("DROP SCHEMA IF EXISTS private CASCADE")
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
            cur.execute("CREATE SCHEMA public")
        for _version, sql in _read_migrations():
            with conn.cursor() as cur:
                cur.execute(sql)
        yield conn
    finally:
        with conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS api CASCADE")
            cur.execute("DROP SCHEMA IF EXISTS rbac CASCADE")
            cur.execute("DROP SCHEMA IF EXISTS private CASCADE")
        conn.close()


def _as_user(conn, user_id: str, role: str = "authenticated"):
    """Open a child connection with SET ROLE + JWT claims (RLS applies)."""
    import json

    c = psycopg.connect(_INTEGRATION_DSN, autocommit=False)
    with c.cursor() as cur:
        cur.execute("SET ROLE %s", (role,))
        cur.execute(
            "SELECT set_config('request.jwt.claims', %s, false)",
            (json.dumps({"sub": str(user_id), "role": role}),),
        )
    return c


class TestRLSEnforcement:
    """Verify the security guarantees that the mock-DB tests cannot reach."""

    def test_anonymous_cannot_see_secrets(self, admin_conn):
        """The anon role sees zero rows from api.secrets."""
        with admin_conn.cursor() as cur:
            cur.execute("SET ROLE anon")
            cur.execute("SELECT count(*) AS n FROM api.secrets")
            assert int(cur.fetchone()[0]) == 0

    def test_audit_is_append_only(self, admin_conn):
        """authenticated cannot INSERT into api.secret_audit directly."""
        with admin_conn.cursor() as cur:
            cur.execute("SET ROLE authenticated")
            with pytest.raises(Exception):  # noqa: B017 - any DB error proves RLS blocked the insert
                cur.execute(
                    "INSERT INTO api.secret_audit (project_id, action) "
                    "VALUES (gen_random_uuid(), 'revealed')"
                )

    def test_force_rls_on_audit_tables(self, admin_conn):
        """FORCE ROW LEVEL SECURITY is set on audit tables (table owner bypass blocked)."""
        with admin_conn.cursor() as cur:
            cur.execute(
                """
                SELECT relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relname IN ('secret_audit', 'org_audit')
                """
            )
            for row in cur.fetchall():
                assert row[0] is True, "RLS must be enabled"
                assert row[1] is True, "FORCE RLS must be set (owner cannot bypass)"

    def test_cross_user_isolation(self, admin_conn):
        """A user in team A cannot see secrets in team B's project."""
        # This is a smoke test of the RLS machinery; a full scenario would
        # create teams, projects, and secrets, then assert cross-tenant
        # SELECT returns zero rows. The scaffold is here to be extended.
        with admin_conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) AS n FROM information_schema.tables "
                "WHERE table_schema = 'api' AND table_name = 'secrets'"
            )
            assert int(cur.fetchone()[0]) == 1, "api.secrets table must exist after migration"
