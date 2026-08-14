"""Unit tests for the versioned SQL migration runner (app/migrations.py)."""
from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest

import migrations


def _cur(fetchone=None, fetchall=None):
    cur = MagicMock()
    if fetchone is not None:
        cur.fetchone.return_value = fetchone
    else:
        cur.fetchone.return_value = None
    if fetchall is not None:
        cur.fetchall.return_value = fetchall
    else:
        cur.fetchall.return_value = []
    return cur


def _checksum(sql):
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def _write_migrations(tmp_path, files):
    d = tmp_path / "migrations"
    d.mkdir()
    for name, content in files.items():
        (d / name).write_text(content)
    return d


def test_migrations_ship_in_order():
    """The repo's db/migrations/*.sql files are present and start with baseline."""
    files = [p.name for p in migrations._migration_files()]
    assert files[0] == "0001_init.sql"
    assert files[1] == "0002_rbac.sql"
    assert len(files) >= 3
    # every file has a zero-padded 4-digit version prefix
    for name in files:
        assert name[:4].isdigit()
        assert name[4] == "_"


def test_project_crypto_migration_ships():
    """0022_project_crypto adds the BYOK key table + per-row provider column."""
    sql = (migrations.MIGRATIONS_DIR / "0022_project_crypto.sql").read_text()
    assert "CREATE TABLE private.project_crypto_keys" in sql
    assert "crypto_provider" in sql
    assert "api.secrets" in sql and "api.secret_versions" in sql
    assert "machine_upsert_enc" in sql


class TestPendingMigrations:
    def test_returns_unapplied_in_order(self, tmp_path):
        d = _write_migrations(tmp_path, {
            "0001_init.sql": "-- baseline",
            "0002_rbac.sql": "-- rbac",
            "0003_add.sql": "-- add",
        })
        cur = _cur(fetchall=[{"version": "0001", "checksum": _checksum("-- baseline")}])
        with patch.object(migrations, "MIGRATIONS_DIR", d):
            pending = migrations.pending_migrations(cur)
        assert [v for v, _ in pending] == ["0002", "0003"]

    def test_applied_checksum_match_is_skipped(self, tmp_path):
        d = _write_migrations(tmp_path, {"0001_init.sql": "SELECT 1;"})
        cur = _cur(fetchall=[{"version": "0001", "checksum": _checksum("SELECT 1;")}])
        with patch.object(migrations, "MIGRATIONS_DIR", d):
            assert migrations.pending_migrations(cur) == []

    def test_checksum_drift_raises(self, tmp_path):
        d = _write_migrations(tmp_path, {"0001_init.sql": "SELECT 1;"})
        cur = _cur(fetchall=[{"version": "0001", "checksum": "deadbeef"}])
        with patch.object(migrations, "MIGRATIONS_DIR", d):
            with pytest.raises(RuntimeError, match="checksum mismatch"):
                migrations.pending_migrations(cur)


class TestApplyPending:
    def test_applies_and_records(self, tmp_path):
        d = _write_migrations(tmp_path, {
            "0003_add.sql": "ALTER TABLE api.secrets ADD COLUMN x int;",
        })
        cur = _cur(fetchall=[], fetchone=None)  # empty migrations table, no schema
        with patch.object(migrations, "MIGRATIONS_DIR", d):
            migrations.apply_pending(cur)
        sqls = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "ALTER TABLE api.secrets ADD COLUMN x int" in sqls
        assert "INSERT INTO private.schema_migrations" in sqls
        assert "0003" in " ".join(
            str(c.args) for c in cur.execute.call_args_list
        )

    def test_dollar_quoted_body_not_split(self, tmp_path):
        d = _write_migrations(tmp_path, {
            "0003_fn.sql": (
                "CREATE FUNCTION f() RETURNS int AS $$\n"
                "BEGIN RETURN 1; END;\n"
                "$$ LANGUAGE plpgsql;"
            ),
        })
        cur = _cur()
        with patch.object(migrations, "MIGRATIONS_DIR", d):
            migrations.apply_pending(cur)
        # The single dollar-quoted statement must be executed as one chunk.
        executed = [c.args[0] for c in cur.execute.call_args_list if c.args]
        assert any("CREATE FUNCTION f() RETURNS int" in s for s in executed)

    def test_baseline_seeded_when_schema_exists(self, tmp_path):
        d = _write_migrations(tmp_path, {
            "0001_init.sql": "CREATE TABLE private.users (id int);",
            "0002_rbac.sql": "CREATE TABLE rbac.roles (id int);",
            "0003_add.sql": "ALTER TABLE x ADD COLUMN y int;",
        })
        # empty migrations table, schema already exists (baseline present)
        cur = _cur(fetchone={"ok": True})
        with patch.object(migrations, "MIGRATIONS_DIR", d):
            migrations.apply_pending(cur)
        sqls = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        # baseline is seeded, not executed as DDL
        assert "CREATE TABLE private.users" not in sqls
        assert "CREATE TABLE rbac.roles" not in sqls
        # only the additive migration runs
        assert "ALTER TABLE x ADD COLUMN y int" in sqls

    def test_access_mode_migration_runs_in_order(self, tmp_path):
        d = _write_migrations(tmp_path, {
            "0004_access_mode.sql": (
                "DO $$ BEGIN END $$;\n"
                "UPDATE api.secrets SET access_mode = 'restricted' WHERE access_mode = 'custom';\n"
                "UPDATE api.secrets SET access_mode = 'inherit' WHERE access_mode NOT IN ('inherit','restricted');\n"
                "ALTER TABLE api.secrets DROP COLUMN IF EXISTS acl_mode;\n"
            ),
        })
        cur = _cur()
        with patch.object(migrations, "MIGRATIONS_DIR", d):
            migrations.apply_pending(cur)
        executed = [str(c.args[0]) for c in cur.execute.call_args_list if c.args]
        joined = " ".join(executed)
        i_restricted = joined.index("access_mode = 'restricted'")
        i_inherit = joined.index("access_mode = 'inherit'")
        i_drop = joined.index("DROP COLUMN IF EXISTS acl_mode")
        assert i_restricted < i_inherit < i_drop
