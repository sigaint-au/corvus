"""Unit tests for the versioned SQL migration runner (app/core/migrations.py)."""
from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from core import migrations


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
    """Baseline plus additive hardening migrations ship in order."""
    files = [p.name for p in migrations._migration_files()]
    assert files == [
        "0001_init.sql",
        "0002_rls_authz_hardening.sql",
        "0003_email_verification.sql",
        "0004_email_verify_backfill.sql",
        "0005_sql_password_crypt.sql",
        "0006_smtp_from_name_corvus.sql",
        "0007_login_alerts_pref.sql",
        "0008_reveal_grant_without_acl.sql",
        "0009_team_reveal_requests.sql",
        "0010_fix_can_reveal_secret.sql",
        "0011_machine_token_scope_deny.sql",
        "0012_reveal_deleted_guard.sql",
        "0013_webhooks.sql",
        "0014_webhook_deliveries.sql",
        "0015_webhook_grants.sql",
        "0016_brand_name_corvus.sql",
    ]
    for name in files:
        assert name[:4].isdigit()
        assert name[4] == "_"


def test_smtp_from_name_rebrand_migration():
    """0006 rewrites leftover 0001 defaults without editing the baseline."""
    sql = (migrations.MIGRATIONS_DIR / "0006_smtp_from_name_corvus.sql").read_text()
    assert "smtp_from_name" in sql
    assert "brand_name" in sql
    assert "brand_tagline" in sql
    assert "Sigaint Secret Server" in sql
    assert "Secret Server v0.1.0" in sql
    assert "Keep your secrets." in sql
    assert "Corvus" in sql
    assert "UPDATE" in sql.upper()


def test_brand_name_secret_server_migration():
    """0016 rewrites a brand_name that 0006 missed (plain 'Secret Server')."""
    sql = (migrations.MIGRATIONS_DIR / "0016_brand_name_corvus.sql").read_text()
    assert "brand_name" in sql
    assert "Secret Server" in sql
    assert "Corvus" in sql
    assert "UPDATE" in sql.upper()


def test_team_reveal_requests_migration():
    sql = (migrations.MIGRATIONS_DIR / "0009_team_reveal_requests.sql").read_text()
    assert "allow_reveal_requests" in sql
    assert "team_allows_reveal_requests" in sql


def test_reveal_grant_without_acl_migration():
    sql = (migrations.MIGRATIONS_DIR / "0008_reveal_grant_without_acl.sql").read_text()
    assert "can_reveal_secret" in sql
    assert "can_access_secret(sid, 'get')" in sql
    assert "secret_access_requests" in sql


def test_fix_can_reveal_secret_migration():
    """0010 undoes 0008's invalid 'get' need so owners/admins can decrypt."""
    sql = (migrations.MIGRATIONS_DIR / "0010_fix_can_reveal_secret.sql").read_text()
    assert "can_reveal_secret" in sql
    assert "can_access_secret(sid, 'read')" in sql
    assert "can_access_secret(sid, 'get')" not in sql
    assert "is_global_admin()" in sql
    assert "can_admin_project" in sql


def test_machine_token_scope_deny_migration():
    sql = (migrations.MIGRATIONS_DIR / "0011_machine_token_scope_deny.sql").read_text()
    assert "machine_key_allowed" in sql
    assert "array_remove(rr.resources, 'machine_tokens')" in sql
    assert "team-member" in sql
    assert "project-write" in sql


def test_reveal_deleted_guard_migration():
    """0012 blocks global admins from revealing soft-deleted secrets."""
    sql = (migrations.MIGRATIONS_DIR / "0012_reveal_deleted_guard.sql").read_text()
    assert "deleted_at IS NULL" in sql
    body = sql[sql.index("$$") + 2:]
    assert body.index("deleted_at IS NULL") < body.index("is_global_admin()")


def test_login_alerts_pref_migration():
    sql = (migrations.MIGRATIONS_DIR / "0007_login_alerts_pref.sql").read_text()
    assert "login_alerts" in sql
    assert "smtp_login_alerts_force" in sql
    assert "private.users" in sql


def test_squashed_baseline_contains_all_schema_layers():
    """The consolidated baseline retains the complete current schema."""
    sql = (migrations.MIGRATIONS_DIR / "0001_init.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS private.project_crypto_keys" in sql
    assert "crypto_provider" in sql
    assert "api.secrets" in sql and "api.secret_versions" in sql
    for col in (
        "rotation_interval_days",
        "rotation_owner",
        "rotation_next_at",
        "rotated_at",
    ):
        assert col in sql
    assert "machine_upsert_enc" in sql
    assert "REVOKE EXECUTE ON FUNCTION api.list_hsm_slots() FROM anon" in sql
    assert "REVOKE EXECUTE ON FUNCTION api.hsm_slot_url(uuid)" in sql
    assert "cannot change the URL of a slot used by project keys" in sql
    assert "p_user IS NOT DISTINCT FROM api.current_user_id()" in sql
    assert "p_subject IS NOT NULL" in sql
    assert "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA api FROM PUBLIC" in sql
    assert "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA rbac FROM PUBLIC" in sql
    assert "REVOKE SELECT ON api.machine_tokens FROM authenticated" in sql
    assert "secret does not belong to request project" in sql
    assert "new access requests must be pending and unresolved" in sql
    assert "CREATE TRIGGER guard_secret_access_request" in sql
    assert "CREATE TRIGGER validate_binding_scope" in sql
    assert "role % cannot be assigned at scope %" in sql
    assert "DROP FUNCTION IF EXISTS api.hsm_slot_url(uuid)" in sql
    assert "ALTER DEFAULT PRIVILEGES IN SCHEMA api" in sql
    assert "ALTER DEFAULT PRIVILEGES IN SCHEMA rbac" in sql
    assert "private.squashed_baseline_marker" in sql


def test_authz_hardening_migration():
    sql = (migrations.MIGRATIONS_DIR / "0002_rls_authz_hardening.sql").read_text()
    assert "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA private FROM PUBLIC" in sql
    assert "only a team owner can assign team-owner" in sql
    assert "only a team owner can map team-owner" in sql
    assert "secret identity fields cannot be changed" in sql
    assert "project team_id cannot be changed" in sql
    assert "REVOKE SELECT (value_enc) ON api.secrets FROM authenticated" in sql
    assert "private.secret_enc" in sql
    assert "can_admin_project(project_id)" in sql
    assert "OR api.can('update', 'secrets', 'secret', sid)" not in sql.split("WHEN need = 'reveal'")[1].split("ELSE")[0]


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
        cur = _cur(fetchall=[], fetchone={"ok": True})  # squashed baseline exists
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
        cur = _cur(fetchone={"ok": True})
        with patch.object(migrations, "MIGRATIONS_DIR", d):
            migrations.apply_pending(cur)
        # The single dollar-quoted statement must be executed as one chunk.
        executed = [c.args[0] for c in cur.execute.call_args_list if c.args]
        assert any("CREATE FUNCTION f() RETURNS int" in s for s in executed)

    def test_baseline_seeded_when_schema_exists(self, tmp_path):
        d = _write_migrations(tmp_path, {
            "0001_init.sql": "CREATE TABLE private.users (id int);",
            "0002_add.sql": "ALTER TABLE x ADD COLUMN y int;",
        })
        # empty migrations table, schema already exists (baseline present)
        cur = _cur(fetchone={"ok": True})
        with patch.object(migrations, "MIGRATIONS_DIR", d):
            migrations.apply_pending(cur)
        sqls = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        # baseline is seeded, not executed as DDL
        assert "CREATE TABLE private.users" not in sqls
        # only the additive migration runs
        assert "ALTER TABLE x ADD COLUMN y int" in sqls

    def test_pre_squash_schema_is_rejected(self, tmp_path):
        """Fresh-only baseline must not silently adopt an older database."""
        d = _write_migrations(tmp_path, {"0001_init.sql": "SELECT 1;"})
        cur = _cur(fetchone={"ok": False})
        with patch.object(migrations, "MIGRATIONS_DIR", d):
            with pytest.raises(RuntimeError, match="recreate the database"):
                migrations.apply_pending(cur)

    def test_access_mode_migration_runs_in_order(self, tmp_path):
        d = _write_migrations(tmp_path, {
            "0004_access_mode.sql": (
                "DO $$ BEGIN END $$;\n"
                "UPDATE api.secrets SET access_mode = 'restricted' WHERE access_mode = 'custom';\n"
                "UPDATE api.secrets SET access_mode = 'inherit' WHERE access_mode NOT IN ('inherit','restricted');\n"
                "ALTER TABLE api.secrets DROP COLUMN IF EXISTS acl_mode;\n"
            ),
        })
        cur = _cur(fetchone={"ok": True})
        with patch.object(migrations, "MIGRATIONS_DIR", d):
            migrations.apply_pending(cur)
        executed = [str(c.args[0]) for c in cur.execute.call_args_list if c.args]
        joined = " ".join(executed)
        i_restricted = joined.index("access_mode = 'restricted'")
        i_inherit = joined.index("access_mode = 'inherit'")
        i_drop = joined.index("DROP COLUMN IF EXISTS acl_mode")
        assert i_restricted < i_inherit < i_drop

def test_webhooks_migration():
    sql = (migrations.MIGRATIONS_DIR / "0013_webhooks.sql").read_text()
    assert "api.webhooks" in sql
    assert "private.webhook_delivery_queue" in sql
    assert "private.enqueue_webhooks" in sql
    assert "tr_webhook_secret_audit" in sql
