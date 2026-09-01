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
    lines: list[str] = []
    for line in sql.splitlines():
        content = line.split("--", 1)[0].strip()
        if content:
            lines.append(content)
    normalized = " ".join(lines).lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _write_migrations(tmp_path, files):
    d = tmp_path / "migrations"
    d.mkdir()
    for name, content in files.items():
        (d / name).write_text(content)
    return d


def test_migrations_ship_in_order():
    """Squashed baseline plus additive CLI session token migration."""
    files = [p.name for p in migrations._migration_files()]
    assert files == [
        "0001_init.sql",
        "0002_cli_session_tokens.sql",
        "0003_secret_folders.sql",
        "0004_materialize_folder_definer.sql",
        "0005_folder_effective_access_label.sql",
        "0006_machine_upsert_conflict_target.sql",
        "0007_machine_upsert_folder.sql",
        "0008_machine_upsert_folder_var.sql",
    ]
    for name in files:
        assert name[:4].isdigit()
        assert name[4] == "_"


def test_secret_folder_migration_covers_schema_and_rls():
    sql = (migrations.MIGRATIONS_DIR / "0003_secret_folders.sql").read_text()
    for fragment in (
        "CREATE TABLE IF NOT EXISTS api.folders",
        "folder_id",
        "scope_kind = 'folder'",
        "api.rbac_scope_chain",
        "api.can_access_secret_row",
        "validate_binding_scope",
    ):
        assert fragment in sql


def test_machine_upsert_conflict_target():
    sql = (migrations.MIGRATIONS_DIR / "0006_machine_upsert_conflict_target.sql").read_text()
    assert "folder_id IS NULL AND deleted_at IS NULL" in sql
    assert "ON CONFLICT (project_id, key)" in sql
    # Stale 8-arg overload from 0001 must be dropped so GRANT is unambiguous.
    assert (
        "DROP FUNCTION IF EXISTS private.machine_upsert_enc("
        "uuid, text, text, text, text, text, timestamptz, boolean)"
    ) in sql
    assert (
        "GRANT EXECUTE ON FUNCTION private.machine_upsert_enc("
        "uuid, text, text, text, text, text, timestamptz, boolean, text)"
    ) in sql


def test_machine_upsert_folder_var_not_shadowing_column():
    sql = (migrations.MIGRATIONS_DIR / "0008_machine_upsert_folder_var.sql").read_text()
    assert "v_folder_id uuid" in sql
    assert "\n  folder_id uuid;" not in sql
    assert "v_folder_id := private.materialize_folder_path" in sql
    assert "p_project, v_folder_id, p_key" in sql
    assert "ON CONFLICT (project_id, folder_id, key) WHERE folder_id IS NOT NULL" in sql
    assert (
        "GRANT EXECUTE ON FUNCTION private.machine_upsert_enc("
        "uuid, text, text, text, text, text, timestamptz, boolean, text)"
    ) in sql


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
    assert "api.hsm_slot_url(uuid)" in sql
    assert "ALTER DEFAULT PRIVILEGES IN SCHEMA api" in sql
    assert "ALTER DEFAULT PRIVILEGES IN SCHEMA rbac" in sql
    assert "private.squashed_baseline_marker" in sql
    # Email verification columns
    assert "email_verified_at" in sql
    assert "email_verify_token_hash" in sql
    assert "email_verify_sent_at" in sql
    assert "users_email_verify_token_idx" in sql
    # Login alerts
    assert "login_alerts" in sql
    assert "smtp_login_alerts_force" in sql
    # Team reveal requests
    assert "allow_reveal_requests" in sql
    assert "team_allows_reveal_requests" in sql
    # Brand defaults
    assert "'Corvus'" in sql
    assert "'Keep your secrets.'" in sql
    # Webhooks
    assert "api.webhooks" in sql
    assert "private.webhook_delivery_queue" in sql
    assert "api.webhook_deliveries" in sql
    assert "ssl_verify" in sql
    assert "enqueue_webhooks" in sql
    assert "tr_webhook_secret_audit" in sql
    assert "tr_webhook_org_audit" in sql
    # Meta tables
    assert "api.team_meta" in sql
    assert "api.project_meta" in sql
    assert "guard_meta_precedence" in sql
    # Security hardening
    assert "pg_catalog" in sql
    assert "SECURITY INVOKER" in sql
    assert "applied_by" in sql
    assert "application_name" in sql
    # Ciphertext guards
    assert "private.secret_enc" in sql
    assert "private.secret_version_enc" in sql
    assert "private.project_reveal_enc_rows" in sql
    assert "REVOKE SELECT (value_enc) ON api.secrets FROM authenticated" in sql
    # Update guards
    assert "guard_secret_update" in sql
    assert "guard_project_update" in sql
    assert "guard_team_dir_map" in sql
    assert "secret identity fields cannot be changed" in sql
    assert "project team_id cannot be changed" in sql
    # only a team owner can assign team-owner
    assert "only a team owner can assign team-owner" in sql
    assert "only a team owner can map team-owner" in sql
    # can_reveal_secret with deleted_at guard
    assert "deleted_at IS NULL" in sql
    # machine_key_allowed with restricted check
    assert "service-read" in sql
    # auditor role
    assert "'auditor'" in sql


def test_cli_session_tokens_migration_creates_table():
    """The additive CLI session token migration defines the sso_ token store."""
    sql = (migrations.MIGRATIONS_DIR / "0002_cli_session_tokens.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS private.cli_session_tokens" in sql
    assert "token_hash text NOT NULL UNIQUE" in sql
    assert "expires_at timestamptz NOT NULL" in sql
    assert "REFERENCES private.users(id) ON DELETE CASCADE" in sql
    assert "cli_session_tokens_user_idx" in sql


def test_squashed_baseline_is_idempotent_enough_for_fresh_init():
    """Fresh volumes run the whole 0001 file once; leftover squash sections
    must not abort docker-entrypoint with duplicate-object errors."""
    import re

    sql = (migrations.MIGRATIONS_DIR / "0001_init.sql").read_text()
    assert re.search(
        r"^CREATE TABLE (?!IF NOT EXISTS )", sql, re.M
    ) is None
    assert re.search(r"^  ON api\.\w+;$", sql, re.M) is None
    marker_insert = sql.split("INSERT INTO private.squashed_baseline_marker")[1][:80]
    assert "ON CONFLICT DO NOTHING" in marker_insert
    # Current verify_user OUT columns (leftover copies omit email_verified_at).
    assert "email_verified_at timestamptz)" in sql
    assert "DROP FUNCTION IF EXISTS private.secret_meta_rows(uuid)" in sql
    # Historical 0003–0019 copies must not be concatenated (they aborted initdb).
    for leftover in (
        "0003_bindings_source",
        "0004_access_mode",
        "0005_users_auth_settings",
        "0016_reveal_approval",
        "0019_row_acl_and_groups",
    ):
        assert f"-- ===== {leftover}.sql =====" not in sql
    assert "-- ===== 0020_security_hardening.sql =====" in sql
    assert "-- ===== 0029_rls_boundary_hardening.sql =====" in sql
    assert "private.project_meta_rows" in sql


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

def test_ensure_table_includes_audit_columns():
    """The migration tracking table records who applied each migration."""
    cur = _cur()
    migrations._ensure_table(cur)
    create_sql = cur.execute.call_args_list[0].args[0]
    assert "applied_by" in create_sql
    assert "application_name" in create_sql
