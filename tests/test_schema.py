"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import app as store
import config
import db
import migrations as migrations_mod
import schema as schema_mod

from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestEnsureSchema:

    def test_requires_admin_url(self):
        with patch.object(schema_mod, 'DATABASE_ADMIN_URL', ''):
            with pytest.raises(RuntimeError) as cm:
                schema_mod.ensure_schema()
        assert 'DATABASE_ADMIN_URL' in str(cm.value)

    def test_uses_advisory_lock(self):
        conn, cur = _conn()
        with patch.object(schema_mod, 'DATABASE_ADMIN_URL', 'postgres://admin@x/db'), patch.object(db, 'connect_admin', return_value=conn), patch.object(schema_mod, 'bootstrap_admin_email', return_value=''):
            schema_mod.ensure_schema()
        sqls = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list if c.args))
        assert 'pg_advisory_lock' in sqls
        assert 'pg_advisory_unlock' in sqls

    def test_runs_migration_runner_and_promotes_admin(self):
        conn, cur = _conn()
        with patch.object(schema_mod, 'DATABASE_ADMIN_URL', 'postgres://admin@x/db'), \
             patch.object(db, 'connect_admin', return_value=conn), \
             patch.object(schema_mod, 'bootstrap_admin_email', return_value='admin@ex.com'), \
             patch.object(migrations_mod, 'apply_pending') as apply_pending:
            schema_mod.ensure_schema()
        apply_pending.assert_called_once()
        sqls = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list if c.args))
        assert 'is_global_admin = true' in sqls
        assert 'admin@ex.com' in str(cur.execute.call_args_list)

    def test_bootstrap_admin_promotion_runs_after_migrations(self):
        events = []

        def fake_apply(cur):
            events.append("migrations")
            return None

        conn, cur = _conn()
        with patch.object(schema_mod, 'DATABASE_ADMIN_URL', 'postgres://admin@x/db'), \
             patch.object(db, 'connect_admin', return_value=conn), \
             patch.object(schema_mod, 'bootstrap_admin_email', return_value='admin@ex.com'), \
             patch.object(migrations_mod, 'apply_pending', side_effect=fake_apply):
            schema_mod.ensure_schema()
        # promotion UPDATE must come after apply_pending (already recorded in sqls order)
        sqls = [str(c.args[0]) for c in cur.execute.call_args_list if c.args]
        lock_i = next(i for i, s in enumerate(sqls) if 'pg_advisory_lock' in s)
        promo_i = next(i for i, s in enumerate(sqls) if 'is_global_admin = true' in s)
        unlock_i = next(i for i, s in enumerate(sqls) if 'pg_advisory_unlock' in s)
        assert lock_i < promo_i < unlock_i

