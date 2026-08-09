"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import app as store
import config
import db
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

