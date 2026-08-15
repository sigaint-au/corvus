"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import app as store
from core import config
from core import db
from auth import lockout

from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestLockout:

    def test_empty_email_not_locked(self):
        assert not lockout.is_locked('')
        assert not lockout.is_locked('  ')

    def test_is_locked_when_at_threshold(self):
        conn, _ = _conn(fetchone={'n': lockout.MAX_ATTEMPTS})
        with patch.object(db, 'connect_admin', return_value=conn):
            assert lockout.is_locked('a@b.c')

    def test_not_locked_below_threshold(self):
        conn, _ = _conn(fetchone={'n': lockout.MAX_ATTEMPTS - 1})
        with patch.object(db, 'connect_admin', return_value=conn):
            assert not lockout.is_locked('a@b.c')

    def test_db_error_fails_open(self):
        with patch.object(db, 'connect_admin', side_effect=RuntimeError('db')):
            assert not lockout.is_locked('a@b.c')

    def test_record_and_clear(self):
        conn, cur = _conn()
        with patch.object(db, 'connect_admin', return_value=conn):
            lockout.record_failure('A@B.C')
            lockout.clear_failures('A@B.C')
        sql = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list))
        assert 'INSERT INTO private.login_failures' in sql
        assert 'DELETE FROM private.login_failures' in sql
        assert cur.execute.call_args_list[0].args[1] == ('a@b.c',)

