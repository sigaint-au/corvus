"""Unit tests for per-project crypto key lifecycle (app/project_keys.py)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import project_keys


def _conn(fetchone=None, fetchall=None):
    cur = MagicMock()
    cur.fetchone.return_value = fetchone
    cur.fetchall.return_value = fetchall if fetchall is not None else []
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    cur.__enter__.return_value = cur
    cur.__exit__.return_value = False
    return conn, cur


class TestProjectKeys:
    def test_ensure_project_key_inserts_wrapped_dek(self):
        pid = str(uuid4())
        admin_conn, admin_cur = _conn(fetchone=None)  # SELECT returns none -> create
        with patch.object(project_keys.db, "connect_admin", return_value=admin_conn):
            created = project_keys.ensure_project_key(pid)
        assert created is True
        calls = admin_cur.execute.call_args_list
        insert = [c.args for c in calls if "INSERT INTO private.project_crypto_keys" in str(c.args[0])]
        assert len(insert) == 1
        key_enc = insert[0][1][1]
        assert key_enc.startswith("gAAAA")  # Fernet-wrapped by MASTER_KEY

    def test_ensure_project_key_idempotent(self):
        pid = str(uuid4())
        admin_conn = _conn(fetchone={"id": "existing"})[0]
        with patch.object(project_keys.db, "connect_admin", return_value=admin_conn):
            assert project_keys.ensure_project_key(pid) is False

    def test_status_none_when_no_key(self):
        conn, _ = _conn(fetchone=None)
        with patch.object(project_keys.db, "connect_admin", return_value=conn):
            assert project_keys.project_crypto_status(str(uuid4())) is None

    def test_status_returns_row(self):
        conn, _ = _conn(fetchone={"key_provider": "local", "kms_key_ref": None, "created_at": None})
        with patch.object(project_keys.db, "connect_admin", return_value=conn):
            st = project_keys.project_crypto_status(str(uuid4()))
        assert st and st["key_provider"] == "local"

    def test_adopt_no_rows(self):
        """Adopt with no master rows still ensures a key and returns 0."""
        pid = str(uuid4())
        admin_conn, admin_cur = _conn(fetchone=None, fetchall=[])
        with patch.object(project_keys.db, "connect_admin", return_value=admin_conn):
            n = project_keys.adopt_project_key(pid)
        assert n == 0

    def test_rewrap_project_keys(self):
        """Re-wrap DEKs from an old MASTER_KEY to the current one."""
        import crypto

        old_master = "old-master-key"
        raw = crypto.generate_project_key()
        old_wrapped = crypto.fernet_for(old_master).encrypt(raw).decode()
        rows = [{"project_id": str(uuid4()), "key_enc": old_wrapped}]
        admin_conn, admin_cur = _conn(fetchone=None, fetchall=rows)
        with patch.object(project_keys.db, "connect_admin", return_value=admin_conn):
            n = project_keys.rewrap_project_keys(old_master)
        assert n == 1
        # the updated key_enc unwraps with the CURRENT master key
        updates = [c.args for c in admin_cur.execute.call_args_list if "UPDATE private.project_crypto_keys" in str(c.args[0])]
        assert len(updates) == 1
        new_enc = updates[0][1][0]
        assert crypto.unwrap_project_key(new_enc) == raw

    def test_rewrap_skips_already_rewrapped(self):
        """Rows wrapped under the current key are left untouched."""
        admin_conn, admin_cur = _conn(fetchall=[{"project_id": str(uuid4()), "key_enc": "not-a-fernet"}])
        with patch.object(project_keys.db, "connect_admin", return_value=admin_conn):
            assert project_keys.rewrap_project_keys("old-master-key") == 0

    def test_ensure_project_key_hsm(self):
        import hsm

        pid = str(uuid4())
        admin_conn, admin_cur = _conn(fetchone=None)
        with patch.object(project_keys.db, "connect_admin", return_value=admin_conn), \
             patch.object(hsm, "ensure_kek"), \
             patch.object(hsm, "wrap_dek", return_value="hsm-wrapped"), \
             patch.object(hsm, "kek_label", return_value="byok-kek"):
            created = project_keys.ensure_project_key(pid, provider="hsm")
        assert created is True
        insert = [c.args for c in admin_cur.execute.call_args_list
                  if "INSERT INTO private.project_crypto_keys" in str(c.args[0])]
        assert len(insert) == 1
        params = insert[0][1]
        assert params[1] == "hsm-wrapped"
        assert params[2] == "hsm"
        assert params[3] == "byok-kek"

    def test_rewrap_skips_hsm_rows(self):
        """HSM-wrapped DEKs must not be touched by MASTER_KEY rotation."""
        rows = [
            {"project_id": str(uuid4()), "key_enc": "hsm-blob", "key_provider": "hsm"},
            {"project_id": str(uuid4()), "key_enc": "local-blob", "key_provider": "local"},
        ]
        admin_conn, admin_cur = _conn(fetchone=None, fetchall=rows)
        with patch.object(project_keys.db, "connect_admin", return_value=admin_conn):
            n = project_keys.rewrap_project_keys("old-master-key")
        # only the 'local' row is even attempted; 'local-blob' isn't valid Fernet
        # under the old key, so it's skipped → 0 re-wrapped, and the hsm row is
        # never UPDATEd.
        updates = [c.args for c in admin_cur.execute.call_args_list
                   if "UPDATE private.project_crypto_keys" in str(c.args[0])]
        assert n == 0
        assert not any("hsm-blob" in str(u[1]) for u in updates)