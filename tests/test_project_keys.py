"""Unit tests for per-project crypto key lifecycle (app/crypto/project_keys.py)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from crypto import project_keys


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
        insert = [
            c.args for c in calls if "INSERT INTO private.project_crypto_keys" in str(c.args[0])
        ]
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
        updates = [
            c.args
            for c in admin_cur.execute.call_args_list
            if "UPDATE private.project_crypto_keys" in str(c.args[0])
        ]
        assert len(updates) == 1
        new_enc = updates[0][1][0]
        assert crypto.unwrap_project_key(new_enc) == raw

    def test_rewrap_skips_already_rewrapped(self):
        """Rows wrapped under the current key are left untouched."""
        admin_conn, admin_cur = _conn(
            fetchall=[{"project_id": str(uuid4()), "key_enc": "not-a-fernet"}]
        )
        with patch.object(project_keys.db, "connect_admin", return_value=admin_conn):
            assert project_keys.rewrap_project_keys("old-master-key") == 0

    def test_ensure_project_key_hsm_requires_slot(self):
        from crypto import hsm

        pid = str(uuid4())
        admin_conn, admin_cur = _conn(fetchone=None)
        with (
            patch.object(project_keys.db, "connect_admin", return_value=admin_conn),
            patch.object(hsm, "wrap_dek_for_slot"),
        ):
            with pytest.raises(RuntimeError, match="requires a named slot"):
                project_keys.ensure_project_key(pid, provider="hsm")
        insert = [
            c.args
            for c in admin_cur.execute.call_args_list
            if "INSERT INTO private.project_crypto_keys" in str(c.args[0])
        ]
        assert insert == []

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
        updates = [
            c.args
            for c in admin_cur.execute.call_args_list
            if "UPDATE private.project_crypto_keys" in str(c.args[0])
        ]
        assert n == 0
        assert not any("hsm-blob" in str(u[1]) for u in updates)

    def test_migrate_project_key_to_hsm(self):
        from cryptography.fernet import Fernet

        from crypto import hsm

        pid = str(uuid4())
        slot_id = str(uuid4())
        old_dek = Fernet.generate_key()
        new_dek = Fernet.generate_key()
        admin_conn, admin_cur = _conn(fetchone={"key_provider": "local"}, fetchall=[])
        slot_url = "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x"
        with (
            patch.object(project_keys.db, "connect_admin", return_value=admin_conn),
            patch.object(project_keys.crypto, "project_dek", return_value=old_dek),
            patch.object(project_keys.crypto, "generate_project_key", return_value=new_dek),
            patch.object(project_keys.crypto, "slot_url", return_value=slot_url),
            patch.object(
                hsm, "wrap_dek_for_slot", return_value=("hsm-wrapped", "byok-kek")
            ) as wrap_hsm,
        ):
            n = project_keys.migrate_project_key(pid, "hsm", target_slot_id=slot_id)
        assert n == 0
        wrap_hsm.assert_called_once_with(slot_url, new_dek)
        updates = [
            c.args
            for c in admin_cur.execute.call_args_list
            if "UPDATE private.project_crypto_keys" in str(c.args[0])
        ]
        assert len(updates) == 1
        params = updates[0][1]
        assert params[0] == "hsm-wrapped"
        assert params[1] == "hsm"
        assert params[2] == "byok-kek"
        assert str(params[3]) == slot_id

    def test_migrate_project_key_to_local(self):
        from cryptography.fernet import Fernet

        pid = str(uuid4())
        old_dek = Fernet.generate_key()
        new_dek = Fernet.generate_key()
        admin_conn, admin_cur = _conn(fetchone={"key_provider": "hsm"}, fetchall=[])
        with (
            patch.object(project_keys.db, "connect_admin", return_value=admin_conn),
            patch.object(project_keys.crypto, "project_dek", return_value=old_dek),
            patch.object(project_keys.crypto, "generate_project_key", return_value=new_dek),
            patch.object(
                project_keys.crypto, "wrap_project_key", return_value="local-wrapped"
            ) as wrap_local,
        ):
            n = project_keys.migrate_project_key(pid, "local")
        assert n == 0
        wrap_local.assert_called_once_with(new_dek)
        updates = [
            c.args
            for c in admin_cur.execute.call_args_list
            if "UPDATE private.project_crypto_keys" in str(c.args[0])
        ]
        assert len(updates) == 1
        params = updates[0][1]
        assert params[0] == "local-wrapped"
        assert params[1] == "local"
        assert params[2] is None

    def test_rotate_hsm_kek(self):
        from crypto import hsm

        slot_id = str(uuid4())
        rows = [
            {"project_id": str(uuid4()), "key_enc": "old-wrap", "kms_key_ref": "byok-kek"},
        ]
        admin_conn, admin_cur = _conn(fetchone=None, fetchall=rows)
        raw = b"x" * 32
        slot_url = "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x"
        with (
            patch.object(project_keys.db, "connect_admin", return_value=admin_conn),
            patch.object(project_keys.crypto, "slot_url", return_value=slot_url),
            patch.object(hsm, "parse_pkcs11_url", return_value={"kek_label": "byok-kek"}),
            patch.object(hsm, "generate_kek"),
            patch.object(hsm, "unwrap_dek_for_slot", return_value=raw) as unwrap,
            patch.object(hsm, "wrap_dek_with_label", return_value="new-wrap") as wrap,
        ):
            n = project_keys.rotate_hsm_kek(slot_id)
        assert n == 1
        unwrap.assert_called_once_with(slot_url, "old-wrap", "byok-kek")
        wrap.assert_called_once()
        updates = [
            c.args
            for c in admin_cur.execute.call_args_list
            if "UPDATE private.project_crypto_keys" in str(c.args[0])
        ]
        assert len(updates) == 1
        params = updates[0][1]
        assert params[0] == "new-wrap"
        assert params[1].startswith("byok-kek-")

    def test_encryption_summary(self):
        rows = [
            {
                "project_id": str(uuid4()),
                "project_name": "a",
                "team_name": "T",
                "key_provider": "hsm",
                "key_created_at": None,
                "key_id": None,
            },
            {
                "project_id": str(uuid4()),
                "project_name": "b",
                "team_name": "T",
                "key_provider": "local",
                "key_created_at": None,
                "key_id": None,
            },
            {
                "project_id": str(uuid4()),
                "project_name": "c",
                "team_name": "T",
                "key_provider": None,
                "key_created_at": None,
                "key_id": None,
            },
        ]
        admin_conn, admin_cur = _conn(fetchone=None, fetchall=rows)
        with (
            patch.object(project_keys.db, "connect_admin", return_value=admin_conn),
            patch.object(project_keys, "count_master_rows", return_value=0),
        ):
            summary = project_keys.encryption_summary()
        assert summary["counts"] == {"managed": 1, "local": 1, "hsm": 1}
        assert len(summary["projects"]) == 3

    def test_migrate_all_local_to_hsm(self):
        slot_id = str(uuid4())
        admin_conn, admin_cur = _conn(
            fetchone={"key_provider": "hsm"}, fetchall=[{"project_id": str(uuid4())}]
        )
        with (
            patch.object(project_keys.db, "connect_admin", return_value=admin_conn),
            patch.object(project_keys, "migrate_project_key", return_value=0) as migrate,
        ):
            n = project_keys.migrate_all_local_to_hsm(target_slot_id=slot_id)
        assert n == 1
        migrate.assert_called_once()
        assert migrate.call_args.kwargs["target_slot_id"] == slot_id

    def test_migrate_all_local_to_hsm_requires_slot(self):
        with pytest.raises(RuntimeError, match="target HSM slot"):
            project_keys.migrate_all_local_to_hsm(target_slot_id=None)

    def test_ensure_project_key_hsm_slot(self):
        from crypto import hsm

        pid, slot_id = str(uuid4()), str(uuid4())
        admin_conn, admin_cur = _conn(fetchone=None)
        slot_url = "pkcs11:token=t;object=byok-kek?module-path=/m.so&pin-value=x"
        with (
            patch.object(project_keys.db, "connect_admin", return_value=admin_conn),
            patch.object(project_keys.crypto, "slot_url", return_value=slot_url),
            patch.object(hsm, "ensure_kek_for_slot") as ensure_kek,
            patch.object(hsm, "wrap_dek_for_slot", return_value=("wrapped", "byok-kek")),
        ):
            created = project_keys.ensure_project_key(pid, provider="hsm", hsm_slot_id=slot_id)
        assert created is True
        insert = [
            c.args
            for c in admin_cur.execute.call_args_list
            if "INSERT INTO private.project_crypto_keys" in str(c.args[0])
        ]
        assert len(insert) == 1
        params = insert[0][1]  # (project_id, key_enc, provider, kms_ref, hsm_slot_id)
        assert params[1] == "wrapped"
        assert params[2] == "hsm"
        assert params[3] == "byok-kek"
        ensure_kek.assert_called_once_with(slot_url)

    def test_migrate_between_slots_rewraps_only(self):
        from cryptography.fernet import Fernet

        from crypto import hsm

        pid, slot_a, slot_b = str(uuid4()), str(uuid4()), str(uuid4())
        dek = Fernet.generate_key()
        admin_conn, admin_cur = _conn(
            fetchone={"key_provider": "hsm", "hsm_slot_id": slot_a},
            fetchall=[],
        )
        slot_url_b = "pkcs11:token=b;object=byok-kek?module-path=/m.so&pin-value=x"
        with (
            patch.object(project_keys.db, "connect_admin", return_value=admin_conn),
            patch.object(project_keys.crypto, "slot_url", return_value=slot_url_b),
            patch.object(project_keys.crypto, "project_dek", return_value=dek),
            patch.object(hsm, "wrap_dek_for_slot", return_value=("wrapped-b", "byok-kek2")) as wrap,
        ):
            n = project_keys.migrate_project_key(pid, "hsm", target_slot_id=slot_b)
        assert n == 0  # re-wrap only, no secret re-encryption
        wrap.assert_called_once_with(slot_url_b, dek)
        updates = [
            c.args
            for c in admin_cur.execute.call_args_list
            if "UPDATE private.project_crypto_keys" in str(c.args[0])
        ]
        assert len(updates) == 1
        params = updates[0][1]
        assert params[0] == "wrapped-b"
        assert params[1] == "byok-kek2"
        assert str(params[2]) == slot_b

    def test_link_legacy_to_slot(self):
        from crypto import hsm

        slot_id = str(uuid4())
        admin_conn, admin_cur = _conn(fetchone=None, fetchall=[])
        admin_cur.rowcount = 2
        slot_url = "pkcs11:token=t;object=byok-kek?module-path=/m.so&pin-value=x"
        with (
            patch.object(project_keys.db, "connect_admin", return_value=admin_conn),
            patch.object(project_keys.crypto, "slot_url", return_value=slot_url),
            patch.object(hsm, "available_for_slot", return_value=True),
            patch.object(hsm, "parse_pkcs11_url", return_value={"kek_label": "byok-kek"}),
        ):
            n = project_keys.link_legacy_to_slot(slot_id)
        assert n == 2
        updates = [
            c.args
            for c in admin_cur.execute.call_args_list
            if "UPDATE private.project_crypto_keys" in str(c.args[0])
        ]
        assert len(updates) == 1
        assert str(updates[0][1][0]) == slot_id

    def test_link_legacy_to_slot_unreachable(self):
        """Raises when the HSM slot is not reachable."""
        from crypto import hsm

        slot_id = str(uuid4())
        admin_conn, _ = _conn(fetchone=None, fetchall=[])
        slot_url = "pkcs11:token=t;object=byok-kek?module-path=/m.so&pin-value=x"
        with (
            patch.object(project_keys.db, "connect_admin", return_value=admin_conn),
            patch.object(project_keys.crypto, "slot_url", return_value=slot_url),
            patch.object(hsm, "available_for_slot", return_value=False),
        ):
            with pytest.raises(RuntimeError, match="not reachable"):
                project_keys.link_legacy_to_slot(slot_id)

    def test_rotate_hsm_kek_for_slot(self):
        from crypto import hsm

        slot_id = str(uuid4())
        rows = [
            {"project_id": str(uuid4()), "key_enc": "old", "kms_key_ref": "byok-kek"},
        ]
        admin_conn, admin_cur = _conn(fetchone=None, fetchall=rows)
        slot_url = "pkcs11:token=t;object=byok-kek?module-path=/m.so&pin-value=x"
        with (
            patch.object(project_keys.db, "connect_admin", return_value=admin_conn),
            patch.object(project_keys.crypto, "slot_url", return_value=slot_url),
            patch.object(project_keys.crypto, "clear_project_key_cache"),
            patch.object(hsm, "parse_pkcs11_url", return_value={"kek_label": "byok-kek"}),
            patch.object(hsm, "generate_kek"),
            patch.object(hsm, "unwrap_dek_for_slot", return_value=b"x" * 32),
            patch.object(hsm, "wrap_dek_with_label", return_value="new") as wrap,
        ):
            n = project_keys.rotate_hsm_kek(slot_id=slot_id)
        assert n == 1
        wrap.assert_called_once()
