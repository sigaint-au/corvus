"""Unit tests (pytest). Mock DB — no Postgres required."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

import app as store
import crypto

store.app.config["TESTING"] = True


class TestCrypto:
    def test_roundtrip(self):
        assert crypto.decrypt(crypto.encrypt("ping")) == "ping"

    def test_empty(self):
        assert crypto.decrypt(crypto.encrypt("")) == ""

    def test_unicode(self):
        s = "héllo 🔐 日本語"
        assert crypto.decrypt(crypto.encrypt(s)) == s

    def test_ciphertext_differs(self):
        a, b = (crypto.encrypt("x"), crypto.encrypt("x"))
        assert a != b
        assert crypto.decrypt(a) == crypto.decrypt(b)


class TestProjectCrypto:
    def setup_method(self):
        crypto.clear_project_key_cache()

    def test_project_key_roundtrip_via_db(self):
        pid = str(uuid4())
        raw = crypto.generate_project_key()
        key_enc = crypto.wrap_project_key(raw)
        conn, cur = _conn(fetchone={"key_enc": key_enc})
        with patch.object(crypto.db, "connect_admin", return_value=conn):
            token, provider = crypto.encrypt_for_project(pid, "secret-value")
        assert provider == "project"
        assert token != crypto.encrypt("secret-value")
        with patch.object(crypto.db, "connect_admin", return_value=conn):
            assert crypto.decrypt_for_project(pid, token, "project") == "secret-value"

    def test_project_key_uses_shared_redis_cache(self):
        pid = str(uuid4())
        row = {"key_enc": crypto.wrap_project_key(crypto.generate_project_key())}
        conn, _ = _conn(fetchone=row)
        client = MagicMock()
        client.get.side_effect = ["0", None, "0", json.dumps(row)]
        with (
            patch.object(crypto.cache, "redis_client", return_value=client),
            patch.object(crypto.db, "connect_admin", return_value=conn) as connect,
        ):
            assert crypto.project_has_key(pid) is True
            assert crypto.project_has_key(pid) is True
        connect.assert_called_once()
        client.setex.assert_called_once()

    def test_slot_url_reads_database_without_redis(self):
        slot_url = "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x"
        conn, _ = _conn(fetchone={"pkcs11_url": slot_url})
        with (
            patch.object(crypto.cache, "redis_client", return_value=None),
            patch.object(crypto.db, "connect_admin", return_value=conn),
        ):
            assert crypto.slot_url("slot-1") == slot_url

    def test_project_key_invalidation_advances_shared_epoch(self):
        client = MagicMock()
        with patch.object(crypto.cache, "redis_client", return_value=client):
            crypto.clear_project_key_cache()
        assert [call.args for call in client.incr.call_args_list] == [
            ("secretserver:crypto:project-key:epoch",),
            ("secretserver:crypto:hsm-slot:epoch",),
        ]

    def test_master_fallback_when_no_key(self):
        pid = str(uuid4())
        conn, cur = _conn()
        cur.fetchone.return_value = None
        with patch.object(crypto.db, "connect_admin", return_value=conn):
            token, provider = crypto.encrypt_for_project(pid, "legacy")
        assert provider == "master"
        with patch.object(crypto.db, "connect_admin", return_value=conn):
            assert crypto.decrypt_for_project(pid, token, "master") == "legacy"

    def test_master_fallback_on_db_error(self):
        pid = str(uuid4())
        with patch.object(crypto.db, "connect_admin", side_effect=Exception("no db")):
            token, provider = crypto.encrypt_for_project(pid, "x")
        assert provider == "master"
        assert crypto.decrypt(token) == "x"

    def test_master_token_decrypts_with_project_provider(self):
        pid = str(uuid4())
        master_tok = crypto.encrypt("secret")
        conn, _ = _conn()  # fetchone None -> no project key
        with patch.object(crypto.db, "connect_admin", return_value=conn):
            assert crypto.decrypt_for_project(pid, master_tok, "master") == "secret"

    def test_wrong_project_key_raises(self):
        pid1, pid2 = str(uuid4()), str(uuid4())
        raw = crypto.generate_project_key()
        key_enc = crypto.wrap_project_key(raw)
        conn, _ = _conn(fetchone={"key_enc": key_enc})
        with patch.object(crypto.db, "connect_admin", return_value=conn):
            token, _provider = crypto.encrypt_for_project(pid1, "v")
        pid2_conn, _ = _conn(fetch_key=crypto.wrap_project_key(crypto.generate_project_key()))
        with patch.object(crypto.db, "connect_admin", return_value=pid2_conn):
            with pytest.raises(ValueError):
                crypto.decrypt_for_project(pid2, token, "project")

    def test_hsm_provider_roundtrip(self):
        from crypto import hsm

        pid = str(uuid4())
        raw = crypto.generate_project_key()
        slot_url = "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x"
        conn, _ = _conn(
            fetchone={
                "key_enc": "hsm-wrapped",
                "key_provider": "hsm",
                "kms_key_ref": "byok-kek",
                "hsm_slot_id": "s1",
            }
        )
        with (
            patch.object(crypto.db, "connect_admin", return_value=conn),
            patch.object(crypto, "_slot_url", return_value=slot_url),
            patch.object(hsm, "unwrap_dek_for_slot", return_value=raw),
        ):
            token, provider = crypto.encrypt_for_project(pid, "secret-value")
        assert provider == "project"
        with (
            patch.object(crypto.db, "connect_admin", return_value=conn),
            patch.object(crypto, "_slot_url", return_value=slot_url),
            patch.object(hsm, "unwrap_dek_for_slot", return_value=raw),
        ):
            assert crypto.decrypt_for_project(pid, token, "project") == "secret-value"

    def test_hsm_unwrap_used_for_hsm_provider(self):
        from crypto import hsm

        pid = str(uuid4())
        raw = crypto.generate_project_key()
        slot_url = "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x"
        conn, _ = _conn(
            fetchone={
                "key_enc": "hsm-wrapped",
                "key_provider": "hsm",
                "kms_key_ref": "byok-kek",
                "hsm_slot_id": "s1",
            }
        )
        with (
            patch.object(crypto.db, "connect_admin", return_value=conn),
            patch.object(crypto, "_slot_url", return_value=slot_url),
            patch.object(hsm, "unwrap_dek_for_slot", return_value=raw) as unwrap,
        ):
            crypto.encrypt_for_project(pid, "x")
        unwrap.assert_called_once_with(slot_url, "hsm-wrapped", "byok-kek")


class TestHsmDekContract:
    """generate_project_key() returns 32 raw bytes; HSM wraps the raw DEK."""

    def test_dek_to_raw_accepts_generate_project_key(self):
        from crypto import hsm

        fkey = crypto.generate_project_key()
        assert len(fkey) == 32
        assert hsm.dek_to_raw(fkey) == fkey

    def test_dek_to_raw_accepts_32_bytes(self):
        import os

        from crypto import hsm

        raw = os.urandom(32)
        assert hsm.dek_to_raw(raw) == raw

    def test_dek_to_raw_rejects_bad_length(self):
        from crypto import hsm

        with pytest.raises(ValueError, match="DEK must be"):
            hsm.dek_to_raw(b"too-short")

    def test_ensure_project_key_hsm_passes_raw_dek_to_wrap(self):
        """Regression: wrap_dek_for_slot must receive the raw 32-byte DEK."""
        from crypto import hsm, project_keys

        pid = str(uuid4())
        slot_id = str(uuid4())
        seen = {}

        def capture_wrap(slot_url, dek):
            seen["dek"] = dek
            hsm.dek_to_raw(dek)
            return ("hsm-wrapped", "byok-kek")

        admin_conn, admin_cur = _project_keys_conn(fetchone=None)
        with (
            patch.object(project_keys.db, "connect_admin", return_value=admin_conn),
            patch.object(
                project_keys.crypto,
                "slot_url",
                return_value="pkcs11:token=t;object=k?module-path=/m.so&pin-value=x",
            ),
            patch.object(hsm, "wrap_dek_for_slot", side_effect=capture_wrap),
            patch.object(hsm, "ensure_kek_for_slot"),
        ):
            assert project_keys.ensure_project_key(pid, provider="hsm", hsm_slot_id=slot_id) is True
        assert len(seen["dek"]) == 32
        assert hsm.dek_to_raw(seen["dek"])  # does not raise


class TestDekResolution:
    def test_dek_for_hsm_slot(self):
        from crypto import hsm

        raw = crypto.generate_project_key()
        slot_url = "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x"
        row = {
            "key_enc": "slot-wrapped",
            "key_provider": "hsm",
            "kms_key_ref": "byok-kek",
            "hsm_slot_id": "s1",
        }
        with (
            patch.object(crypto, "_slot_url", return_value=slot_url),
            patch.object(hsm, "unwrap_dek_for_slot", return_value=raw) as unwrap,
        ):
            out = crypto._dek_for(row)
        assert out == raw
        unwrap.assert_called_once_with(slot_url, "slot-wrapped", "byok-kek")

    def test_dek_for_hsm_requires_slot(self):
        row = {
            "key_enc": "x",
            "key_provider": "hsm",
            "kms_key_ref": "byok-kek",
            "hsm_slot_id": None,
        }
        with pytest.raises(RuntimeError, match="no slot"):
            crypto._dek_for(row)

    def test_dek_for_hsm_missing_slot_url(self):
        row = {
            "key_enc": "x",
            "key_provider": "hsm",
            "kms_key_ref": "byok-kek",
            "hsm_slot_id": "s1",
        }
        with patch.object(crypto, "_slot_url", return_value=None):
            with pytest.raises(RuntimeError, match="slot not found"):
                crypto._dek_for(row)


def _project_keys_conn(fetchone=None, fetchall=None):
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


def _conn(fetchone=None, fetch_key=None):
    cur = MagicMock()
    if fetch_key is not None:
        cur.fetchone.return_value = {"key_enc": fetch_key}
    else:
        cur.fetchone.return_value = fetchone
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    cur.__enter__.return_value = cur
    cur.__exit__.return_value = False
    return conn, cur


class TestFipsPrimitives:
    def test_aes_gcm_rejects_corrupt_token(self):
        good = crypto.encrypt("value")
        with pytest.raises(ValueError):
            crypto.decrypt(good[:-4] + "AAAA")  # mangled tag/payload

    def test_master_key_derivation_is_hkdf(self):
        k1 = crypto.master_aes_key("master-key-1")
        k2 = crypto.master_aes_key("master-key-2")
        assert len(k1) == 32 and len(k2) == 32
        assert k1 != k2
        assert crypto.master_aes_key("master-key-1") == k1  # deterministic

    def test_pbkdf2_password_hash(self):
        from auth import passwords

        h = passwords.hash_password("correct horse battery staple")
        assert h.startswith("pbkdf2$sha256$")
        assert passwords.verify_password("correct horse battery staple", h)
        assert not passwords.verify_password("wrong password", h)
        assert not passwords.verify_password("x", "not-a-hash")
        assert not passwords.verify_password("x", "$2b$12$legacybcrypt.hash")


class TestKeyedCrypto:
    def test_encrypt_decrypt_with_explicit_key(self):
        key = crypto.master_aes_key("explicit")
        token = crypto.encrypt_with_key(key, "payload")
        assert token.startswith("gcm$")
        assert crypto.decrypt_with_key(key, token) == "payload"

    def test_decrypt_with_wrong_key_rejected(self):
        good = crypto.master_aes_key("a")
        other = crypto.master_aes_key("b")
        token = crypto.encrypt_with_key(good, "secret")
        with pytest.raises(ValueError):
            crypto.decrypt_with_key(other, token)

    def test_project_has_key_and_dek(self):
        raw = crypto.generate_project_key()
        row = {
            "key_enc": crypto.wrap_project_key(raw),
            "key_provider": "local",
            "kms_key_ref": None,
            "hsm_slot_id": None,
        }
        with patch.object(crypto, "_project_key", return_value=row):
            assert crypto.project_has_key(str(uuid4())) is True
            assert crypto.project_dek(str(uuid4())) == raw
        with patch.object(crypto, "_project_key", return_value=None):
            assert crypto.project_has_key(str(uuid4())) is False
            assert crypto.project_dek(str(uuid4())) is None

    def test_clear_cache_invalidates_epoch(self):
        client = MagicMock()
        with patch.object(crypto.cache, "redis_client", return_value=client):
            crypto.clear_project_key_cache()
            crypto.clear_slot_url_cache()
        assert client.incr.call_count >= 1
