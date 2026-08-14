"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import pytest

import app as store
import config
import crypto

store.app.config["TESTING"] = True

class TestCrypto:

    def test_roundtrip(self):
        assert crypto.decrypt(crypto.encrypt('ping')) == 'ping'

    def test_empty(self):
        assert crypto.decrypt(crypto.encrypt('')) == ''

    def test_unicode(self):
        s = 'héllo 🔐 日本語'
        assert crypto.decrypt(crypto.encrypt(s)) == s

    def test_ciphertext_differs(self):
        a, b = (crypto.encrypt('x'), crypto.encrypt('x'))
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
        pid2_conn, _ = _conn(
            fetch_key=crypto.wrap_project_key(crypto.generate_project_key())
        )
        with patch.object(crypto.db, "connect_admin", return_value=pid2_conn):
            with pytest.raises(ValueError):
                crypto.decrypt_for_project(pid2, token, "project")


def _conn(fetchone=None, fetch_key=None):
    from unittest.mock import MagicMock
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

