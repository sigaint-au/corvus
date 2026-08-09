"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

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

