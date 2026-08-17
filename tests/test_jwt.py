"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from uuid import uuid4

import jwt as pyjwt

import app as store
from core import config, db

store.app.config["TESTING"] = True

class TestJWT:

    def test_make_jwt_claims(self):
        uid = str(uuid4())
        token = db.make_jwt(uid, hours=1)
        claims = pyjwt.decode(token, config.JWT_SECRET, algorithms=['HS256'])
        assert claims['sub'] == uid
        assert claims['role'] == 'authenticated'
        assert 'exp' in claims

