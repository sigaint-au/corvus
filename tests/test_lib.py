"""Unit tests (pytest) for lib pure helpers. Mock DB — no Postgres required."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock
from uuid import uuid4

from lib import datetime_utils as du
from lib import metadata as meta
from lib import serialize as ser
from lib import users
from lib.validate import is_uuid


class TestLib:
    def test_is_uuid(self):
        uid = str(uuid4())
        assert is_uuid(uid)
        assert is_uuid(uid.upper())
        assert not is_uuid(None)
        assert not is_uuid("")
        assert not is_uuid("not-a-uuid")
        assert not is_uuid(123)

    def test_meta_key(self):
        assert meta.validate_meta_key("owner.email")
        assert meta.validate_meta_key("a")
        assert not meta.validate_meta_key("")
        assert not meta.validate_meta_key("-bad")
        assert not meta.validate_meta_key("x" * 66)

    def test_clean_meta_value(self):
        assert meta.clean_meta_value("  hi  ") == "hi"
        assert meta.clean_meta_value(None) == ""
        assert len(meta.clean_meta_value("x" * 3000)) == meta.META_VALUE_MAX

    def test_utc_helpers(self):
        assert du.as_utc(None) is None
        naive = datetime(2026, 1, 1, 12, 0, 0)
        assert du.as_utc(naive).tzinfo is not None
        assert du.iso_utc(None) is None
        assert du.iso_utc(naive).endswith("+00:00")
        assert du.coerce_utc(None) is None
        assert du.coerce_utc("") is None
        assert du.coerce_utc("bogus") is None
        got = du.coerce_utc("2026-01-01T12:00:00Z")
        assert got is not None and got.tzinfo == timezone.utc and got.hour == 12
        assert du.coerce_utc(naive).tzinfo is not None

    def test_serialize(self):
        uid = uuid4()
        assert ser.json_safe(uid) == str(uid)
        assert ser.json_safe("x") == "x"
        assert ser.json_safe(datetime(2026, 1, 1)) is not None
        assert ser.row_to_dict(None) == {}
        assert ser.row_to_dict({"id": uid}) == {"id": str(uid)}

    def test_lookup_user_id(self):
        uid = str(uuid4())
        cur = MagicMock()
        assert users.lookup_user_id(cur, uid.upper()) == uid.lower()
        assert users.lookup_user_id(cur, "  ") is None
        cur.fetchone.return_value = {"id": uid}
        assert users.lookup_user_id(cur, "A@x.y") == uid
        cur.fetchone.return_value = {}
        assert users.lookup_user_id(cur, "b@x.y") is None

    def test_user_email(self):
        cur = MagicMock()
        cur.fetchone.return_value = {"email": " a@x.y "}
        assert users.user_email(cur, str(uuid4())) == "a@x.y"
        assert users.user_email(cur, "") == ""
        cur.execute.side_effect = Exception("db down")
        assert users.user_email(cur, str(uuid4())) == ""
