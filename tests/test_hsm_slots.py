"""Unit tests for the PKCS#11 URL parser and multi-slot HSM functions."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from crypto import hsm


class TestParsePkcs11Url:
    def test_full_url(self):
        p = hsm.parse_pkcs11_url(
            "pkcs11:token=tok1;object=byok-kek;slot-id=5"
            "?module-path=/usr/lib/libsofthsm2.so&pin-value=1234"
        )
        assert p["module_path"] == "/usr/lib/libsofthsm2.so"
        assert p["token_label"] == "tok1"
        assert p["kek_label"] == "byok-kek"
        assert p["pin"] == "1234"
        assert p["slot_id"] == "5"

    def test_pin_source_reads_file(self, tmp_path):
        f = tmp_path / "pin"
        f.write_text("9999\n")
        p = hsm.parse_pkcs11_url(
            f"pkcs11:token=t;object=k?module-path=/m.so&pin-source={f}"
        )
        assert p["pin"] == "9999"

    def test_percent_decoding(self):
        p = hsm.parse_pkcs11_url(
            "pkcs11:token=my%20box;object=k%2F2?module-path=/m.so&pin-value=x"
        )
        assert p["token_label"] == "my box"
        assert p["kek_label"] == "k/2"

    def test_missing_module_path_raises(self):
        with pytest.raises(ValueError, match="module-path"):
            hsm.parse_pkcs11_url("pkcs11:token=t;object=k")

    def test_missing_token_raises(self):
        with pytest.raises(ValueError, match="token"):
            hsm.parse_pkcs11_url("pkcs11:object=k?module-path=/m.so")

    def test_not_pkcs11_raises(self):
        with pytest.raises(ValueError, match="pkcs11"):
            hsm.parse_pkcs11_url("http://example.com")

    def test_pin_source_file_error_raises(self):
        """pin-source pointing at a missing file raises a clear ValueError."""
        with pytest.raises(ValueError, match="Cannot read PIN file"):
            hsm.parse_pkcs11_url(
                "pkcs11:token=t;object=k?module-path=/m.so&pin-source=/nonexistent/path/pin"
            )


class TestHasInlinePin:
    def test_inline_pin_detected(self):
        assert hsm.has_inline_pin("pkcs11:token=t?module-path=/m.so&pin-value=1234") is True

    def test_pin_source_not_inline(self):
        assert hsm.has_inline_pin("pkcs11:token=t?module-path=/m.so&pin-source=/p") is False

    def test_empty_url(self):
        assert hsm.has_inline_pin("") is False

    def test_no_pin(self):
        assert hsm.has_inline_pin("pkcs11:token=t?module-path=/m.so") is False


class TestRedactPkcs11Url:
    def test_redacts_pin_value(self):
        url = "pkcs11:token=t?module-path=/m.so&pin-value=topsecret"
        assert "pin-value=***" in hsm.redact_pkcs11_url(url)
        assert "topsecret" not in hsm.redact_pkcs11_url(url)

    def test_preserves_pin_source(self):
        url = "pkcs11:token=t?module-path=/m.so&pin-source=/run/secrets/hsm-pin"
        out = hsm.redact_pkcs11_url(url)
        assert "/run/secrets/hsm" in out


class TestTestConnectionForSlot:
    """test_connection_for_slot returns (True, ...) when reachable, even if KEK is missing."""

    def test_returns_true_when_kek_missing(self):
        mock_session = MagicMock()
        mock_session.__enter__.return_value = mock_session
        mock_session.__exit__.return_value = False
        mock_session.get_objects.return_value = iter([])
        with patch.object(hsm, "_session", return_value=mock_session), \
             patch.object(hsm, "_pkcs11"):
            ok, msg = hsm.test_connection_for_slot(
                "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x"
            )
        assert ok is True
        assert "KEK not present" in msg

    def test_returns_true_when_kek_present(self):
        mock_session = MagicMock()
        mock_session.__enter__.return_value = mock_session
        mock_session.__exit__.return_value = False
        mock_session.get_objects.return_value = iter([MagicMock()])
        with patch.object(hsm, "_session", return_value=mock_session), \
             patch.object(hsm, "_pkcs11"):
            ok, msg = hsm.test_connection_for_slot(
                "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x"
            )
        assert ok is True
        assert "KEK present" in msg

    def test_returns_false_on_error(self):
        with patch.object(hsm, "_session", side_effect=RuntimeError("boom")):
            ok, msg = hsm.test_connection_for_slot(
                "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x"
            )
        assert ok is False
        assert "boom" in msg


class TestSlotFunctions:
    def test_status_for_slot_missing_module(self):
        with patch.object(hsm, "os") as os_mock:
            os_mock.path.exists.return_value = False
            st = hsm.status_for_slot(
                "pkcs11:token=t;object=k?module-path=/nope.so&pin-value=x"
            )
        assert st["available"] is False
        assert "not found" in (st["error"] or "")

    def test_available_for_slot_false_on_error(self):
        with patch.object(hsm, "_session", side_effect=RuntimeError("boom")):
            assert hsm.available_for_slot("pkcs11:token=t;object=k?module-path=/m.so&pin-value=x") is False

    def test_parse_in_wizard_slot_dropdown_ok(self):
        # sanity: a typical SoftHSM2 dev URL parses cleanly
        p = hsm.parse_pkcs11_url(
            "pkcs11:token=secretserver;object=byok-kek"
            "?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-value=1234"
        )
        assert p["token_label"] == "secretserver"
        assert p["kek_label"] == "byok-kek"
