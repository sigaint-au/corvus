"""Route-level tests for the HSM onboarding UI (wizard + settings)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import app as store
import audit
import crypto
from auth import authz
from core import db
from crypto import hsm, project_keys

store.app.config["TESTING"] = True


def _team_conn():
    cur = MagicMock()
    cur.fetchone.side_effect = [
        {"id": "teamid", "name": "Platform"},  # wizard team row
        {"r": "team-owner"},  # wizard team_role
    ]
    cur.__enter__.return_value = cur
    cur.__exit__.return_value = False
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    return conn


def _slots_conn(slots):
    cur = MagicMock()
    cur.fetchall.return_value = slots
    cur.__enter__.return_value = cur
    cur.__exit__.return_value = False
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    return conn


class TestHsmWizard:
    def setup_method(self):
        self.client = store.app.test_client()
        with self.client.session_transaction() as s:
            s["user_id"] = str(uuid4())

    def test_hides_hsm_when_no_slots(self):
        with (
            patch.object(db, "as_user", return_value=_team_conn()),
            patch.object(db, "connect_admin", return_value=_slots_conn([])),
        ):
            r = self.client.get(f"/teams/{uuid4()}/projects/new")
        assert r.status_code == 200
        assert b'value="hsm"' not in r.data

    def test_shows_hsm_when_slots_exist(self):
        slot = {"id": str(uuid4()), "name": "prod-hsm", "is_default": True}
        with (
            patch.object(db, "as_user", return_value=_team_conn()),
            patch.object(db, "connect_admin", return_value=_slots_conn([slot])),
        ):
            r = self.client.get(f"/teams/{uuid4()}/projects/new")
        assert r.status_code == 200
        assert b'value="hsm"' in r.data
        assert b"prod-hsm" in r.data


class TestHsmSettingsAdopt:
    def setup_method(self):
        self.client = store.app.test_client()
        with self.client.session_transaction() as s:
            s["user_id"] = str(uuid4())
        self.pid = str(uuid4())

    def _admin_conn(self):
        cur = MagicMock()
        cur.fetchone.side_effect = [
            {"team_id": "teamid"},  # project team_id
            {"g": True},  # is_global_admin
            {"r": "team-owner"},  # team_role
        ]
        cur.__enter__.return_value = cur
        cur.__exit__.return_value = False
        conn = MagicMock()
        conn.cursor.return_value = cur
        conn.__enter__.return_value = conn
        conn.__exit__.return_value = False
        return conn

    def test_adopt_hsm_requires_slot(self):
        with (
            patch.object(db, "as_user", return_value=self._admin_conn()),
            patch.object(project_keys, "ensure_project_key") as ensure,
            patch.object(project_keys, "adopt_project_key") as adopt,
        ):
            r = self.client.post(
                f"/projects/{self.pid}/crypto",
                data={"action": "adopt", "provider": "hsm"},
            )
        assert r.status_code == 302
        ensure.assert_not_called()
        adopt.assert_not_called()

    def test_adopt_hsm_success(self):
        slot = str(uuid4())
        with (
            patch.object(db, "as_user", return_value=self._admin_conn()),
            patch.object(project_keys, "ensure_project_key", return_value=True),
            patch.object(project_keys, "adopt_project_key", return_value=5) as adopt,
        ):
            r = self.client.post(
                f"/projects/{self.pid}/crypto",
                data={"action": "adopt", "provider": "hsm", "hsm_slot": slot},
            )
        assert r.status_code == 302
        adopt.assert_called_once_with(UUID(self.pid), provider="hsm", hsm_slot_id=slot)

    def test_migrate_hsm_route(self):
        slot = str(uuid4())
        with (
            patch.object(db, "as_user", return_value=self._admin_conn()),
            patch.object(project_keys, "migrate_project_key", return_value=7) as migrate,
        ):
            r = self.client.post(
                f"/projects/{self.pid}/crypto",
                data={"action": "migrate", "provider": "hsm", "target_slot": slot},
            )
        assert r.status_code == 302
        migrate.assert_called_once_with(UUID(self.pid), "hsm", target_slot_id=slot)


class TestHsmSlotWizard:
    """Tests for the HSM slot wizard (create, edit, save-without-testing)."""

    def setup_method(self):
        self.client = store.app.test_client()
        self.uid = str(uuid4())
        with self.client.session_transaction() as s:
            s["user_id"] = self.uid
            s["is_global_admin"] = True

    def test_wizard_edit_prefills_slot(self):
        """GET with slot_id pre-fills the form and shows 'Edit' title."""
        slot_id = str(uuid4())
        slot_data = {
            "id": slot_id,
            "name": "prod-hsm",
            "pkcs11_url": "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x",
            "description": "Production HSM",
            "is_default": True,
        }
        from tests.helpers import mock_conn

        user_conn, _ = mock_conn(fetchone=slot_data)
        with (
            patch.object(authz, "is_global_admin", return_value=True),
            patch.object(db, "as_user", return_value=user_conn),
        ):
            r = self.client.get(f"/settings/encryption/hsm-slots/new?slot_id={slot_id}")
        assert r.status_code == 200
        assert b"Edit HSM slot" in r.data
        assert b"prod-hsm" in r.data
        assert b"Production HSM" in r.data

    def test_wizard_create_logs_audit(self):
        """POST create logs an hsm_slot_added audit event."""
        from tests.helpers import mock_conn

        admin_conn, _ = mock_conn(fetchone={"is_global_admin": True})
        user_conn, _ = mock_conn(fetchone={"id": str(uuid4())})
        with (
            patch.object(authz, "is_global_admin", return_value=True),
            patch.object(hsm, "test_connection_for_slot", return_value=(True, "OK")),
            patch.object(db, "as_user", return_value=user_conn),
            patch.object(db, "connect_admin", return_value=admin_conn),
            patch.object(crypto, "clear_slot_url_cache"),
            patch.object(audit, "log_org") as log_org,
        ):
            r = self.client.post(
                "/settings/encryption/hsm-slots/new",
                data={
                    "action": "create",
                    "name": "test-slot",
                    "pkcs11_url": "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x",
                },
            )
        assert r.status_code == 302
        log_org.assert_called_once()
        assert log_org.call_args.kwargs["action"] == "hsm_slot_added"

    def test_wizard_force_create_saves_without_test(self):
        """POST force_create saves the slot even when the connection test fails."""
        from tests.helpers import mock_conn

        admin_conn, _ = mock_conn(fetchone={"is_global_admin": True})
        user_conn, _ = mock_conn(fetchone={"id": str(uuid4())})
        with (
            patch.object(authz, "is_global_admin", return_value=True),
            patch.object(
                hsm, "test_connection_for_slot", return_value=(False, "connection refused")
            ),
            patch.object(db, "as_user", return_value=user_conn),
            patch.object(db, "connect_admin", return_value=admin_conn),
            patch.object(crypto, "clear_slot_url_cache"),
            patch.object(audit, "log_org") as log_org,
        ):
            r = self.client.post(
                "/settings/encryption/hsm-slots/new",
                data={
                    "action": "force_create",
                    "name": "offline-slot",
                    "pkcs11_url": "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x",
                },
            )
        assert r.status_code == 302
        log_org.assert_called_once()
        assert log_org.call_args.kwargs["action"] == "hsm_slot_added"

    def test_wizard_edit_logs_audit(self):
        """POST create with slot_id logs hsm_slot_edited (not added)."""
        slot_id = str(uuid4())
        from tests.helpers import mock_conn

        admin_conn, _ = mock_conn(fetchone={"is_global_admin": True})
        user_conn, _ = mock_conn(fetchone={"id": slot_id})
        with (
            patch.object(authz, "is_global_admin", return_value=True),
            patch.object(hsm, "test_connection_for_slot", return_value=(True, "OK")),
            patch.object(db, "as_user", return_value=user_conn),
            patch.object(db, "connect_admin", return_value=admin_conn),
            patch.object(crypto, "clear_slot_url_cache"),
            patch.object(audit, "log_org") as log_org,
        ):
            r = self.client.post(
                "/settings/encryption/hsm-slots/new",
                data={
                    "action": "create",
                    "slot_id": slot_id,
                    "name": "updated-slot",
                    "pkcs11_url": "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x",
                },
            )
        assert r.status_code == 302
        log_org.assert_called_once()
        assert log_org.call_args.kwargs["action"] == "hsm_slot_edited"
