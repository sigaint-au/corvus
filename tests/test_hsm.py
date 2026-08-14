"""Route-level tests for the HSM onboarding UI (wizard + settings)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import app as store
import db
import hsm
import project_keys

store.app.config["TESTING"] = True


def _team_conn():
    cur = MagicMock()
    cur.fetchone.side_effect = [
        {"id": "teamid", "name": "Platform"},  # wizard team row
        {"r": "team-owner"},                   # wizard team_role
    ]
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

    def test_hides_hsm_when_unavailable(self):
        with patch.object(db, "as_user", return_value=_team_conn()), \
             patch.object(hsm, "available", return_value=False):
            r = self.client.get("/teams/%s/projects/new" % uuid4())
        assert r.status_code == 200
        assert b'value="hsm"' not in r.data

    def test_shows_hsm_when_available(self):
        with patch.object(db, "as_user", return_value=_team_conn()), \
             patch.object(hsm, "available", return_value=True), \
             patch.object(hsm, "kek_label", return_value="byok-kek"):
            r = self.client.get("/teams/%s/projects/new" % uuid4())
        assert r.status_code == 200
        assert b'value="hsm"' in r.data


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
            {"g": True},            # is_global_admin
            {"r": "team-owner"},    # team_role
        ]
        cur.__enter__.return_value = cur
        cur.__exit__.return_value = False
        conn = MagicMock()
        conn.cursor.return_value = cur
        conn.__enter__.return_value = conn
        conn.__exit__.return_value = False
        return conn

    def test_adopt_hsm_requires_hsm(self):
        with patch.object(db, "as_user", return_value=self._admin_conn()), \
             patch.object(hsm, "available", return_value=False), \
             patch.object(project_keys, "ensure_project_key") as ensure, \
             patch.object(project_keys, "adopt_project_key") as adopt:
            r = self.client.post(
                f"/projects/{self.pid}/crypto",
                data={"action": "adopt", "provider": "hsm"},
            )
        assert r.status_code == 302
        ensure.assert_not_called()
        adopt.assert_not_called()

    def test_adopt_hsm_success(self):
        with patch.object(db, "as_user", return_value=self._admin_conn()), \
             patch.object(hsm, "available", return_value=True), \
             patch.object(project_keys, "ensure_project_key", return_value=True), \
             patch.object(project_keys, "adopt_project_key", return_value=5) as adopt:
            r = self.client.post(
                f"/projects/{self.pid}/crypto",
                data={"action": "adopt", "provider": "hsm"},
            )
        assert r.status_code == 302
        adopt.assert_called_once_with(UUID(self.pid), provider="hsm")

    def test_migrate_hsm_route(self):
        with patch.object(db, "as_user", return_value=self._admin_conn()), \
             patch.object(hsm, "available", return_value=True), \
             patch.object(project_keys, "migrate_project_key", return_value=7) as migrate:
            r = self.client.post(
                f"/projects/{self.pid}/crypto",
                data={"action": "migrate", "provider": "hsm"},
            )
        assert r.status_code == 302
        migrate.assert_called_once_with(UUID(self.pid), "hsm", target_slot_id=None)
