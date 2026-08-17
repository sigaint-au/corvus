"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import app as store
from auth import authz, lockout, user_sessions
from core import db, settings_svc
from integrations import ldap_auth
from tests.helpers import mock_conn as _conn

store.app.config["TESTING"] = True

class TestMailer:

    def test_smtp_configured_requires_host_and_from(self):
        from integrations import mailer
        assert not mailer.smtp_configured({'smtp_enabled': 'true', 'smtp_host': '', 'smtp_from_email': 'a@b.c'})
        assert not mailer.smtp_configured({'smtp_enabled': 'false', 'smtp_host': 'h', 'smtp_from_email': 'a@b.c'})
        assert mailer.smtp_configured({'smtp_enabled': 'true', 'smtp_host': 'smtp.example.com', 'smtp_from_email': 'a@b.c'})

    def test_login_alerts_need_smtp(self):
        from integrations import mailer
        assert not mailer.login_alerts_enabled({'smtp_enabled': 'true', 'smtp_host': 'h', 'smtp_from_email': 'a@b.c', 'smtp_login_alerts': 'false'})
        assert mailer.login_alerts_enabled({'smtp_enabled': 'true', 'smtp_host': 'h', 'smtp_from_email': 'a@b.c', 'smtp_login_alerts': 'true'})

    def test_send_email_not_configured(self):
        from integrations import mailer
        ok, err = mailer.send_email('a@b.c', 'subj', 'body', cfg={'smtp_enabled': 'false', 'smtp_host': '', 'smtp_from_email': ''})
        assert not ok
        assert 'SMTP' in err

    def test_send_email_starttls(self):
        from integrations import mailer
        cfg = {'smtp_enabled': 'true', 'smtp_host': 'smtp.example.com', 'smtp_port': '587', 'smtp_encryption': 'starttls', 'smtp_username': 'u', 'smtp_password': '', 'smtp_from_email': 'from@ex.com', 'smtp_from_name': 'App'}
        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        with patch('integrations.mailer.smtplib.SMTP', return_value=mock_smtp) as SMTP:
            ok, err = mailer.send_email('to@ex.com', 'Hello', 'Body text', cfg=cfg)
        assert ok
        assert err == ''
        SMTP.assert_called_once()
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with('u', '')
        mock_smtp.send_message.assert_called_once()

    def test_forgot_password_sends_email(self):
        store.app.config['TESTING'] = True
        client = store.app.test_client()
        with patch('auth.passwords.create_reset_token', return_value='tok123'), patch('integrations.mailer.smtp_configured', return_value=True), patch('integrations.mailer.send_password_reset', return_value=(True, '')) as send:
            r = client.post('/forgot-password', data={'email': 'user@ex.com'}, follow_redirects=False)
        assert r.status_code == 302
        send.assert_called_once()
        args = send.call_args[0]
        assert args[0] == 'user@ex.com'
        assert '/reset-password/tok123' in args[1]

    def test_login_sends_alert_when_enabled(self):
        store.app.config['TESTING'] = True
        client = store.app.test_client()
        uid = uuid4()
        conn, _ = _conn(fetchone={'id': uid, 'email': 'a@b.c', 'name': 'A'})
        with patch.object(db, 'connect', return_value=conn), patch.object(ldap_auth, 'ldap_cfg', return_value={'ldap_enabled': 'false'}), patch.object(settings_svc, 'setup_notice', return_value=None), patch.object(lockout, 'is_locked', return_value=False), patch.object(lockout, 'clear_failures'), patch.object(authz, 'is_global_admin', return_value=False), patch.object(authz, 'is_account_disabled', return_value=False), patch('auth.totp_svc.needs_challenge', return_value=None), patch('integrations.mailer.login_alerts_enabled', return_value=True), patch('integrations.mailer.send_login_alert', return_value=(True, '')) as alert, patch.object(user_sessions, 'create_session', return_value=None):
            r = client.post('/login', data={'email': 'a@b.c', 'password': 'secret12'}, follow_redirects=False)
        assert r.status_code == 302
        alert.assert_called_once()
        assert alert.call_args[0][0] == 'a@b.c'

