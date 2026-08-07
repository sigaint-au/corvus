"""Outbound email via server SMTP settings (password resets, login alerts)."""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

from config import APP_NAME, DEFAULT_SETTINGS, SMTP_ENCRYPTION_MODES, SMTP_SETTING_KEYS
from crypto import decrypt
from settings_svc import get_settings, truthy

log = logging.getLogger(__name__)

SMTP_TIMEOUT = 20


def smtp_cfg() -> dict:
    s = get_settings()
    return {k: s.get(k, DEFAULT_SETTINGS.get(k, "")) for k in SMTP_SETTING_KEYS}


def smtp_password_plain(cfg: dict) -> str:
    enc = (cfg.get("smtp_password") or "").strip()
    if not enc:
        return ""
    try:
        return decrypt(enc)
    except Exception:
        log.exception(
            "failed to decrypt smtp_password; refusing ciphertext as SMTP password"
        )
        return ""


def smtp_configured(cfg: dict | None = None) -> bool:
    """True when SMTP is enabled and has host + from address."""
    c = cfg if cfg is not None else smtp_cfg()
    if not truthy(c.get("smtp_enabled")):
        return False
    host = (c.get("smtp_host") or "").strip()
    from_email = (c.get("smtp_from_email") or "").strip()
    return bool(host and from_email)


def login_alerts_enabled(cfg: dict | None = None) -> bool:
    c = cfg if cfg is not None else smtp_cfg()
    return smtp_configured(c) and truthy(c.get("smtp_login_alerts"))


def _port(cfg: dict) -> int:
    try:
        p = int(str(cfg.get("smtp_port") or "587").strip() or "587")
        if 1 <= p <= 65535:
            return p
    except (TypeError, ValueError):
        pass
    return 587


def _encryption(cfg: dict) -> str:
    mode = (cfg.get("smtp_encryption") or "starttls").strip().lower()
    if mode not in SMTP_ENCRYPTION_MODES:
        return "starttls"
    return mode


def send_email(
    to_email: str,
    subject: str,
    body_text: str,
    *,
    cfg: dict | None = None,
) -> tuple[bool, str]:
    """
    Send a plain-text email using server SMTP settings.
    Returns (ok, error_message). error_message is empty on success.
    """
    to_email = (to_email or "").strip()
    if not to_email:
        return False, "Recipient required"
    c = cfg if cfg is not None else smtp_cfg()
    if not smtp_configured(c):
        return False, "SMTP is not enabled or incomplete (host and from address required)"

    host = (c.get("smtp_host") or "").strip()
    port = _port(c)
    encryption = _encryption(c)
    username = (c.get("smtp_username") or "").strip()
    password = smtp_password_plain(c)
    from_email = (c.get("smtp_from_email") or "").strip()
    from_name = (c.get("smtp_from_name") or "").strip() or APP_NAME

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((from_name, from_email))
    msg["To"] = to_email
    msg.set_content(body_text)

    try:
        if encryption == "ssl":
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(
                host, port, timeout=SMTP_TIMEOUT, context=context
            ) as smtp:
                if username:
                    smtp.login(username, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT) as smtp:
                smtp.ehlo()
                if encryption == "starttls":
                    context = ssl.create_default_context()
                    smtp.starttls(context=context)
                    smtp.ehlo()
                if username:
                    smtp.login(username, password)
                smtp.send_message(msg)
        return True, ""
    except Exception as e:
        log.exception("SMTP send failed to %s", to_email)
        return False, str(e) or "SMTP send failed"


def send_password_reset(to_email: str, reset_url: str) -> tuple[bool, str]:
    """Email a password reset link. Returns (ok, error)."""
    subject = f"Password reset — {APP_NAME}"
    body = (
        f"You requested a password reset for your {APP_NAME} account.\n\n"
        f"Open this link to choose a new password (expires in 1 hour):\n\n"
        f"{reset_url}\n\n"
        "If you did not request this, you can ignore this message.\n"
    )
    return send_email(to_email, subject, body)


def send_login_alert(
    to_email: str,
    *,
    ip: str = "",
    user_agent: str = "",
    when: str = "",
) -> tuple[bool, str]:
    """Notify the account holder of a successful sign-in."""
    subject = f"New sign-in — {APP_NAME}"
    lines = [
        f"A successful sign-in was recorded for your {APP_NAME} account.",
        "",
    ]
    if when:
        lines.append(f"Time: {when}")
    if ip:
        lines.append(f"IP address: {ip}")
    if user_agent:
        lines.append(f"Client: {user_agent}")
    lines.extend(
        [
            "",
            "If this was you, no action is needed.",
            "If you do not recognize this sign-in, change your password and "
            "revoke other sessions from your profile.",
            "",
        ]
    )
    return send_email(to_email, subject, "\n".join(lines))


def send_test_email(to_email: str) -> tuple[bool, str]:
    """Send a short test message to verify SMTP settings."""
    subject = f"Test email — {APP_NAME}"
    body = (
        f"This is a test message from {APP_NAME}.\n\n"
        "If you received this, SMTP is configured correctly.\n"
    )
    return send_email(to_email, subject, body)
