"""Outbound email via server SMTP settings (password resets, login alerts)."""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

from core.config import APP_NAME, DEFAULT_SETTINGS, SMTP_ENCRYPTION_MODES, SMTP_SETTING_KEYS
from core.settings_svc import get_settings, truthy
from crypto import decrypt

log = logging.getLogger(__name__)

SMTP_TIMEOUT = 20


def smtp_cfg() -> dict:
    """Build the SMTP settings dict from stored server settings.

    Returns:
        Mapping of each SMTP setting key to its configured value, using
        defaults from DEFAULT_SETTINGS when a key is unset.

    Example:
        >>> cfg = smtp_cfg()
        >>> "smtp_host" in cfg
        True
    """
    s = get_settings()
    return {k: s.get(k, DEFAULT_SETTINGS.get(k, "")) for k in SMTP_SETTING_KEYS}


def smtp_password_plain(cfg: dict) -> str:
    """Decrypt the SMTP password from encrypted settings.

    Args:
        cfg: SMTP settings mapping that may contain ``smtp_password``
            (encrypted ciphertext).

    Returns:
        Decrypted plaintext SMTP password, or an empty string if unset
        or decryption fails.

    Example:
        >>> smtp_password_plain({"smtp_password": ""})
        ''
    """
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
    """Return whether SMTP is enabled and has host plus from address.

    Args:
        cfg: Optional SMTP settings dict; when None, loads via ``smtp_cfg()``.

    Returns:
        True when SMTP is enabled and both host and from-email are set;
        False otherwise.

    Example:
        >>> smtp_configured({"smtp_enabled": "false"})
        False
    """
    c = cfg if cfg is not None else smtp_cfg()
    if not truthy(c.get("smtp_enabled")):
        return False
    host = (c.get("smtp_host") or "").strip()
    from_email = (c.get("smtp_from_email") or "").strip()
    return bool(host and from_email)


def login_alerts_enabled(cfg: dict | None = None) -> bool:
    """Return whether successful-login alert emails are enabled.

    Args:
        cfg: Optional SMTP settings dict; when None, loads via ``smtp_cfg()``.

    Returns:
        True when SMTP is fully configured and ``smtp_login_alerts`` is
        truthy; False otherwise.

    Example:
        >>> login_alerts_enabled({"smtp_enabled": "false", "smtp_login_alerts": "true"})
        False
    """
    c = cfg if cfg is not None else smtp_cfg()
    return smtp_configured(c) and truthy(c.get("smtp_login_alerts"))


def _port(cfg: dict) -> int:
    """Parse and validate the SMTP port from settings.

    Args:
        cfg: SMTP settings mapping that may contain ``smtp_port``.

    Returns:
        Integer port in range 1–65535, or 587 if missing/invalid.

    Example:
        >>> _port({"smtp_port": "465"})
        465
        >>> _port({"smtp_port": "bad"})
        587
    """
    try:
        p = int(str(cfg.get("smtp_port") or "587").strip() or "587")
        if 1 <= p <= 65535:
            return p
    except (TypeError, ValueError):
        pass
    return 587


def _encryption(cfg: dict) -> str:
    """Resolve the SMTP encryption mode from settings.

    Args:
        cfg: SMTP settings mapping that may contain ``smtp_encryption``.

    Returns:
        One of the allowed modes in ``SMTP_ENCRYPTION_MODES`` (e.g.
        ``starttls``, ``ssl``, ``none``); defaults to ``starttls`` if
        unset or invalid.

    Example:
        >>> _encryption({"smtp_encryption": "ssl"})
        'ssl'
        >>> _encryption({"smtp_encryption": "bogus"})
        'starttls'
    """
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
    """Send a plain-text email using server SMTP settings.

    Args:
        to_email: Recipient email address.
        subject: Message subject line.
        body_text: Plain-text body content.
        cfg: Optional SMTP settings dict; when None, loads via ``smtp_cfg()``.

    Returns:
        Tuple ``(ok, error_message)``. ``error_message`` is empty on
        success; on failure ``ok`` is False and the message describes
        the problem (e.g. SMTP not configured, send error).

    Example:
        >>> ok, err = send_email("user@example.com", "Hello", "Body text")
        >>> # ok is True on success; err is "" or an error string
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
    """Email a password-reset link to the user.

    Args:
        to_email: Recipient email address.
        reset_url: Absolute URL the user opens to choose a new password.

    Returns:
        Tuple ``(ok, error)`` from ``send_email``.

    Example:
        >>> ok, err = send_password_reset(
        ...     "user@example.com",
        ...     "https://app.example/reset?token=abc",
        ... )
    """
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
    """Notify the account holder of a successful sign-in.

    Args:
        to_email: Account email address to notify.
        ip: Optional client IP address string for the alert body.
        user_agent: Optional User-Agent string for the alert body.
        when: Optional human-readable timestamp of the sign-in.

    Returns:
        Tuple ``(ok, error)`` from ``send_email``.

    Example:
        >>> ok, err = send_login_alert(
        ...     "user@example.com",
        ...     ip="203.0.113.1",
        ...     when="2024-01-01 12:00 UTC",
        ... )
    """
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
    """Send a short test message to verify SMTP settings.

    Args:
        to_email: Recipient email address for the test message.

    Returns:
        Tuple ``(ok, error)`` from ``send_email``.

    Example:
        >>> ok, err = send_test_email("admin@example.com")
    """
    subject = f"Test email — {APP_NAME}"
    body = (
        f"This is a test message from {APP_NAME}.\n\n"
        "If you received this, SMTP is configured correctly.\n"
    )
    return send_email(to_email, subject, body)
