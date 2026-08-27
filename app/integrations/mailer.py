"""Outbound email via server SMTP settings (password resets, login alerts)."""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.config import APP_NAME, DEFAULT_SETTINGS, SMTP_ENCRYPTION_MODES, SMTP_SETTING_KEYS
from core.settings_svc import get_settings, truthy
from crypto import decrypt

log = logging.getLogger(__name__)

SMTP_TIMEOUT = 20

_TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(("html", "htm", "xml")),
)


def render_email(name: str, **ctx) -> tuple[str, str]:
    """Render an email template into ``(subject, body)``.

    Templates live in ``app/templates/emails/<name>.txt``; the first line
    is the subject, the remainder the plain-text body.
    """
    template = _env.get_template(f"emails/{name}.txt")
    text = template.render(app_name=APP_NAME, **ctx).strip("\n")
    subject, _, body = text.partition("\n")
    return subject.strip(), body


def render_email_html(name: str, **ctx) -> str:
    """Render an email's HTML body from ``app/templates/emails/<name>.html``."""
    template = _env.get_template(f"emails/{name}.html")
    return template.render(app_name=APP_NAME, **ctx).strip()


def render_email_message(name: str, **ctx) -> tuple[str, str, str]:
    """Render an email template into ``(subject, text_body, html_body)``."""
    subject, body = render_email(name, **ctx)
    return subject, body, render_email_html(name, **ctx)


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


def login_alerts_forced(cfg: dict | None = None) -> bool:
    """Return whether login alerts are required for every user.

    Args:
        cfg: Optional SMTP settings dict; when None, loads via ``smtp_cfg()``.

    Returns:
        True when the server override is on.

    Example:
        >>> login_alerts_forced({"smtp_login_alerts_force": "true"})
        True
    """
    c = cfg if cfg is not None else smtp_cfg()
    return truthy(c.get("smtp_login_alerts_force"))


def _user_login_alerts_pref(user: dict | None = None, user_id=None) -> bool:
    """Return the user's login-alert preference, defaulting to True."""
    if user is not None and "login_alerts" in user and user.get("login_alerts") is not None:
        return bool(user["login_alerts"])
    uid = user_id or ((user or {}).get("id") if user is not None else None)
    if not uid:
        return True
    try:
        from core import db

        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT login_alerts FROM private.users WHERE id = %s::uuid",
                (str(uid),),
            )
            row = cur.fetchone() or {}
        if "login_alerts" not in row or row.get("login_alerts") is None:
            return True
        return bool(row["login_alerts"])
    except Exception:
        log.exception("login-alert preference lookup failed")
        return True


def should_send_login_alert(user: dict | None = None, *, user_id=None, cfg: dict | None = None) -> bool:
    """Return whether a login-alert email should be sent for this user.

    Global ``smtp_login_alerts`` (and working SMTP) must be on. When
    ``smtp_login_alerts_force`` is on, the user preference is ignored.

    Args:
        user: Optional user mapping that may include ``login_alerts``.
        user_id: User UUID used when ``user`` has no preference field.
        cfg: Optional SMTP settings dict.

    Returns:
        True when an alert should be sent.

    Example:
        >>> should_send_login_alert(
        ...     {"login_alerts": False},
        ...     cfg={"smtp_enabled": "true", "smtp_host": "h",
        ...          "smtp_from_email": "a@b.c", "smtp_login_alerts": "true"},
        ... )
        False
    """
    c = cfg if cfg is not None else smtp_cfg()
    if not login_alerts_enabled(c):
        return False
    if login_alerts_forced(c):
        return True
    return _user_login_alerts_pref(user, user_id)


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
    body_html: str | None = None,
) -> tuple[bool, str]:
    """Send an email using server SMTP settings.

    Args:
        to_email: Recipient email address.
        subject: Message subject line.
        body_text: Plain-text body content.
        cfg: Optional SMTP settings dict; when None, loads via ``smtp_cfg()``.
        body_html: Optional HTML body; when given the message is sent as
            multipart/alternative with the plain-text part first.

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
    if body_html:
        msg.add_alternative(body_html, subtype="html")

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
    subject, body, html = render_email_message("password_reset", reset_url=reset_url)
    return send_email(to_email, subject, body, body_html=html)


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
    subject, body, html = render_email_message(
        "login_alert", ip=ip, user_agent=user_agent, when=when
    )
    return send_email(to_email, subject, body, body_html=html)


def send_test_email(to_email: str) -> tuple[bool, str]:
    """Send a short test message to verify SMTP settings.

    Args:
        to_email: Recipient email address for the test message.

    Returns:
        Tuple ``(ok, error)`` from ``send_email``.

    Example:
        >>> ok, err = send_test_email("admin@example.com")
    """
    subject, body, html = render_email_message("test")
    return send_email(to_email, subject, body, body_html=html)


def send_email_verification(to_email: str, verify_url: str) -> tuple[bool, str]:
    """Email the address-verification link for a new local account."""
    subject, body, html = render_email_message("verify_email", verify_url=verify_url)
    return send_email(to_email, subject, body, body_html=html)
