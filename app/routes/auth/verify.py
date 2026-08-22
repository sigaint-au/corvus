"""Email verification: confirm-the-address link and resend."""

from __future__ import annotations

import hashlib
import logging

from flask import flash, redirect, render_template, request, url_for

from core import db

from .helpers import send_verification_email

log = logging.getLogger(__name__)


def verify_email(token: str):
    """Confirm an emailed verification link.

    Args:
        token: Random token from the emailed URL; stored hashed on the user row.

    Returns:
        Redirect to login with a result flash (single-use, 3-day window).

    Example:
        GET /verify-email/<token>
    """
    thash = hashlib.sha256((token or "").encode()).hexdigest()
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id FROM private.users
             WHERE email_verify_token_hash = %s
               AND email_verify_sent_at > now() - interval '3 days'
               AND email_verified_at IS NULL
            """,
            (thash,),
        )
        row = cur.fetchone()
        if not row:
            flash(
                "This verification link is invalid or expired. "
                "Request a new link below.",
                "error",
            )
            return redirect(url_for("verify_resend_page"))
        cur.execute(
            """
            UPDATE private.users
               SET email_verified_at = now(),
                   email_verify_token_hash = NULL,
                   email_verify_sent_at = NULL
             WHERE id = %s::uuid
            """,
            (str(row["id"]),),
        )
    flash("Email verified. Sign in.", "ok")
    return redirect(url_for("login"))


def resend_verification():
    """Resend the verification email for an unverified local account.

    Always answers with the same generic confirmation so the endpoint cannot
    be used to probe which addresses are registered. Throttled to one send
    per address per 60 seconds via ``email_verify_sent_at``.

    Args:
        None (reads form ``email``).

    Returns:
        Redirect to the verification page with a generic ok flash.

    Example:
        POST /verify-email/resend  (form field: email)
    """
    email = (request.form.get("email") or "").strip().lower()
    if email:
        try:
            with db.connect_admin() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, email FROM private.users
                     WHERE email = %s
                       AND auth_source = 'local'
                       AND password_hash IS NOT NULL
                       AND disabled_at IS NULL
                       AND email_verified_at IS NULL
                       AND (email_verify_sent_at IS NULL
                            OR email_verify_sent_at < now() - interval '60 seconds')
                    """,
                    (email,),
                )
                row = cur.fetchone()
                if row:
                    send_verification_email(row["id"], row["email"])
        except Exception:
            # Never leak lookup/send state through the response.
            log.exception("resend verification failed")
    flash(
        "If that address belongs to an unverified account, we sent a new link.",
        "ok",
    )
    return redirect(url_for("verify_resend_page"))


def verify_resend_page():
    """Step-2 signup screen: check-inbox notice plus resend form.

    Also reachable standalone (GET /verify-email) for users who lost
    the email; ``?email=`` pre-fills the form.

    Args:
        None (reads optional query arg ``email``).

    Returns:
        HTML verification page.

    Example:
        GET /verify-email?email=user@example.com
    """
    return render_template("verify_email.html", email=request.args.get("email", ""))
