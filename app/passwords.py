"""Local-account password change and reset helpers."""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone

import db
from crypto import sha256_hex

log = logging.getLogger(__name__)

MIN_PASSWORD_LEN = 8
RESET_TOKEN_HOURS = 1


def change_password(user_id: str, old_password: str, new_password: str) -> tuple[bool, str]:
    """Change password for a local user after verifying the current password.

    Args:
        user_id: UUID of the user whose password will change.
        old_password: Current password for verification.
        new_password: Desired new password (must be at least ``MIN_PASSWORD_LEN``).

    Returns:
        ``(True, "")`` on success, or ``(False, error_message)`` on failure
        (too short, wrong current password, non-local account, or DB error).

    Example:
        >>> ok, err = change_password(uid, "old-pass", "new-secure-pass")
        >>> if not ok:
        ...     flash(err, "error")
    """
    if len(new_password or "") < MIN_PASSWORD_LEN:
        return False, f"Password must be at least {MIN_PASSWORD_LEN} characters"
    if not old_password:
        return False, "Current password is required"
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT private.change_password(%s::uuid, %s, %s) AS ok",
                (user_id, old_password, new_password),
            )
            row = cur.fetchone()
            if row and row.get("ok"):
                return True, ""
            return False, "Current password is incorrect or account is not local"
    except Exception as e:
        log.exception("change_password failed")
        return False, str(e)


def create_reset_token(email: str) -> str | None:
    """Create a password-reset token for a local user by email.

    Only succeeds for enabled local accounts with a password hash. Invalid or
    unknown emails return None (no enumeration).

    Args:
        email: Account email (normalized to lowercase).

    Returns:
        Plaintext reset token to email to the user, or None if no eligible user.

    Example:
        >>> token = create_reset_token("user@example.com")
        >>> if token:
        ...     send_password_reset("user@example.com", token)
    """
    email = (email or "").strip().lower()
    if not email:
        return None
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM private.users
                WHERE email = %s
                  AND auth_source = 'local'
                  AND password_hash IS NOT NULL
                  AND disabled_at IS NULL
                """,
                (email,),
            )
            user = cur.fetchone()
            if not user:
                return None
            return _insert_reset_token(cur, str(user["id"]))
    except Exception:
        log.exception("create_reset_token failed")
        return None


def create_reset_token_for_user(user_id: str) -> tuple[str | None, str]:
    """Admin helper: create a password-reset token for a specific local account.

    Args:
        user_id: UUID of the target user.

    Returns:
        ``(token, "")`` on success, or ``(None, error_message)`` if the user is
        missing, disabled, or not a local password account.

    Example:
        >>> token, err = create_reset_token_for_user(user_id)
        >>> if err:
        ...     flash(err, "error")
        ... else:
        ...     # show one-time link to admin or email user
        ...     pass
    """
    if not user_id:
        return None, "User required"
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, auth_source, password_hash, disabled_at
                FROM private.users
                WHERE id = %s::uuid
                """,
                (str(user_id),),
            )
            user = cur.fetchone()
            if not user:
                return None, "User not found"
            if user.get("disabled_at"):
                return None, "Account is disabled — enable it before resetting password"
            if user.get("auth_source") != "local" or not user.get("password_hash"):
                return None, "Password reset only applies to local password accounts"
            token = _insert_reset_token(cur, str(user["id"]))
            if not token:
                return None, "Could not create reset token"
            return token, ""
    except Exception as e:
        log.exception("create_reset_token_for_user failed")
        return None, str(e)


def _insert_reset_token(cur, user_id: str) -> str | None:
    """Invalidate prior unused tokens and insert a new reset token row.

    Args:
        cur: Open DB cursor (admin connection, transactional context).
        user_id: UUID string of the user receiving the reset token.

    Returns:
        Plaintext token (``secrets.token_urlsafe(32)``), or None only if insert
        fails unexpectedly (normally always returns the token).

    Example:
        >>> with db.connect_admin() as conn, conn.cursor() as cur:
        ...     token = _insert_reset_token(cur, user_id)
        ...     # email token; store only hash in DB
    """
    token = secrets.token_urlsafe(32)
    th = sha256_hex(token)
    expires = datetime.now(timezone.utc) + timedelta(hours=RESET_TOKEN_HOURS)
    cur.execute(
        """
        UPDATE private.password_reset_tokens
        SET used_at = now()
        WHERE user_id = %s::uuid AND used_at IS NULL
        """,
        (user_id,),
    )
    cur.execute(
        """
        INSERT INTO private.password_reset_tokens
          (user_id, token_hash, expires_at)
        VALUES (%s::uuid, %s, %s)
        """,
        (user_id, th, expires),
    )
    return token


def consume_reset_token(token: str, new_password: str) -> tuple[bool, str]:
    """Validate a reset token, set the new password, and revoke all sessions.

    Marks the token used, updates the password via ``private.set_local_password``,
    and revokes active ``user_sessions`` for that user.

    Args:
        token: Plaintext token from the reset link/email.
        new_password: New password (min ``MIN_PASSWORD_LEN`` characters).

    Returns:
        ``(True, "")`` on success, or ``(False, error_message)`` for invalid/
        expired token, weak password, or DB errors.

    Example:
        >>> ok, err = consume_reset_token(request.args["token"], form["password"])
        >>> if ok:
        ...     flash("Password updated — please sign in")
    """
    if len(new_password or "") < MIN_PASSWORD_LEN:
        return False, f"Password must be at least {MIN_PASSWORD_LEN} characters"
    if not token:
        return False, "Invalid or expired reset link"
    th = sha256_hex(token)
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT t.id, t.user_id
                FROM private.password_reset_tokens t
                WHERE t.token_hash = %s
                  AND t.used_at IS NULL
                  AND t.expires_at > now()
                """,
                (th,),
            )
            row = cur.fetchone()
            if not row:
                return False, "Invalid or expired reset link"
            cur.execute(
                "SELECT private.set_local_password(%s::uuid, %s) AS ok",
                (str(row["user_id"]), new_password),
            )
            ok = (cur.fetchone() or {}).get("ok")
            if not ok:
                return False, "Could not update password"
            cur.execute(
                """
                UPDATE private.password_reset_tokens
                SET used_at = now()
                WHERE id = %s::uuid
                """,
                (str(row["id"]),),
            )
            # Sign out all sessions after reset
            cur.execute(
                """
                UPDATE private.user_sessions
                SET revoked_at = now()
                WHERE user_id = %s::uuid AND revoked_at IS NULL
                """,
                (str(row["user_id"]),),
            )
            return True, ""
    except Exception as e:
        log.exception("consume_reset_token failed")
        return False, str(e)
