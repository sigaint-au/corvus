"""Admin operations — shared between UI routes and mgmt API."""

from __future__ import annotations

import logging

import audit
from auth import passwords, totp_svc, user_sessions
from core import db

log = logging.getLogger(__name__)


def disable_user(user_id: str, actor_id: str) -> tuple[bool, str]:
    """Disable a user account and revoke all sessions.

    Args:
        user_id: UUID of the user to disable.
        actor_id: UUID of the admin performing the action.

    Returns:
        ``(True, "")`` on success, or ``(False, error_message)``.
    """
    if not user_id or not actor_id:
        return False, "User and actor required"
    if actor_id == user_id:
        return False, "You cannot disable your own account"
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE private.users
                SET disabled_at = now()
                WHERE id = %s::uuid AND disabled_at IS NULL
                RETURNING id, email
                """,
                (user_id,),
            )
            row = cur.fetchone()
            if not row:
                return False, "User not found or already disabled"
            user_sessions.revoke_all_sessions(user_id)
            audit.log_org(
                cur,
                action=audit.ORG_USER_DISABLED,
                detail=f"user_id={user_id}",
                actor_email=None,
            )
            conn.commit()
        return True, ""
    except Exception as e:
        log.exception("disable_user failed")
        return False, str(e)


def enable_user(user_id: str) -> tuple[bool, str]:
    """Re-enable a disabled user account.

    Args:
        user_id: UUID of the user to enable.

    Returns:
        ``(True, "")`` on success, or ``(False, error_message)``.
    """
    if not user_id:
        return False, "User required"
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE private.users
                SET disabled_at = NULL
                WHERE id = %s::uuid AND disabled_at IS NOT NULL
                RETURNING id, email
                """,
                (user_id,),
            )
            row = cur.fetchone()
            if not row:
                return False, "User not found or already active"
            audit.log_org(
                cur,
                action=audit.ORG_USER_ENABLED,
                detail=f"user_id={user_id}",
                actor_email=None,
            )
            conn.commit()
        return True, ""
    except Exception as e:
        log.exception("enable_user failed")
        return False, str(e)


def promote_user(email: str, actor_id: str) -> tuple[bool, str]:
    """Promote a user to global admin by email.

    Args:
        email: Email of the user to promote (lowercased).
        actor_id: UUID of the admin performing the action.

    Returns:
        ``(True, "")`` on success, or ``(False, error_message)``.
    """
    email = (email or "").strip().lower()
    if not email:
        return False, "Email address required"
    if not actor_id:
        return False, "Actor required"
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE private.users
                SET is_global_admin = true
                WHERE email = %s
                RETURNING id, email
                """,
                (email,),
            )
            row = cur.fetchone()
            if not row:
                return (
                    False,
                    "No user with that email. They need to register or sign in via LDAP first.",
                )
            audit.log_org(
                cur,
                action=audit.ORG_USER_PROMOTED,
                detail=f"email={email}",
                actor_email=None,
            )
            conn.commit()
        return True, ""
    except Exception as e:
        log.exception("promote_user failed")
        return False, str(e)


def demote_user(user_id: str, actor_id: str) -> tuple[bool, str]:
    """Remove global admin role from a user.

    Args:
        user_id: UUID of the user to demote.
        actor_id: UUID of the admin performing the action.

    Returns:
        ``(True, "")`` on success, or ``(False, error_message)``.
    """
    if not user_id or not actor_id:
        return False, "User and actor required"
    if actor_id == user_id:
        return False, "You cannot remove your own global admin role"
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE private.users
                SET is_global_admin = false
                WHERE id = %s::uuid
                RETURNING id, email
                """,
                (user_id,),
            )
            row = cur.fetchone()
            if not row:
                return False, "User not found"
            audit.log_org(
                cur,
                action=audit.ORG_USER_DEMOTED,
                detail=f"user_id={user_id}",
                actor_email=None,
            )
            conn.commit()
        return True, ""
    except Exception as e:
        log.exception("demote_user failed")
        return False, str(e)


def reset_user_password(user_id: str) -> tuple[str | None, str]:
    """Create a password-reset token and revoke all sessions.

    Args:
        user_id: UUID of the target user.

    Returns:
        ``(token, "")`` on success, or ``(None, error_message)``.
    """
    if not user_id:
        return None, "User required"
    token, err = passwords.create_reset_token_for_user(user_id)
    if not token:
        return None, err or "Could not create password reset"
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            user_sessions.revoke_all_sessions(user_id)
            audit.log_org(
                cur,
                action=audit.ORG_USER_PASSWORD_RESET,
                detail=f"user_id={user_id}",
                actor_email=None,
            )
            conn.commit()
    except Exception:
        log.exception("reset_user_password audit failed")
        return token, ""  # token already created; non-fatal audit failure
    return token, ""


def reset_user_2fa(user_id: str) -> tuple[bool, str]:
    """Disable TOTP and revoke all sessions for a user.

    Args:
        user_id: UUID of the target user.

    Returns:
        ``(True, "")`` on success, or ``(False, error_message)``.
    """
    if not user_id:
        return False, "User required"
    if not totp_svc.is_enabled(user_id):
        return False, "User does not have two-factor authentication enabled"
    try:
        totp_svc.disable(user_id)
        with db.connect_admin() as conn, conn.cursor() as cur:
            user_sessions.revoke_all_sessions(user_id)
            audit.log_org(
                cur,
                action=audit.ORG_USER_2FA_RESET,
                detail=f"user_id={user_id}",
                actor_email=None,
            )
            conn.commit()
        return True, ""
    except Exception as e:
        log.exception("reset_user_2fa failed")
        return False, str(e)