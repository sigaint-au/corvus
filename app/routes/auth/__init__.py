"""Auth routes package (login, register, sessions, account, tokens, 2FA)."""

from __future__ import annotations

from .account import (
    change_password,
    profile,
    revoke_other_sessions,
    revoke_session,
)
from .login import (
    forgot_password,
    login,
    login_2fa,
    login_oidc,
    login_oidc_callback,
    reset_password,
)
from .register import register_page
from .session import (
    index,
    logout,
    logout_get,
    select_team,
)
from .tokens import (
    create_personal_token,
    delete_personal_token,
)
from .totp import (
    totp_disable,
    totp_recovery_codes,
    totp_regenerate_recovery,
    totp_setup,
    totp_setup_confirm,
)
from .verify import resend_verification, verify_email


def register(app):
    """Register authentication, registration, session, and profile routes."""
    app.post("/select-team")(select_team)
    app.get("/")(index)
    app.route("/login", methods=["GET", "POST"])(login)
    app.get("/login/oidc")(login_oidc)
    app.get("/login/oidc/callback")(login_oidc_callback)
    app.route("/login/2fa", methods=["GET", "POST"])(login_2fa)
    app.route("/register", methods=["GET", "POST"], endpoint="register")(register_page)
    app.get("/verify-email/<token>")(verify_email)
    app.post("/verify-email/resend")(resend_verification)
    app.post("/logout")(logout)
    app.get("/logout")(logout_get)
    app.route("/forgot-password", methods=["GET", "POST"])(forgot_password)
    app.route("/reset-password/<token>", methods=["GET", "POST"])(reset_password)
    app.post("/profile/tokens")(create_personal_token)
    app.post("/profile/tokens/<uuid:token_id>/delete")(delete_personal_token)
    app.post("/profile/password")(change_password)
    app.post("/profile/sessions/revoke-others")(revoke_other_sessions)
    app.post("/profile/sessions/<uuid:session_id>/revoke")(revoke_session)
    app.get("/profile/2fa")(totp_setup)
    app.post("/profile/2fa/confirm")(totp_setup_confirm)
    app.get("/profile/2fa/recovery-codes")(totp_recovery_codes)
    app.post("/profile/2fa/disable")(totp_disable)
    app.post("/profile/2fa/recovery-codes/regenerate")(totp_regenerate_recovery)
    app.get("/profile")(profile)
