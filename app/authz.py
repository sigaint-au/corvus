"""Auth decorators, admin checks, CSRF."""
import secrets
from functools import wraps
from urllib.parse import urlsplit

from flask import abort, current_app, flash, redirect, request, session, url_for

import db


# Endpoints allowed while pending 2FA challenge or forced TOTP enrollment
_PENDING_2FA_OK = frozenset(
    {
        "login",
        "login_2fa",
        "logout",
        "logout_get",
        "forgot_password",
        "reset_password",
    }
)
_TOTP_SETUP_OK = frozenset(
    {
        "totp_setup",
        "totp_setup_confirm",
        "totp_recovery_codes",
        "logout",
        "logout_get",
    }
)


def login_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if session.get("pending_2fa_uid"):
            return redirect(url_for("login_2fa"))
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*a, **kw)

    return wrapped


def validate_registered_session():
    """
    Ensure the browser session is still registered server-side (not revoked).
    Also gates mid-login 2FA and forced TOTP enrollment.
    Skipped in unit tests (no sid / no DB session rows).
    """
    from flask import current_app

    if current_app.config.get("TESTING"):
        return None

    # Mid-login 2FA: no full session yet
    if session.get("pending_2fa_uid"):
        if request.endpoint in _PENDING_2FA_OK or request.endpoint is None:
            return None
        return redirect(url_for("login_2fa"))

    uid = session.get("user_id")
    if not uid:
        return None

    if is_account_disabled(uid):
        session.clear()
        flash("Your account has been disabled. Contact an administrator.", "error")
        return redirect(url_for("login"))

    # Forced enrollment for global admins
    if session.get("totp_setup_required"):
        if request.endpoint in _TOTP_SETUP_OK or (
            request.endpoint and str(request.endpoint).startswith("totp_")
        ):
            return None
        flash("Set up two-factor authentication to continue.", "error")
        return redirect(url_for("totp_setup"))

    # Exempt auth endpoints that clear session themselves
    if request.endpoint in (
        "login",
        "logout",
        "register",
        "forgot_password",
        "reset_password",
        "login_2fa",
    ):
        return None
    sid = session.get("sid")
    if not sid:
        # Legacy cookie without server-side session — force re-login
        session.clear()
        flash("Please sign in again.", "error")
        return redirect(url_for("login"))
    import user_sessions

    if not user_sessions.touch_session(sid, uid):
        session.clear()
        flash("Your session was signed out or expired. Please sign in again.", "error")
        return redirect(url_for("login"))
    return None



def global_admin_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        # Always verify against DB (session flag alone can be stale after demotion)
        if not is_global_admin(session["user_id"]):
            session["is_global_admin"] = False
            flash("Global admin access required", "error")
            return redirect(url_for("projects_list"))
        session["is_global_admin"] = True
        return f(*a, **kw)

    return wrapped


def htmx():
    return request.headers.get("HX-Request") == "true"


def is_global_admin(user_id: str) -> bool:
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT is_global_admin FROM private.users WHERE id = %s::uuid",
                (user_id,),
            )
            row = cur.fetchone()
            return bool(row and row.get("is_global_admin"))
    except Exception:
        return False


def is_account_disabled(user_id: str) -> bool:
    """True when a global admin has disabled this account."""
    if not user_id:
        return False
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT disabled_at FROM private.users WHERE id = %s::uuid",
                (str(user_id),),
            )
            row = cur.fetchone()
            return bool(row and row.get("disabled_at"))
    except Exception:
        return False


def csrf_token() -> str:
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_hex(16)
        session["_csrf"] = tok
    return tok


def csrf_protect():
    """Reject POSTs without a valid session CSRF token (form or X-CSRF-Token)."""
    if request.method != "POST":
        return
    # Bearer-token ESO/machine API — not session-cookie CSRF surface
    if request.path.startswith("/eso/"):
        return
    # Unit tests skip unless CSRF_TESTING is set
    if current_app.config.get("TESTING") and not current_app.config.get("CSRF_TESTING"):
        return
    want = session.get("_csrf")
    got = request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
    if not want or got != want:
        abort(400, description="CSRF token missing or invalid")


def safe_redirect_target(nxt: str | None, fallback: str) -> str:
    """Allow only same-origin relative paths (blocks //evil open redirects)."""
    if not nxt:
        return fallback
    parts = urlsplit(nxt)
    if parts.scheme or parts.netloc or not nxt.startswith("/"):
        return fallback
    return nxt
