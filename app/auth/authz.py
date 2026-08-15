"""Auth decorators, admin checks, CSRF."""
import secrets
from functools import wraps
from urllib.parse import urlsplit

from flask import abort, current_app, flash, redirect, request, session, url_for

from core import db


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
    """Require an authenticated browser session before running a view.

    Redirects users with a pending 2FA challenge to the 2FA page, and
    unauthenticated users to login. Otherwise calls the wrapped view.

    Args:
        f: The Flask view function to protect.

    Returns:
        A decorator wrapper that enforces login before invoking ``f``.

    Example:
        >>> @login_required
        ... def dashboard():
        ...     return "ok"
    """

    @wraps(f)
    def wrapped(*a, **kw):
        """Enforce session login and 2FA state for the protected view.

        Args:
            *a: Positional arguments forwarded to the original view.
            **kw: Keyword arguments forwarded to the original view.

        Returns:
            A redirect to 2FA or login when unauthenticated, otherwise
            the result of the original view function.

        Example:
            Applied automatically when a route is decorated with
            ``@login_required``; Flask invokes this wrapper on each request.
        """
        if session.get("pending_2fa_uid"):
            return redirect(url_for("login_2fa"))
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*a, **kw)

    return wrapped


def validate_registered_session():
    """Ensure the browser session is still registered server-side (not revoked).

    Also gates mid-login 2FA and forced TOTP enrollment. Skipped in unit
    tests (no sid / no DB session rows). May clear the session and redirect
    when the account is disabled, enrollment is required, or the server-side
    session is missing/expired.

    Returns:
        ``None`` when the request may proceed, or a Flask redirect response
        when the user must re-authenticate, complete 2FA, or set up TOTP.

    Example:
        >>> # Register as a before_request handler
        >>> app.before_request(validate_registered_session)
    """
    if current_app.config.get("TESTING"):
        return None

    # Personal access token exchange does not need a browser session
    if request.endpoint == "api_token":
        auth = request.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            raw = auth.split(None, 1)[-1].strip()
            if raw.startswith("pat_"):
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
    from auth import user_sessions

    if not user_sessions.touch_session(sid, uid):
        session.clear()
        flash("Your session was signed out or expired. Please sign in again.", "error")
        return redirect(url_for("login"))
    return None



def global_admin_required(f):
    """Require a logged-in global administrator before running a view.

    Checks the database (not only the session flag) so demotions take effect
    immediately. Redirects non-admins to the projects list.

    Args:
        f: The Flask view function to protect.

    Returns:
        A decorator wrapper that enforces global-admin access before invoking ``f``.

    Example:
        >>> @global_admin_required
        ... def admin_users():
        ...     return "admin only"
    """

    @wraps(f)
    def wrapped(*a, **kw):
        """Enforce global-admin membership for the protected view.

        Args:
            *a: Positional arguments forwarded to the original view.
            **kw: Keyword arguments forwarded to the original view.

        Returns:
            A redirect to login or projects list when unauthorized, otherwise
            the result of the original view function.

        Example:
            Applied automatically when a route is decorated with
            ``@global_admin_required``; Flask invokes this wrapper on each request.
        """
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
    """Report whether the current request was issued by HTMX.

    Returns:
        ``True`` if the ``HX-Request`` header is present and equal to
        ``"true"``, otherwise ``False``.

    Example:
        >>> if htmx():
        ...     return render_template("partial.html")
    """
    return request.headers.get("HX-Request") == "true"


def is_global_admin(user_id: str) -> bool:
    """Check whether a user has the global administrator flag in the database.

    Args:
        user_id: UUID string of the user to look up.

    Returns:
        ``True`` if the user exists and ``is_global_admin`` is set; ``False``
        on missing user, DB errors, or when the flag is unset.

    Example:
        >>> if is_global_admin(session["user_id"]):
        ...     show_admin_menu()
    """
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
    """True when a global admin has disabled this account.

    Args:
        user_id: UUID string of the user to look up. Empty/falsy values
            short-circuit to ``False``.

    Returns:
        ``True`` if the user row has a non-null ``disabled_at``; ``False``
        for missing users, empty ids, or DB errors.

    Example:
        >>> if is_account_disabled(uid):
        ...     session.clear()
    """
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
    """Return the session CSRF token, creating one if missing.

    Stores a 16-byte hex token under ``session["_csrf"]`` on first use.

    Returns:
        The current CSRF token string for embedding in forms or headers.

    Example:
        >>> # In a template context or form helper
        >>> token = csrf_token()
        >>> html = f'<input type="hidden" name="_csrf" value="{token}">'
    """
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_hex(16)
        session["_csrf"] = tok
    return tok


def csrf_protect():
    """Reject mutating requests without a valid session CSRF token.

    No-op for safe methods, ``/eso/`` (Bearer machine/PAT secret API),
    ``/api/token``, and unit tests unless ``CSRF_TESTING`` is enabled.
    Compares ``session["_csrf"]`` to form ``_csrf`` or header ``X-CSRF-Token``.

    Returns:
        ``None`` when the request is allowed. Aborts with HTTP 400 when the
        token is missing or does not match.

    Example:
        >>> # Register as a before_request handler
        >>> app.before_request(csrf_protect)
    """
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    # Bearer-token ESO/machine/PAT secret API — not session-cookie CSRF surface
    if request.path.startswith("/eso/"):
        return
    # PAT exchange / JSON API token minting is GET-only; keep path free for future POSTs
    if request.path.startswith("/api/token"):
        return
    # Unit tests skip unless CSRF_TESTING is set
    if current_app.config.get("TESTING") and not current_app.config.get("CSRF_TESTING"):
        return
    want = session.get("_csrf")
    got = request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
    if not want or got != want:
        abort(400, description="CSRF token missing or invalid")


def safe_redirect_target(nxt: str | None, fallback: str) -> str:
    """Allow only same-origin relative paths (blocks //evil open redirects).

    Args:
        nxt: Candidate redirect target from a query parameter or form field.
            May be ``None`` or empty.
        fallback: URL to use when ``nxt`` is missing or unsafe.

    Returns:
        ``nxt`` when it is a relative path with no scheme or netloc;
        otherwise ``fallback``.

    Example:
        >>> safe_redirect_target("/projects", "/dashboard")
        '/projects'
        >>> safe_redirect_target("//evil.example", "/dashboard")
        '/dashboard'
    """
    if not nxt:
        return fallback
    parts = urlsplit(nxt)
    if parts.scheme or parts.netloc or not nxt.startswith("/"):
        return fallback
    return nxt
