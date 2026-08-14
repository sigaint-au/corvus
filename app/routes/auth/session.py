"""Index, team select, and logout routes."""

from __future__ import annotations

from flask import (
    redirect,
    request,
    session,
    url_for,
)
import authz
import nav
import user_sessions


def index():
    """Redirect root URL to teams when logged in, otherwise login.

    Args:
        None (reads Flask session for ``user_id``).

    Returns:
        Redirect Response to teams or login.

    Example:
        GET /
    """
    if session.get("user_id"):
        return redirect(url_for("teams"))
    return redirect(url_for("login"))


@authz.login_required
def select_team():
    """Set the active team in session and redirect safely.

    Args:
        None (reads ``team_id`` and ``next`` from the form; uses session).

    Returns:
        Redirect Response to ``next``, referrer, or projects list.

    Example:
        POST /select-team
    """
    tid = (request.form.get("team_id") or "").strip()
    session["team_id"] = tid or None
    nxt = request.form.get("next") or request.referrer or url_for("projects_list")
    # Leave project URLs that belong to another team (e.g. secrets tab
    # stayed on the old project and looked like a no-op).
    nxt = nav.redirect_after_team_switch(nxt, tid or None)
    return redirect(nxt)


def logout():
    """Sign out the current user via POST and clear the session.

    Args:
        None (reads ``user_id`` and ``sid`` from session).

    Returns:
        Redirect Response to the login page.

    Example:
        POST /logout
    """
    uid = session.get("user_id")
    sid = session.get("sid")
    if uid and sid:
        user_sessions.revoke_session(sid, uid)
    session.clear()
    return redirect(url_for("login"))


def logout_get():
    """Sign out via GET (e.g. cancel 2FA) when a session or pending 2FA exists.

    Args:
        None (reads pending 2FA / user session keys).

    Returns:
        Redirect Response to the login page.

    Example:
        GET /logout
    """
    if session.get("pending_2fa_uid") or session.get("user_id"):
        uid = session.get("user_id")
        sid = session.get("sid")
        if uid and sid:
            user_sessions.revoke_session(sid, uid)
        session.clear()
    return redirect(url_for("login"))
