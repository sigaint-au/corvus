"""Personal access token (PAT) routes."""

from __future__ import annotations

import logging
from flask import (
    flash,
    redirect,
    request,
    session,
    url_for,
)
import authz
import pats
log = logging.getLogger(__name__)


@authz.login_required
def create_personal_token():
    """Create a personal access token for the current user.

    Args:
        None (reads form ``name`` and ``expires_days``; uses session user).

    Returns:
        Redirect to profile security tab (raw token stored in session once).

    Example:
        POST /profile/tokens
    """
    name = (request.form.get("name") or "").strip()
    days_raw = (request.form.get("expires_days") or "").strip()
    expires_days = None
    if days_raw:
        try:
            expires_days = int(days_raw)
        except ValueError:
            flash("Expires days must be a positive integer", "error")
            return redirect(url_for("profile", tab="security"))
    try:
        raw = pats.create(session["user_id"], name, expires_days=expires_days)
        session["new_pat"] = raw
        flash("Personal access token created — copy it now; it is shown once", "ok")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        log.exception("create PAT failed")
        flash(str(e), "error")
    return redirect(url_for("profile", tab="security"))


@authz.login_required
def delete_personal_token(token_id):
    """Revoke a personal access token owned by the current user.

    Args:
        token_id: UUID of the PAT to revoke (path parameter).

    Returns:
        Redirect to profile security tab with success or error flash.

    Example:
        POST /profile/tokens/<uuid>/delete
    """
    if pats.revoke(session["user_id"], str(token_id)):
        flash("Token revoked", "ok")
    else:
        flash("Token not found", "error")
    return redirect(url_for("profile", tab="security"))
