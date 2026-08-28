"""CLI "copy login command" route."""

from __future__ import annotations

import logging

from flask import render_template, request, session

from auth import authz, cli_sessions
from core import settings_svc

log = logging.getLogger(__name__)


@authz.login_required
def cli_login_command():
    """Mint a short-lived CLI session token and render a ready login command.

    Returns a dialog partial containing a ``corvus login`` command with the
    freshly minted ``sso_…`` token (shown once) and a Copy button.

    Args:
        None (uses session ``user_id``).

    Returns:
        Rendered ``partials/cli_login_dialog_body.html``.
    """
    raw = cli_sessions.create(session["user_id"])
    base = settings_svc.public_base_url(request.url_root)
    command = f"corvus login --url {base} --token {raw}"
    return render_template(
        "partials/cli_login_dialog_body.html",
        command=command,
        minutes=cli_sessions.ttl_seconds() // 60,
    )
