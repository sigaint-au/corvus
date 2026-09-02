"""Audit row writers (secret and org events)."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from flask import session

from .constants import ACTIONS

# One JSON line per audit event on stdout, so container log shippers
# (rsyslog, Splunk HEC/forwarder, journald) can relay to a SIEM.
audit_console = logging.getLogger("corvus.audit")


def _client_meta() -> tuple[str, str]:
    """Return (user_agent, ip) for the current request, or ("", "") outside one.

    Lazy import keeps auth -> audit imports cycle-free; background callers
    without a request context get blanks rather than a RuntimeError.
    """
    try:
        from auth.user_sessions import client_meta
    except ImportError:
        return "", ""
    try:
        return client_meta()
    except RuntimeError:
        return "", ""


def _emit_console(kind: str, **fields) -> None:
    """Mirror an audit row as a single-line JSON record on stdout."""
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": kind,
        **{k: v for k, v in fields.items() if v},
    }
    try:
        audit_console.info(json.dumps(payload, separators=(",", ":")))
    except Exception:
        logging.getLogger(__name__).exception("audit console log failed")


def log_secret(
    cur,
    *,
    project_id,
    action: str,
    secret_key: str = "",
    secret_id=None,
    actor_email: str | None = None,
):
    """Insert a secret audit row via private.audit_secret.

    Actor user_id is taken from JWT claims inside the DB function (as_user
    connections). Optional actor_email is only used when there is no JWT user
    (e.g. machine paths).

    Args:
        cur: Database cursor used to execute the audit insert.
        project_id: UUID of the project the secret belongs to.
        action: Audit action name; must be one of ACTIONS.
        secret_key: Human-readable secret key/name (default empty).
        secret_id: Optional UUID of the secret row.
        actor_email: Optional actor email override; defaults to session email.

    Returns:
        None. The audit row is written via a side-effect SQL call.

    Example:
        >>> log_secret(cur, project_id=pid, action="created", secret_key="API_KEY")
    """
    if action not in ACTIONS:
        raise ValueError(f"invalid audit action: {action}")
    # p_user_id is ignored by private.audit_secret; pass NULL for clarity.
    email = actor_email if actor_email is not None else (session.get("email") or "")
    user_agent, ip = _client_meta()
    cur.execute(
        """
        SELECT private.audit_secret(
          %s::uuid, %s::uuid, %s, %s, NULL::uuid, %s, %s, %s
        )
        """,
        (
            str(project_id),
            str(secret_id) if secret_id else None,
            secret_key or "",
            action,
            email or "",
            ip or "",
            user_agent or "",
        ),
    )
    _emit_console(
        "secret_audit",
        action=action,
        actor=email,
        project_id=str(project_id) if project_id else None,
        secret_id=str(secret_id) if secret_id else None,
        secret_key=secret_key or None,
        ip=ip or None,
        user_agent=user_agent or None,
    )


def log_org(
    cur,
    *,
    action: str,
    detail: str = "",
    team_id=None,
    project_id=None,
    actor_email: str | None = None,
):
    """Insert a membership/settings audit row via private.audit_org.

    Args:
        cur: Database cursor used to execute the audit insert.
        action: Org audit action string (e.g. ORG_MEMBER_ADD); required.
        detail: Free-text detail about the change (default empty).
        team_id: Optional team UUID related to the event.
        project_id: Optional project UUID related to the event.
        actor_email: Optional actor email override; defaults to session email.

    Returns:
        None. The audit row is written via a side-effect SQL call.

    Example:
        >>> log_org(cur, action=ORG_MEMBER_ADD, detail="user@ex.com as member", team_id=tid)
    """
    if not action:
        raise ValueError("org audit action required")
    email = actor_email if actor_email is not None else (session.get("email") or "")
    user_agent, ip = _client_meta()
    cur.execute(
        """
        SELECT private.audit_org(
          %s::uuid, %s::uuid, %s, %s, %s, %s, %s
        )
        """,
        (
            str(team_id) if team_id else None,
            str(project_id) if project_id else None,
            action,
            detail or "",
            email or "",
            ip or "",
            user_agent or "",
        ),
    )
    _emit_console(
        "org_audit",
        action=action,
        actor=email,
        team_id=str(team_id) if team_id else None,
        project_id=str(project_id) if project_id else None,
        detail=detail or None,
        ip=ip or None,
        user_agent=user_agent or None,
    )
