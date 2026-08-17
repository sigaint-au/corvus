"""Centralized read-side SQL for secrets.

Route handlers previously inlined SELECT statements, scattering SQL across
``routes/secrets/view.py``, ``crud.py``, and the API surfaces. This module is
the single owner of secret read queries so that schema changes touch one
place and the SQL is easy to audit.

Each function takes an open cursor (the route owns the connection lifecycle)
and returns the raw row dict (or ``None``). The ``cur.execute`` / ``cur.fetchone``
call sequence is identical to the previous inline code, so mock-DB tests are
unaffected.
"""

from __future__ import annotations

from typing import Any


def get_secret_brief(cur, secret_id, project_id) -> dict[str, Any] | None:
    """Return a lightweight secret row for the reveal path.

    Selects only the columns needed to render the reveal partial. Returns
    ``None`` when the secret is deleted or not visible under RLS.

    Example:
        >>> row = get_secret_brief(cur, sid, pid)
        >>> row is None or "value_enc" not in row  # no ciphertext in brief
        True
    """
    cur.execute(
        """
        SELECT id, key, note, kind, expires_at, crypto_provider
        FROM api.secrets
        WHERE id = %s AND project_id = %s AND deleted_at IS NULL
        """,
        (str(secret_id), str(project_id)),
    )
    return cur.fetchone()


def get_secret_detail(cur, secret_id, project_id) -> dict[str, Any] | None:
    """Return the full secret row with project/team joins for the view page.

    Includes rotation fields, access policy, project name, and team membership
    flag. Returns ``None`` when the secret is deleted or not visible under RLS.

    Example:
        >>> row = get_secret_detail(cur, sid, pid)
        >>> row is None or "project_name" in row
        True
    """
    cur.execute(
        """
        SELECT s.id, s.key, s.note, s.kind, s.expires_at,
               s.rotation_interval_days, s.rotation_owner, s.rotation_next_at, s.rotated_at,
               s.requires_approval, s.access_mode, s.created_at, s.updated_at,
               s.last_accessed_at, s.last_accessed_by, s.crypto_provider,
               p.name AS project_name, p.require_reveal_approval,
               p.team_id, t.name AS team_name,
               api.is_team_member(p.team_id) AS is_team_member
        FROM api.secrets s
        JOIN api.projects p ON p.id = s.project_id
        LEFT JOIN api.teams t ON t.id = p.team_id
        WHERE s.id = %s AND s.project_id = %s AND s.deleted_at IS NULL
        """,
        (str(secret_id), str(project_id)),
    )
    return cur.fetchone()
