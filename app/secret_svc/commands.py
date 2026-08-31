"""Surface-agnostic command layer for secret lifecycle operations.

Each command takes an **already-open cursor** (the route owns the connection
lifecycle), raises a ``werkzeug`` HTTP exception (``Forbidden``/``NotFound``)
on expected business failures, and returns plain values on success. The three
access surfaces — UI (HTML/redirect), ESO API (JSON), management API (JSON) —
become thin adapters that format the result.

This eliminates the triple duplication of the resolve → authorize → mutate →
audit pipeline. A feature like clearance enforcement needs to be added in
exactly one place (the command) to cover all three surfaces.

Commands preserve the exact ``cur.execute`` / ``cur.fetchone`` call sequence
of the original inline route code, so the existing mock-DB tests continue to
pass unchanged.
"""

from __future__ import annotations

import logging

from werkzeug.exceptions import Forbidden, NotFound

import audit
import crypto
from lib.folders import split_key
from secret_svc.folder_ops import ensure_path
from secret_svc.secret_ops import _upsert_secret

log = logging.getLogger(__name__)


def upsert_secret_command(
    cur,
    *,
    project_id,
    key: str,
    value: str,
    note: str = "",
    expires_at=None,
    kind: str = "plain",
    requires_approval=None,
    set_requires_approval: bool = False,
    access_mode: str = "inherit",
    set_access_mode: bool = False,
    audit_action: str | None = None,
    actor_email: str | None = None,
) -> tuple[str, bool]:
    """Create or update a secret, then write the audit row.

    Mirrors the inline logic previously in ``routes/secrets/crud.py`` and the
    PAT path of ``routes/eso/helpers._upsert_body``. The caller opens the
    ``as_user`` / ``connect`` cursor and is responsible for commit/rollback.

    Args:
        cur: Open DB cursor under the caller's RLS context.
        project_id: Project UUID.
        key: Secret key name.
        value: Plaintext value (encrypted via ``_upsert_secret``).
        note: Optional note.
        expires_at: Optional expiry datetime or None.
        kind: Secret kind (normalized inside ``_upsert_secret``).
        requires_approval: Per-secret override (None = inherit).
        set_requires_approval: Write the override column when True.
        access_mode: Per-secret access mode.
        set_access_mode: Write the access_mode column when True.
        audit_action: Override the audit action (default ``created``/``updated``).
            Machine/CLI surfaces pass ``"machine_upsert"``.
        actor_email: Override the audit actor email (default: session email).
            Machine/CLI surfaces pass the machine label or PAT user email.

    Returns:
        Tuple ``(secret_id, was_new)``.

    Raises:
        Forbidden: when the upsert was blocked by RLS (``_upsert_secret``
            returned a null id).
    """
    folder_path, _ = split_key(key)
    folder_id = ensure_path(cur, project_id, folder_path) if folder_path else None
    sid, was_new = _upsert_secret(
        cur,
        project_id,
        key,
        value,
        note=note,
        expires_at=expires_at,
        kind=kind,
        requires_approval=requires_approval,
        set_requires_approval=set_requires_approval,
        access_mode=access_mode,
        set_access_mode=set_access_mode,
        folder_id=folder_id,
    )
    if not sid:
        raise Forbidden("You don't have permission to do that")
    audit.log_secret(
        cur,
        project_id=project_id,
        secret_id=sid,
        secret_key=key,
        action=audit_action or ("created" if was_new else "updated"),
        actor_email=actor_email,
    )
    return str(sid), was_new


def delete_secret_command(cur, *, project_id, secret_id, actor_email: str | None = None) -> str:
    """Soft-delete a secret (move to trash) and audit the deletion.

    Args:
        cur: Open DB cursor under the caller's RLS context.
        project_id: Project UUID.
        secret_id: Secret UUID.
        actor_email: Override the audit actor email (default: session email).
            Machine/CLI surfaces pass the machine label or PAT user email.

    Returns:
        The deleted secret's UUID.

    Raises:
        NotFound: when the secret is not visible.
        Forbidden: when the UPDATE was blocked by RLS (read-only role).
    """
    cur.execute(
        """
        SELECT id, key FROM api.secrets
        WHERE id = %s AND project_id = %s AND deleted_at IS NULL
        """,
        (str(secret_id), str(project_id)),
    )
    row = cur.fetchone()
    if not row:
        raise NotFound("Secret not found")
    cur.execute(
        """
        UPDATE api.secrets SET deleted_at = now()
        WHERE id = %s AND project_id = %s AND deleted_at IS NULL
        """,
        (str(secret_id), str(project_id)),
    )
    if cur.rowcount == 0:
        # SELECT allowed (read) but UPDATE blocked (write) — e.g. read-only role
        raise Forbidden("You don't have permission to do that")
    audit.log_secret(
        cur,
        project_id=project_id,
        secret_id=row["id"],
        secret_key=row["key"],
        action="deleted",
        actor_email=actor_email,
    )
    return str(row["id"])


def update_secret_value_command(
    cur,
    *,
    project_id,
    secret_id,
    value: str,
    expires_at=None,
    set_expires: bool = False,
) -> str:
    """Replace a secret's value in place (archives the prior value via trigger).

    Args:
        cur: Open DB cursor under the caller's RLS context.
        project_id: Project UUID.
        secret_id: Secret UUID.
        value: New plaintext value.
        expires_at: Optional expiry datetime (only written when set_expires).
        set_expires: When True, write ``expires_at``; otherwise leave it.

    Returns:
        The updated secret's UUID.

    Raises:
        Forbidden: when the caller cannot write the project or the UPDATE
            affected zero rows.
        NotFound: when the secret is gone.
    """
    cur.execute("SELECT api.can_write_project(%s) AS w", (str(project_id),))
    if not cur.fetchone()["w"]:
        raise Forbidden("You don't have permission to do that")
    cur.execute(
        """
        SELECT id, key FROM api.secrets
        WHERE id = %s AND project_id = %s AND deleted_at IS NULL
        """,
        (str(secret_id), str(project_id)),
    )
    row = cur.fetchone()
    if not row:
        raise NotFound("Not found")
    enc, provider = crypto.encrypt_for_project(project_id, value)
    if set_expires:
        cur.execute(
            """
            UPDATE api.secrets SET value_enc = %s, expires_at = %s, crypto_provider = %s
            WHERE id = %s AND project_id = %s AND deleted_at IS NULL
            """,
            (enc, expires_at, provider, str(secret_id), str(project_id)),
        )
    else:
        cur.execute(
            """
            UPDATE api.secrets SET value_enc = %s, crypto_provider = %s
            WHERE id = %s AND project_id = %s AND deleted_at IS NULL
            """,
            (enc, provider, str(secret_id), str(project_id)),
        )
    if cur.rowcount == 0:
        raise Forbidden("You don't have permission to do that")
    audit.log_secret(
        cur,
        project_id=project_id,
        secret_id=row["id"],
        secret_key=row["key"],
        action="updated",
    )
    return str(row["id"])
