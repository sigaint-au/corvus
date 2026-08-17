"""Typed domain models and the command result envelope.

Frozen dataclasses replace raw ``dict`` rows so downstream code accesses typed
attributes (``secret.key``) instead of untyped ``row.get("key")`` lookups.
``from_row`` classmethods normalise the varied DB row shapes into a single
canonical model. ``CommandResult`` is the envelope returned by every command
in ``secret_svc.commands`` — surface adapters (UI/ESO/mgmt) format it into
HTML or JSON without re-implementing business logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class SecretRow:
    """A typed view of an ``api.secrets`` row.

    Not every query returns every column; ``from_row`` tolerates missing keys
    so callers can build a model from any subset of the secret columns.
    """

    id: str
    project_id: str
    key: str
    note: str = ""
    kind: str = "plain"
    crypto_provider: str = "master"
    expires_at: datetime | None = None
    requires_approval: bool | None = None
    access_mode: str = "inherit"
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> SecretRow:
        """Build a ``SecretRow`` from a DB row dict, tolerating missing keys."""
        return cls(
            id=str(row["id"]),
            project_id=str(row.get("project_id") or ""),
            key=row.get("key") or "",
            note=row.get("note") or "",
            kind=row.get("kind") or "plain",
            crypto_provider=row.get("crypto_provider") or "master",
            expires_at=row.get("expires_at"),
            requires_approval=row.get("requires_approval"),
            access_mode=(row.get("access_mode") or "inherit").strip() or "inherit",
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Envelope returned by every command in ``secret_svc.commands``.

    Attributes:
        ok: Whether the operation succeeded.
        status: HTTP status code an adapter should use on failure.
        error: Human-readable error message (empty on success).
        secret_id: UUID of the affected secret when available.
        secret_key: Key name of the affected secret when available.
        was_new: For upserts, True when a new row was created (vs. updated).
        data: Optional payload (e.g. the updated row) for adapters to format.

    Example:
        >>> r = CommandResult(ok=True, secret_id="…", was_new=True)
        >>> if r.ok:
        ...     conn.commit()
    """

    ok: bool
    status: int = 200
    error: str = ""
    secret_id: str | None = None
    secret_key: str = ""
    was_new: bool = False
    data: dict[str, Any] | None = field(default=None, repr=False)
