"""Shared datetime helpers (avoid duplicated iso/UTC logic across modules)."""

from __future__ import annotations

from datetime import datetime, timezone


def as_utc(dt: datetime | None) -> datetime | None:
    """Normalize a datetime to timezone-aware UTC.

    Naive datetimes get UTC attached; aware datetimes are returned unchanged.
    ``None`` passes through.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def iso_utc(dt: datetime | None) -> str | None:
    """Format a datetime as UTC ISO-8601 (None-safe)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def coerce_utc(dt) -> datetime | None:
    """Coerce a datetime or ISO-8601 string (Z/offset allowed) to aware UTC.

    Returns None for missing/unparseable input.
    """
    if dt is None:
        return None
    if isinstance(dt, str):
        s = dt.strip()
        if not s:
            return None
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
