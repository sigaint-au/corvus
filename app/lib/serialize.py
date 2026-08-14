"""Shared row/JSON serialization helpers (jsonify-safe conversion)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from lib.datetime_utils import iso_utc


def json_safe(value):
    """Convert a value to a JSON-serializable form.

    datetime → ISO-8601 (UTC if naive); UUID → str; other values pass through.
    """
    if isinstance(value, datetime):
        return iso_utc(value)
    if isinstance(value, UUID):
        return str(value)
    return value


def row_to_dict(row) -> dict:
    """Convert a DB row mapping to a JSON-safe dict (datetimes/UUIDs stringified)."""
    if not row:
        return {}
    return {k: json_safe(v) for k, v in row.items()}
