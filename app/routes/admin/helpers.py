"""Admin export response helpers (CSV/JSON)."""

from __future__ import annotations

import csv
import io
import json
from datetime import (
    datetime,
    timezone,
)
from flask import Response


def _csv_response(filename: str, fieldnames: list[str], rows: list[dict]) -> Response:
    """Build a downloadable CSV response from row dicts.

    Args:
        filename: Suggested download filename (Content-Disposition).
        fieldnames: Ordered CSV column names; only these keys are written.
        rows: Sequence of dicts to export; datetimes and bools are normalized.

    Returns:
        Flask ``Response`` with ``text/csv`` body and attachment headers.

    Example:
        >>> return _csv_response("access-review.csv", fields, rows)
    """
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        out = {}
        for k in fieldnames:
            v = r.get(k)
            if isinstance(v, datetime):
                v = v.astimezone(timezone.utc).isoformat() if v.tzinfo else v.isoformat()
            elif isinstance(v, bool):
                v = "true" if v else "false"
            out[k] = "" if v is None else v
        w.writerow(out)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _json_response(filename: str, payload) -> Response:
    """Build a downloadable JSON response from an arbitrary payload.

    Args:
        filename: Suggested download filename (Content-Disposition).
        payload: JSON-serializable object (uses ``default=str`` for extras).

    Returns:
        Flask ``Response`` with ``application/json`` body and attachment headers.

    Example:
        >>> return _json_response("audit-export.json", {"rows": rows})
    """
    body = json.dumps(payload, indent=2, default=str)
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
