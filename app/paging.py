"""Simple page/offset helpers for list views."""

from flask import request

DEFAULT_PAGE_SIZE = 25


def page_arg(name: str = "page", default: int = 1) -> int:
    """Read a 1-based page number from the query string or form body.

    HTMX POSTs often carry list state in the form, so both sources are checked.
    Invalid or missing values fall back to ``default``; result is at least 1.

    Args:
        name: Query/form field name. Defaults to ``"page"``.
        default: Value used when the field is missing or not an integer.
            Defaults to ``1``.

    Returns:
        Integer page number >= 1.

    Example:
        >>> # With request ?page=3
        >>> page_arg()
        3
        >>> # Missing or garbage → default
        >>> page_arg(default=1)
        1
    """
    try:
        p = int(request.args.get(name) or request.form.get(name) or default)
    except (TypeError, ValueError):
        p = default
    return max(1, p)


def list_state_q() -> str:
    """Return the search/filter string ``q`` from query args or form.

    Args:
        None (reads from the current Flask request).

    Returns:
        Stripped search string, or ``""`` if absent.

    Example:
        >>> # With request ?q=prod
        >>> list_state_q()
        'prod'
    """
    return (request.args.get("q") or request.form.get("q") or "").strip()


def page_window(total: int, page: int, per_page: int = DEFAULT_PAGE_SIZE) -> dict:
    """Compute offset/limit and display metadata for a paginated list.

    Clamps ``page`` into the valid range given ``total`` and ``per_page``.

    Args:
        total: Total number of items across all pages (>= 0).
        page: Requested 1-based page number.
        per_page: Page size. Defaults to ``DEFAULT_PAGE_SIZE`` (25). Minimum 1.

    Returns:
        Dict with keys: ``page``, ``per_page``, ``total``, ``pages``,
        ``offset``, ``limit``, ``start``, ``end``, ``has_prev``, ``has_next``,
        ``prev_page``, ``next_page``.

    Example:
        >>> page_window(100, page=2, per_page=25)
        {'page': 2, 'per_page': 25, 'total': 100, 'pages': 4,
         'offset': 25, 'limit': 25, 'start': 26, 'end': 50,
         'has_prev': True, 'has_next': True,
         'prev_page': 1, 'next_page': 3}
    """
    per_page = max(1, int(per_page))
    total = max(0, int(total or 0))
    pages = max(1, (total + per_page - 1) // per_page) if total else 1
    page = min(max(1, int(page or 1)), pages)
    offset = (page - 1) * per_page
    start = 0 if total == 0 else offset + 1
    end = min(offset + per_page, total)
    return {
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages,
        "offset": offset,
        "limit": per_page,
        "start": start,
        "end": end,
        "has_prev": page > 1,
        "has_next": page < pages,
        "prev_page": page - 1 if page > 1 else None,
        "next_page": page + 1 if page < pages else None,
    }
