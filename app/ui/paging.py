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
    visible = {1, pages, page}
    visible.update(range(max(1, page - 2), min(pages, page + 2) + 1))
    return {
        "page": page,
        "per_page": per_page,
        "page_numbers": sorted(visible),
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


def paged_rows(cur, count_sql: str, rows_sql: str, params, *, endpoint: str, q=None):
    """Run the standard count→page→`LIMIT/OFFSET` idiom for a list view.

    Caller supplies the count and rows SQL (both use the same ``params``); this
    helper runs the count, computes the `paging window`, attaches ``endpoint``/``q``
    and fetches the page of rows.

    Args:
        cur: Open DB cursor (user RLS context).
        count_sql: ``SELECT count(*) AS n …`` for the unfiltered list/filter.
        rows_sql: ``SELECT …`` with ``LIMIT %s OFFSET %s`` appended.
        params: Tuple of parameters for both statements (limit/offset appended).
        endpoint: Flask endpoint for the pager links.
        q: Optional search string preserved across pages.

    Returns:
        Tuple ``(rows, pager)`` where pager is a `page_window` dict updated with
        ``endpoint`` and ``q``.

    Example:
        >>> rows, pager = paged_rows(
        ...     cur,
        ...     "SELECT count(*) AS n FROM api.projects p WHERE p.team_id = %s",
        ...     "SELECT id, name FROM api.projects p WHERE p.team_id = %s LIMIT %s OFFSET %s",
        ...     (team_id,),
        ...     endpoint="projects_list",
        ... )
    """
    cur.execute(count_sql, params)
    total = int((cur.fetchone() or {}).get("n") or 0)
    pager = page_window(total, page_arg())
    pager.update(endpoint=endpoint, q=q or None)
    cur.execute(rows_sql, (*params, pager["limit"], pager["offset"]))
    return (cur.fetchall() or []), pager
