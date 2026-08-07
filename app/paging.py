"""Simple page/offset helpers for list views."""

from flask import request

DEFAULT_PAGE_SIZE = 25


def page_arg(name: str = "page", default: int = 1) -> int:
    """Read page from query string or form (HTMX POSTs carry state in form)."""
    try:
        p = int(request.args.get(name) or request.form.get(name) or default)
    except (TypeError, ValueError):
        p = default
    return max(1, p)


def list_state_q() -> str:
    """Search/filter string from args or form."""
    return (request.args.get("q") or request.form.get("q") or "").strip()


def page_window(total: int, page: int, per_page: int = DEFAULT_PAGE_SIZE) -> dict:
    """Return offset/limit and display metadata for a list page."""
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
