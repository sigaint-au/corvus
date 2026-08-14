"""Date parsing and human-readable time formatting for audit display."""

from __future__ import annotations

from datetime import datetime, time, timezone

from lib.datetime_utils import coerce_utc


def _parse_day(s: str, *, end: bool = False):
    """Parse YYYY-MM-DD to a UTC datetime at start or end of day.

    Args:
        s: Date string; first 10 characters are parsed as YYYY-MM-DD.
        end: If True, return 23:59:59.999999 UTC; else 00:00:00 UTC.

    Returns:
        Timezone-aware UTC datetime, or None if s is empty/invalid.

    Example:
        >>> _parse_day("2026-08-08", end=False).hour
        0
        >>> _parse_day("bad") is None
        True
    """
    s = (s or "").strip()
    if not s:
        return None
    try:
        d = datetime.strptime(s[:10], "%Y-%m-%d").date()
    except ValueError:
        return None
    t = time(23, 59, 59, 999999) if end else time(0, 0, 0)
    return datetime.combine(d, t, tzinfo=timezone.utc)


def _as_utc_dt(dt):
    """Coerce a datetime or ISO string to timezone-aware UTC (delegates to lib)."""
    return coerce_utc(dt)


def format_when(dt) -> str:
    """Format a timestamp as a compact absolute UTC display string.

    Args:
        dt: Datetime, ISO string, or None to format.

    Returns:
        String like '2026-08-08 12:00 UTC', '—' for None, or str(dt)
        if unparseable.

    Example:
        >>> format_when(None)
        '—'
    """
    d = _as_utc_dt(dt)
    if d is None:
        return "—" if dt is None else str(dt)
    return d.strftime("%Y-%m-%d %H:%M UTC")


def format_expires(dt, *, prefix: bool = True) -> str:
    """Format an expiry time as a human-friendly relative string.

    Args:
        dt: Expiry datetime or ISO string; empty result if missing/invalid.
        prefix: If True, prefix with 'expires'/'expired'; if False, omit
            the leading word for future dates far out, still include it
            for past relative forms as implemented.

    Returns:
        Human-friendly expiry string such as
        'expires in 3 days (10 Aug 2026)', or empty string if dt is invalid.

    Example:
        >>> format_expires(None)
        ''
    """
    d = _as_utc_dt(dt)
    if d is None:
        return ""
    now = datetime.now(timezone.utc)
    sec = int((d - now).total_seconds())
    abs_when = d.strftime("%d %b %Y")
    if sec < 0:
        past = -sec
        if past < 60:
            rel = "just now"
        elif past < 3600:
            n = max(1, past // 60)
            rel = f"{n} minute{'s' if n != 1 else ''} ago"
        elif past < 86400:
            n = max(1, past // 3600)
            rel = f"{n} hour{'s' if n != 1 else ''} ago"
        elif past < 86400 * 30:
            n = max(1, past // 86400)
            rel = f"{n} day{'s' if n != 1 else ''} ago"
        else:
            return f"expired {abs_when}" if prefix else abs_when
        body = f"{rel} ({abs_when})"
        return f"expired {body}" if prefix else f"expired {body}"
    if sec < 60:
        rel = "in under a minute"
    elif sec < 3600:
        n = max(1, sec // 60)
        rel = f"in {n} minute{'s' if n != 1 else ''}"
    elif sec < 86400:
        n = max(1, sec // 3600)
        rel = f"in {n} hour{'s' if n != 1 else ''}"
    elif sec < 86400 * 30:
        n = max(1, sec // 86400)
        rel = f"in {n} day{'s' if n != 1 else ''}"
    elif sec < 86400 * 365:
        n = max(1, sec // (86400 * 30))
        rel = f"in {n} month{'s' if n != 1 else ''}"
    else:
        return f"expires {abs_when}" if prefix else abs_when
    body = f"{rel} ({abs_when})"
    return f"expires {body}" if prefix else body


def format_time_ago(dt) -> str:
    """Format a timestamp as relative time for Updated columns.

    Args:
        dt: Datetime or ISO string representing a past (or slightly future) time.

    Returns:
        Relative string such as '3 hours ago', 'just now', absolute format
        for future/clock-skew, or '—' for None.

    Example:
        >>> format_time_ago(None)
        '—'
    """
    d = _as_utc_dt(dt)
    if d is None:
        return "—" if dt is None else str(dt)
    now = datetime.now(timezone.utc)
    sec = int((now - d).total_seconds())
    if sec < 0:
        # Clock skew / future stamp — fall back to absolute
        return format_when(d)
    if sec < 45:
        return "just now"
    if sec < 90:
        return "1 minute ago"
    if sec < 3600:
        n = sec // 60
        return f"{n} minutes ago"
    if sec < 5400:
        return "1 hour ago"
    if sec < 86400:
        n = sec // 3600
        return f"{n} hours ago"
    if sec < 86400 * 2:
        return "1 day ago"
    if sec < 86400 * 30:
        n = sec // 86400
        return f"{n} days ago"
    if sec < 86400 * 45:
        return "1 month ago"
    if sec < 86400 * 365:
        n = sec // (86400 * 30)
        return f"{n} months ago"
    if sec < 86400 * 365 * 2:
        return "1 year ago"
    n = sec // (86400 * 365)
    return f"{n} years ago"
