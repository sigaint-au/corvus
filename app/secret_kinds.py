"""Secret kind detection, parsing, and display helpers."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone

_SOON_DAYS = 14
_KEY_LINE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$"
)
_PEM_BLOCK = re.compile(
    r"(-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----)",
    re.DOTALL,
)
_DB_URL = re.compile(
    r"^(?P<scheme>postgresql|postgres|mysql|mongodb|redis|amqp|http|https)://",
    re.I,
)
STRUCTURED_VIEW_KINDS = frozenset({"kv", "certificate", "ssh", "database"})
VALID_KINDS = frozenset({"plain", "database", "certificate", "ssh", "kv"})


def env_line_match(line: str, *, allow_dots: bool = False):
    """Match KEY=value; allow_dots enables KV key charset.

    Args:
        line: Single line that may contain a KEY=value assignment.
        allow_dots: If True, allow dots and hyphens in the key (KV mode);
            if False, keys must match [A-Za-z_][A-Za-z0-9_]*.

    Returns:
        A re.Match for the key and value groups, or None if the line is
        not a valid env-style assignment under the chosen key rules.

    Example:
        >>> m = env_line_match("FOO=bar")
        >>> m.group(1), m.group(2)
        ('FOO', 'bar')
    """
    m = _KEY_LINE.match(line)
    if not m:
        return None
    if not allow_dots and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", m.group(1)):
        return None
    return m


def detect_secret_kind(value: str, note: str = "") -> str:
    """Infer kind from value content (creation-time auto-suggest / one-shot backfill).

    ``note`` is ignored for inference; kept optional for call-site compatibility.

    Args:
        value: Secret plaintext to inspect for certificates, keys, URLs, or KV.
        note: Unused; retained so existing callers can pass note without change.

    Returns:
        One of "certificate", "ssh", "database", "kv", or "plain".

    Example:
        >>> detect_secret_kind("postgresql://u:p@localhost/db")
        'database'
    """
    del note  # not used — kind is stored explicitly
    v = value or ""
    if "BEGIN CERTIFICATE" in v:
        return "certificate"
    if re.search(
        r"BEGIN (?:OPENSSH |RSA |EC |DSA |ED25519 )?PRIVATE KEY",
        v,
    ):
        return "ssh"
    stripped = v.strip()
    if stripped and _DB_URL.match(stripped) and "\n" not in stripped:
        return "database"
    lines = [
        ln.strip()
        for ln in v.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if len(lines) >= 2 and sum(1 for ln in lines if env_line_match(ln, allow_dots=True)) >= 2:
        return "kv"
    if len(lines) == 1 and env_line_match(lines[0], allow_dots=True) and "\n" in v:
        return "kv"
    return "plain"


def normalize_kind(kind: str | None, default: str = "plain") -> str:
    """Normalize a secret kind string to a known VALID_KINDS value.

    Args:
        kind: Raw kind from form, DB, or API (may be None or unknown).
        default: Fallback kind when kind is missing or invalid.

    Returns:
        Lowercased kind if it is in VALID_KINDS; otherwise default.

    Example:
        >>> normalize_kind("SSH")
        'ssh'
        >>> normalize_kind("unknown")
        'plain'
    """
    k = (kind or default).strip().lower()
    return k if k in VALID_KINDS else default


def parse_kv_lines(value: str) -> list[tuple[str, str]]:
    """Parse KEY=value lines into pairs (keeps empty values).

    Args:
        value: Multiline text of KEY=value lines (comments and blanks skipped).

    Returns:
        List of (key, value) tuples; non-matching lines with "=" still split
        once on the first equals.

    Example:
        >>> parse_kv_lines("A=1\\n# c\\nB=")
        [('A', '1'), ('B', '')]
    """
    pairs: list[tuple[str, str]] = []
    for line in (value or "").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        m = env_line_match(raw, allow_dots=True)
        if m:
            pairs.append((m.group(1), m.group(2)))
        elif "=" in raw:
            k, _, rest = raw.partition("=")
            pairs.append((k.strip(), rest))
    return pairs


def parse_pem_blocks(value: str) -> list[dict]:
    """Split PEM material into labeled blocks for display.

    Args:
        value: Text that may contain one or more PEM BEGIN/END blocks.

    Returns:
        List of dicts with keys label, kind (certificate|private_key|pem|text),
        and text. If no PEM found but value is non-empty, a single text block.

    Example:
        >>> blocks = parse_pem_blocks("-----BEGIN CERTIFICATE-----\\nX\\n-----END CERTIFICATE-----")
        >>> blocks[0]["kind"]
        'certificate'
    """
    blocks = []
    for m in _PEM_BLOCK.finditer(value or ""):
        block = m.group(1).strip()
        header = block.splitlines()[0] if block else ""
        label = header.replace("-----BEGIN ", "").replace("-----", "").strip().title()
        if "CERTIFICATE" in header.upper():
            kind = "certificate"
        elif "PRIVATE KEY" in header.upper() or "OPENSSH" in header.upper():
            kind = "private_key"
        else:
            kind = "pem"
        blocks.append({"label": label or "PEM", "kind": kind, "text": block})
    if not blocks and (value or "").strip():
        blocks.append(
            {"label": "Value", "kind": "text", "text": (value or "").strip()}
        )
    return blocks


def parse_database_url(value: str) -> dict:
    """Break a DB URL into display fields (password kept separate).

    Args:
        value: Connection URL string (e.g. postgresql://user:pass@host/db).

    Returns:
        Dict with raw, scheme, user, password, host, port, database, and query.
        On parse failure, returns {"raw": raw} only.

    Example:
        >>> d = parse_database_url("postgresql://u:p@localhost:5432/app")
        >>> d["host"], d["database"]
        ('localhost', 'app')
    """
    from urllib.parse import unquote, urlparse

    raw = (value or "").strip()
    try:
        u = urlparse(raw)
    except Exception:
        return {"raw": raw}
    return {
        "raw": raw,
        "scheme": u.scheme or "",
        "user": unquote(u.username) if u.username else "",
        "password": unquote(u.password) if u.password else "",
        "host": u.hostname or "",
        "port": str(u.port) if u.port else "",
        "database": (u.path or "").lstrip("/"),
        "query": u.query or "",
    }


def split_cert_and_key(value: str) -> tuple[str, str]:
    """Pull certificate and private key PEM blocks out of a combined value.

    Args:
        value: Combined PEM text that may include cert and private key blocks.

    Returns:
        Tuple (cert_pem, key_pem). If neither PEM kind is found but value is
        non-empty, the whole stripped value is returned as cert and key is "".

    Example:
        >>> cert, key = split_cert_and_key("-----BEGIN CERTIFICATE-----\\nx\\n-----END CERTIFICATE-----")
        >>> bool(cert), key
        (True, '')
    """
    cert = ""
    key = ""
    for block in parse_pem_blocks(value):
        if block["kind"] == "certificate" and not cert:
            cert = block["text"]
        elif block["kind"] == "private_key" and not key:
            key = block["text"]
    if not cert and not key and (value or "").strip():
        cert = (value or "").strip()
    return cert, key


def as_utc(dt):
    """Normalize a datetime to timezone-aware UTC.

    Args:
        dt: A datetime instance, or None.

    Returns:
        None if dt is None; naive datetimes get UTC tzinfo attached;
        aware datetimes are returned unchanged.

    Example:
        >>> as_utc(None) is None
        True
    """
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def expires_status(expires_at, soon_days=_SOON_DAYS):
    """Return 'overdue', 'soon', or None for a single expiry timestamp.

    Args:
        expires_at: Expiry datetime (naive treated as UTC) or None for no expiry.
        soon_days: Days before expiry that count as "soon" (default 14).

    Returns:
        "overdue" if past now, "soon" if within soon_days, else None
        (including when expires_at is None).

    Example:
        >>> expires_status(None) is None
        True
    """
    due = as_utc(expires_at)
    if due is None:
        return None
    now = datetime.now(timezone.utc)
    if due <= now:
        return "overdue"
    if due <= now + timedelta(days=soon_days):
        return "soon"
    return None


def secret_due_status(row, soon_days=_SOON_DAYS):
    """Return 'overdue', 'soon', or None from expires_at.

    Args:
        row: Mapping with optional "expires_at" key (e.g. a secret row).
        soon_days: Days-before-expiry window for "soon" (default 14).

    Returns:
        Same as expires_status for row["expires_at"].

    Example:
        >>> secret_due_status({"expires_at": None}) is None
        True
    """
    return expires_status(row.get("expires_at"), soon_days=soon_days)


def annotate_token_expiry(rows):
    """Add a due status field to each machine-token (or similar) row.

    Args:
        rows: Iterable of mutable mappings with optional expires_at.

    Returns:
        The same list of rows, each with a "due" key set via expires_status.

    Example:
        >>> annotate_token_expiry([{"expires_at": None}])[0]["due"] is None
        True
    """
    for r in rows:
        r["due"] = expires_status(r.get("expires_at"))
    return rows


def parse_secret_pairs(text: str) -> list[tuple[str, str]]:
    """Parse .env, JSON object/list, or CSV (key,value) into (key, value) pairs.

    Args:
        text: Bulk import body as env lines, JSON object/array, or CSV with
            key/value headers.

    Returns:
        List of (key, value) pairs. Values may be str or, for encrypted
        import shapes, a dict with _enc/note. Empty input yields [].

    Raises:
        ValueError: If JSON is present but not an object or key/value array.
        json.JSONDecodeError: If text starts with { or [ but is invalid JSON.

    Example:
        >>> parse_secret_pairs("FOO=bar")
        [('FOO', 'bar')]
    """
    text = (text or "").strip()
    if not text:
        return []
    if text[0] in "{[":
        data = json.loads(text)
        if isinstance(data, dict):
            out = []
            for k, v in data.items():
                if isinstance(v, dict) and "value" in v:
                    out.append((str(k), str(v["value"])))
                elif isinstance(v, dict) and "value_enc" in v:
                    out.append((str(k), {"_enc": v["value_enc"], "note": v.get("note", "")}))
                else:
                    out.append((str(k), "" if v is None else str(v)))
            return out
        if isinstance(data, list):
            out = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                k = item.get("key") or item.get("name")
                if not k:
                    continue
                if "value_enc" in item and "value" not in item:
                    out.append((str(k), {"_enc": item["value_enc"], "note": item.get("note", "")}))
                else:
                    out.append((str(k), "" if item.get("value") is None else str(item.get("value"))))
            return out
        raise ValueError("JSON must be object or array of {key,value}")
    first = text.splitlines()[0].lower()
    if "key" in first and "value" in first and ("," in first or "\t" in first):
        delim = "\t" if "\t" in first and first.count("\t") >= first.count(",") else ","
        reader = csv.DictReader(io.StringIO(text), delimiter=delim)
        out = []
        for row in reader:
            k = (row.get("key") or row.get("KEY") or "").strip()
            if k:
                out.append((k, row.get("value") or row.get("VALUE") or ""))
        return out
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = env_line_match(line, allow_dots=False)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        out.append((k, v))
    return out
