"""Secret kind detection, parsing, and note tags."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone

_SOON_DAYS = 14
# Allow dots in keys for KV; .env import stays stricter via allow_dots=False
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
_STRUCTURED_VIEW_KINDS = frozenset({"kv", "certificate", "ssh", "database"})


def env_line_match(line: str, *, allow_dots: bool = False):
    """Match KEY=value; allow_dots enables KV key charset."""
    m = _KEY_LINE.match(line)
    if not m:
        return None
    if not allow_dots and any(c in m.group(1) for c in ".-"):
        # Strict .env: reject keys with . or - (legacy _ENV_LINE behavior used [A-Za-z0-9_]* only)
        # Actually old _ENV was [A-Za-z_][A-Za-z0-9_]*  and _KV allowed . -
        # Re-check: if allow_dots False, key must match [A-Za-z_][A-Za-z0-9_]*
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", m.group(1)):
            return None
    return m


def detect_secret_kind(value: str, note: str = "") -> str:
    """Infer secret shape from note tag and/or value content."""
    note_l = (note or "").lower()
    for kind in ("certificate", "kv", "ssh", "database", "plain"):
        if f"type:{kind}" in note_l:
            return kind
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


def parse_kv_lines(value: str) -> list[tuple[str, str]]:
    """Parse KEY=value lines into pairs (keeps empty values)."""
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
    """Split PEM material into labeled blocks for display."""
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
    """Break a DB URL into display fields (password kept separate)."""
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


def note_with_kind(note: str, kind_label: str) -> str:
    """Ensure non-plain secrets keep a type: tag for later reveal detection."""
    kind_label = (kind_label or "plain").strip().lower()
    note = note_without_kind(note)
    if kind_label == "plain":
        return note
    tag = f"type:{kind_label}"
    return f"{note} ({tag})".strip() if note else tag


def note_without_kind(note: str) -> str:
    """Strip type: tags so the user-facing note field stays clean."""
    note = (note or "").strip()
    note = re.sub(r"\s*\(\s*type:[a-z]+\s*\)\s*", " ", note, flags=re.I)
    note = re.sub(r"\btype:[a-z]+\b", "", note, flags=re.I)
    return re.sub(r"\s{2,}", " ", note).strip(" -|,")


def split_cert_and_key(value: str) -> tuple[str, str]:
    """Pull certificate and private key PEM blocks out of a combined value."""
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
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def expires_status(expires_at, soon_days=_SOON_DAYS):
    """Return 'overdue', 'soon', or None for a single expiry timestamp."""
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
    """Return 'overdue', 'soon', or None from expires_at."""
    return expires_status(row.get("expires_at"), soon_days=soon_days)


def annotate_token_expiry(rows):
    for r in rows:
        r["due"] = expires_status(r.get("expires_at"))
    return rows


def parse_secret_pairs(text: str) -> list[tuple[str, str]]:
    """Parse .env, JSON object/list, or CSV (key,value) into (key, value) pairs."""
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
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\'\"":
            v = v[1:-1]
        out.append((k, v))
    return out


STRUCTURED_VIEW_KINDS = _STRUCTURED_VIEW_KINDS
