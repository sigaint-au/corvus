"""Operational jobs: due notifications and directory deprovisioning."""
from __future__ import annotations

import re
from pathlib import Path

import audit
from core import db
from integrations import ldap_auth


AUDIT_ACTOR = "sync-directory"
# Refuse a live run when the roster covers less than this fraction of the
# directory users known to Corvus — a sign of a truncated/failed fetch.
MIN_ROSTER_FRACTION = 0.8
LDAP_PAGE_SIZE = 500
# Active Directory userAccountControl bit: ACCOUNTDISABLE.
LDAP_ACCOUNTDISABLE = 0x2
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _global_admin_emails(cur) -> list[str]:
    cur.execute(
        """
        SELECT email FROM private.users
        WHERE is_global_admin AND disabled_at IS NULL
        ORDER BY email
        """
    )
    return [r["email"] for r in (cur.fetchall() or []) if r.get("email")]


def due_notifications(cur, days: int = 14) -> dict[str, list[str]]:
    """Return recipient -> due-notification lines."""
    out: dict[str, list[str]] = {}
    admins = _global_admin_emails(cur)
    days_s = str(max(1, int(days)))

    cur.execute(
        """
        SELECT p.name AS project_name, s.key, s.expires_at
        FROM api.secrets s
        JOIN api.projects p ON p.id = s.project_id
        WHERE s.deleted_at IS NULL
          AND s.expires_at IS NOT NULL
          AND s.expires_at <= now() + (%s || ' days')::interval
          AND NOT EXISTS (
              SELECT 1 FROM api.secret_meta m
              WHERE m.secret_id = s.id AND m.key IN ('exclude-due-notify', 'exclude_due_notify')
          )
        ORDER BY s.expires_at, p.name, s.key
        LIMIT 500
        """,
        (days_s,),
    )
    for row in cur.fetchall() or []:
        line = f"Secret {row['project_name']}/{row['key']} expires {row['expires_at']}"
        for email in admins:
            out.setdefault(email, []).append(line)

    cur.execute(
        """
        SELECT p.name AS project_name, mt.name, mt.token_prefix, mt.expires_at
        FROM api.machine_tokens mt
        JOIN api.projects p ON p.id = mt.project_id
        WHERE mt.expires_at IS NOT NULL
          AND mt.expires_at <= now() + (%s || ' days')::interval
        ORDER BY mt.expires_at, p.name, mt.name
        LIMIT 500
        """,
        (days_s,),
    )
    for row in cur.fetchall() or []:
        line = (
            f"Machine token {row['project_name']}/{row['name']} "
            f"({row['token_prefix']}) expires {row['expires_at']}"
        )
        for email in admins:
            out.setdefault(email, []).append(line)

    cur.execute(
        """
        SELECT u.email, t.name, t.token_prefix, t.expires_at
        FROM private.personal_access_tokens t
        JOIN private.users u ON u.id = t.user_id
        WHERE u.disabled_at IS NULL
          AND t.expires_at IS NOT NULL
          AND t.expires_at <= now() + (%s || ' days')::interval
        ORDER BY t.expires_at, u.email, t.name
        LIMIT 500
        """,
        (days_s,),
    )
    for row in cur.fetchall() or []:
        out.setdefault(row["email"], []).append(
            f"Personal access token {row['name']} ({row['token_prefix']}) expires {row['expires_at']}"
        )

    cur.execute(
        """
        SELECT p.name AS project_name, s.key, u.email AS requester, r.created_at
        FROM api.secret_access_requests r
        JOIN api.projects p ON p.id = r.project_id
        JOIN api.secrets s ON s.id = r.secret_id
        JOIN private.users u ON u.id = r.user_id
        WHERE r.status = 'pending'
        ORDER BY r.created_at, p.name, s.key
        LIMIT 500
        """
    )
    for row in cur.fetchall() or []:
        line = (
            f"Pending reveal approval {row['project_name']}/{row['key']} "
            f"requested by {row['requester']} at {row['created_at']}"
        )
        for email in admins:
            out.setdefault(email, []).append(line)
    return out


def send_due_notifications(days: int = 14, *, dry_run: bool = False) -> dict[str, int]:
    """Send due notifications; return counts."""
    from integrations import mailer

    sent = failed = 0
    with db.connect_admin() as conn, conn.cursor() as cur:
        notifications = due_notifications(cur, days)
    if dry_run:
        return {"recipients": len(notifications), "sent": 0, "failed": 0}
    for email, lines in notifications.items():
        if not lines:
            continue
        subject, body, html = mailer.render_email_message("due_notifications", lines=lines)
        ok, _err = mailer.send_email(email, subject, body, body_html=html)
        if ok:
            sent += 1
        else:
            failed += 1
    return {"recipients": len(notifications), "sent": sent, "failed": failed}


def _read_email_file(path: str) -> set[str]:
    """Read a roster file of one email per line; `#` starts a comment.

    Malformed lines raise instead of silently disabling their owners —
    a mangled file must fail closed, never half-match.
    """
    emails: set[str] = set()
    bad: list[str] = []
    for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _EMAIL_RE.match(stripped):
            emails.add(stripped.lower())
        else:
            bad.append(f"line {lineno}: {stripped[:60]}")
    if bad:
        shown = ", ".join(bad[:5])
        extra = f" (+{len(bad) - 5} more)" if len(bad) > 5 else ""
        raise ValueError(f"roster file has {len(bad)} invalid email line(s): {shown}{extra}")
    return emails


def _ldap_entry_locked(entry) -> bool:
    """True when a directory entry is locked/disabled (not a leaver delete).

    Covers Active Directory (`userAccountControl` ACCOUNTDISABLE bit),
    389 DS / FreeIPA (`nsAccountLock`), and ppolicy-style
    (`pwdAccountLockedTime`) servers. Unknown schemas fail open (not locked)
    so exotic directories keep the old delete-only behavior.
    """
    uac = ldap_auth.ldap_attr(entry, "userAccountControl", "")
    if uac.strip():
        try:
            if int(uac.strip()) & LDAP_ACCOUNTDISABLE:
                return True
        except ValueError:
            pass
    if ldap_auth.truthy(ldap_auth.ldap_attr(entry, "nsAccountLock", "")):
        return True
    if ldap_auth.ldap_attr(entry, "pwdAccountLockedTime", "").strip():
        return True
    return False


def _ldap_search_all(conn, base: str, search_filter: str, attributes: list[str]) -> list:
    """Return every matching entry, following paged-result cookies.

    A single unpaged search silently truncates at the server size limit
    (AD defaults to 1000), which would read as mass departures. If the
    server rejects paging, fall back to one plain search.
    """
    from ldap3 import SUBTREE

    try:
        entries: list = []
        cookie = None
        first = True
        while first or cookie:
            page_kwargs = {"paged_size": LDAP_PAGE_SIZE}
            if cookie:
                page_kwargs["paged_cookie"] = cookie
            conn.search(base, search_filter, search_scope=SUBTREE, attributes=attributes, **page_kwargs)
            entries.extend(conn.entries)
            controls = (conn.result or {}).get("controls", {})
            paged = (controls.get("1.2.840.113556.1.4.319", {}) or {}).get("value", {}) or {}
            cookie = paged.get("cookie")
            first = False
        return entries
    except Exception:
        conn.search(base, search_filter, search_scope=SUBTREE, attributes=attributes)
        return list(conn.entries)


def ldap_active_emails() -> set[str]:
    """Fetch active LDAP emails using configured service bind."""
    cfg = ldap_auth.ldap_cfg()
    if not ldap_auth.truthy(cfg.get("ldap_enabled")):
        return set()
    url = (cfg.get("ldap_url") or "").strip()
    user_base = (cfg.get("ldap_user_base") or "").strip()
    if not url or not user_base:
        return set()
    start_tls = ldap_auth.truthy(cfg.get("ldap_start_tls"))
    if not ldap_auth.ldap_tls_required_ok(url, start_tls):
        raise RuntimeError("LDAP transport is not safe; use ldaps:// or StartTLS")
    from ldap3 import ALL, SUBTREE, Server

    want_tls = start_tls and not url.lower().startswith("ldaps://")
    server = Server(url, get_info=ALL, connect_timeout=8)
    bind_dn = (cfg.get("ldap_bind_dn") or "").strip()
    bind_pw = ldap_auth.ldap_password_plain(cfg)
    conn = ldap_auth._ldap_bind(
        server,
        user=bind_dn or None,
        password=bind_pw if bind_dn else None,
        start_tls=want_tls,
    )
    email_attr = (cfg.get("ldap_email_attr") or "mail").strip() or "mail"
    attributes = [email_attr, "userAccountControl", "nsAccountLock", "pwdAccountLockedTime"]
    try:
        return {
            ldap_auth.ldap_attr(entry, email_attr).strip().lower()
            for entry in _ldap_search_all(conn, user_base, "(objectClass=*)", attributes)
            if ldap_auth.ldap_attr(entry, email_attr).strip() and not _ldap_entry_locked(entry)
        }
    finally:
        conn.unbind()


def sync_directory(
    *,
    source: str = "ldap",
    active_email_file: str | None = None,
    dry_run: bool = False,
    force: bool = False,
) -> dict[str, int | str | list[str]]:
    """Disable directory users absent from supplied/current directory roster.

    Lockout is enforced by ``disabled_at`` (login, PAT/CLI-token, and RLS
    checks all exclude disabled users), so personal access tokens are
    deliberately left in place — re-enabling restores them, matching a
    manual admin disable. Ephemeral CLI session tokens have no revoked
    flag and are deleted.

    Safety guards: an empty roster always refuses unless ``force``; a
    roster covering less than ``MIN_ROSTER_FRACTION`` of known directory
    users refuses unless ``force``; disabling the last active global
    admin always refuses, even with ``force``.
    """
    wanted = {s.strip() for s in (source or "ldap").strip().lower().split(",") if s.strip()}
    sources = sorted(wanted & {"ldap", "oidc"})
    if not sources:
        raise ValueError("source must be ldap, oidc, or ldap,oidc")
    if active_email_file:
        active = _read_email_file(active_email_file)
    elif sources == ["ldap"]:
        active = ldap_active_emails()
    else:
        raise ValueError("OIDC deprovisioning needs --active-email-file")
    if not active and not force:
        raise ValueError("active directory roster is empty; refusing to disable everyone")

    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) AS n FROM private.users WHERE auth_source = ANY(%s) AND disabled_at IS NULL",
            (sources,),
        )
        eligible = (cur.fetchone() or {}).get("n") or 0
        if eligible and not force and len(active) < eligible * MIN_ROSTER_FRACTION:
            raise ValueError(
                f"roster covers {len(active)} of {eligible} active directory users "
                f"(under {int(MIN_ROSTER_FRACTION * 100)}%); refusing — "
                "check for a truncated/failed fetch, or pass --force"
            )
        cur.execute(
            "SELECT COUNT(*) AS n FROM private.users WHERE is_global_admin AND disabled_at IS NULL"
        )
        admin_total = (cur.fetchone() or {}).get("n") or 0
        cur.execute(
            """
            SELECT id, email, is_global_admin FROM private.users
            WHERE auth_source = ANY(%s)
              AND disabled_at IS NULL
              AND NOT (lower(email) = ANY(%s))
            ORDER BY email
            """,
            (sources, sorted(active)),
        )
        stale = cur.fetchall() or []
        stale_admins = sum(1 for r in stale if r.get("is_global_admin"))
        if stale and stale_admins and admin_total - stale_admins <= 0:
            raise ValueError(
                "refusing to disable the last active global admin; "
                "promote a successor (or re-enable afterwards via SQL) first"
            )
        emails = sorted(r["email"] for r in stale if r.get("email"))
        if dry_run or not stale:
            return {
                "source": ",".join(sources),
                "disabled": len(stale),
                "disabled_emails": emails,
                "revoked_sessions": 0,
                "revoked_cli_tokens": 0,
            }
        ids = [str(r["id"]) for r in stale]
        cur.execute(
            "UPDATE private.users SET disabled_at = now() WHERE id = ANY(%s::uuid[])",
            (ids,),
        )
        cur.execute(
            "DELETE FROM private.cli_session_tokens WHERE user_id = ANY(%s::uuid[])",
            (ids,),
        )
        revoked_cli_tokens = cur.rowcount or 0
        cur.execute(
            """
            UPDATE private.user_sessions
            SET revoked_at = now()
            WHERE user_id = ANY(%s::uuid[]) AND revoked_at IS NULL
            """,
            (ids,),
        )
        revoked_sessions = cur.rowcount or 0
        for r in stale:
            audit.log_org(
                cur,
                action=audit.ORG_USER_DISABLED,
                detail=f"user_id={r['id']} email={r.get('email')} source={','.join(sources)} via=sync-directory",
                actor_email=AUDIT_ACTOR,
            )
        conn.commit()
    return {
        "source": ",".join(sources),
        "disabled": len(stale),
        "disabled_emails": emails,
        "revoked_sessions": revoked_sessions,
        "revoked_cli_tokens": revoked_cli_tokens,
    }
