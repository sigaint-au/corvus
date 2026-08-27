"""Operational jobs: due notifications and directory deprovisioning."""
from __future__ import annotations

from pathlib import Path

from core import db
from integrations import ldap_auth


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
    return {
        line.strip().lower()
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


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
    try:
        conn.search(user_base, "(objectClass=*)", search_scope=SUBTREE, attributes=[email_attr])
        return {
            ldap_auth.ldap_attr(entry, email_attr).strip().lower()
            for entry in conn.entries
            if ldap_auth.ldap_attr(entry, email_attr).strip()
        }
    finally:
        conn.unbind()


def sync_directory(
    *,
    source: str = "ldap",
    active_email_file: str | None = None,
    dry_run: bool = False,
) -> dict[str, int | str]:
    """Disable directory users absent from supplied/current directory roster."""
    source = (source or "ldap").strip().lower()
    sources = [s for s in source.split(",") if s in {"ldap", "oidc"}]
    if not sources:
        raise ValueError("source must be ldap, oidc, or ldap,oidc")
    if active_email_file:
        active = _read_email_file(active_email_file)
    elif sources == ["ldap"]:
        active = ldap_active_emails()
    else:
        raise ValueError("OIDC deprovisioning needs --active-email-file")
    if not active:
        raise ValueError("active directory roster is empty; refusing to disable everyone")

    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, email FROM private.users
            WHERE auth_source = ANY(%s)
              AND disabled_at IS NULL
              AND NOT (lower(email) = ANY(%s))
            ORDER BY email
            """,
            (sources, sorted(active)),
        )
        stale = cur.fetchall() or []
        if dry_run or not stale:
            return {"source": ",".join(sources), "disabled": len(stale), "revoked_sessions": 0, "revoked_tokens": 0}
        ids = [str(r["id"]) for r in stale]
        cur.execute(
            "UPDATE private.users SET disabled_at = now() WHERE id = ANY(%s::uuid[])",
            (ids,),
        )
        cur.execute(
            "DELETE FROM private.personal_access_tokens WHERE user_id = ANY(%s::uuid[])",
            (ids,),
        )
        revoked_tokens = cur.rowcount or 0
        cur.execute(
            """
            UPDATE private.user_sessions
            SET revoked_at = now()
            WHERE user_id = ANY(%s::uuid[]) AND revoked_at IS NULL
            """,
            (ids,),
        )
        revoked_sessions = cur.rowcount or 0
        conn.commit()
    return {
        "source": ",".join(sources),
        "disabled": len(stale),
        "revoked_sessions": revoked_sessions,
        "revoked_tokens": revoked_tokens,
    }
