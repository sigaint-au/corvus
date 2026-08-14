"""Global admin audit and access-review routes."""

from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from flask import (
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
import audit
import authz
import db
import settings_svc
from .helpers import (
    _csv_response,
    _json_response,
)


@authz.global_admin_required
def admin_audit():
    """Render audit/access-review UI or handle retention/purge POSTs.

    Args:
        None (reads query/form ``tab``, filters, and POST ``action``).

    Returns:
        HTML audit template, or redirect after settings/purge actions.

    Example:
        GET/POST /admin/audit?tab=access
    """
    tab = (request.args.get("tab") or request.form.get("tab") or "access").strip().lower()
    if tab not in ("access", "roles", "export"):
        tab = "access"

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        if action == "retention":
            raw = (request.form.get("audit_retention_days") or "").strip()
            try:
                days = int(raw)
                if days < 0 or days > 36500:
                    raise ValueError("out of range")
            except ValueError:
                flash("Retention must be an integer from 0 (forever) to 36500 days", "error")
            else:
                settings_svc.set_setting("audit_retention_days", str(days))
                flash(
                    "Audit retention saved"
                    if days > 0
                    else "Audit retention set to forever (no automatic purge)",
                    "ok",
                )
            return redirect(url_for("admin_audit", tab="export"))
        if action == "purge":
            settings = settings_svc.get_settings()
            try:
                days = int(settings.get("audit_retention_days") or "365")
            except ValueError:
                days = 365
            if days <= 0:
                flash("Retention is forever — set a positive day count before purging", "error")
                return redirect(url_for("admin_audit", tab="export"))
            with db.connect_admin() as conn, conn.cursor() as cur:
                result = audit.purge_old_audit(cur, days)
                if not conn.autocommit:
                    conn.commit()
            flash(
                f"Purged {result['secret_audit']} secret audit, "
                f"{result['org_audit']} org audit, and "
                f"{result.get('login_failures', 0)} login-failure row(s) "
                f"older than {days} days",
                "ok",
            )
            return redirect(url_for("admin_audit", tab="export"))
        return redirect(url_for("admin_audit", tab=tab))

    settings = settings_svc.get_settings()
    retention_days = settings.get("audit_retention_days") or "365"
    access_rows = []
    role_rows = []
    role_total = 0
    counts = {"secret_audit": 0, "org_audit": 0, "oldest": None, "newest": None}
    q = (request.args.get("q") or "").strip()
    actor = (request.args.get("actor") or "").strip()
    since = (request.args.get("since") or "").strip()
    until = (request.args.get("until") or "").strip()
    role_actions = (request.args.get("role_actions") or "roles").strip().lower()
    active_actions = (
        audit.ENC_CHANGE_ACTIONS
        if role_actions == "encryption"
        else audit.ROLE_CHANGE_ACTIONS
    )

    with db.connect_admin() as conn, conn.cursor() as cur:
        if tab == "access":
            access_rows = audit.access_review_rows(cur)
        elif tab == "roles":
            role_total = audit.count_org_audit(
                cur,
                actions=active_actions,
                q=q,
                actor=actor,
                since=since,
                until=until,
            )
            role_rows = audit.list_org_audit(
                cur,
                actions=active_actions,
                q=q,
                actor=actor,
                since=since,
                until=until,
                limit=100,
            )
        elif tab == "export":
            counts = audit.audit_counts(cur)

    return render_template(
        "admin_audit.html",
        active_tab=tab,
        access_rows=access_rows,
        role_rows=role_rows,
        role_total=role_total,
        role_actions=role_actions,
        counts=counts,
        retention_days=retention_days,
        search_q=q,
        audit_actor=actor,
        audit_since=since,
        audit_until=until,
    )


@authz.global_admin_required
def admin_audit_access_export():
    """Export the access-review report as CSV or JSON download.

    Args:
        None (reads query ``format``: ``csv`` or ``json``).

    Returns:
        File download Response (CSV or JSON attachment).

    Example:
        GET /admin/audit/access/export?format=csv
    """
    fmt = (request.args.get("format") or "csv").strip().lower()
    if fmt not in ("csv", "json"):
        fmt = "csv"
    with db.connect_admin() as conn, conn.cursor() as cur:
        rows = audit.access_review_rows(cur)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    fields = [
        "email",
        "name",
        "is_global_admin",
        "disabled",
        "scope",
        "team",
        "team_role",
        "project",
        "project_role",
        "access_via",
        "user_id",
    ]
    if fmt == "json":
        return _json_response(
            f"access-review-{stamp}.json",
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "type": "access_review",
                "count": len(rows),
                "rows": rows,
            },
        )
    return _csv_response(f"access-review-{stamp}.csv", fields, rows)


@authz.global_admin_required
def admin_audit_export():
    """Export secret and/or org audit logs as CSV or JSON.

    Args:
        None (reads query ``format``, ``source``, ``since``, ``until``).

    Returns:
        File download Response with filtered audit rows.

    Example:
        GET /admin/audit/export?format=csv&source=both
    """
    fmt = (request.args.get("format") or "csv").strip().lower()
    source = (request.args.get("source") or "both").strip().lower()
    since = (request.args.get("since") or "").strip()
    until = (request.args.get("until") or "").strip()
    if fmt not in ("csv", "json"):
        fmt = "csv"
    if source not in ("secret", "org", "both"):
        source = "both"
    secret_rows, org_rows = [], []
    with db.connect_admin() as conn, conn.cursor() as cur:
        if source in ("secret", "both"):
            secret_rows = audit.export_secret_audit(cur, since=since, until=until)
        if source in ("org", "both"):
            org_rows = audit.export_org_audit(cur, since=since, until=until)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    if fmt == "json":
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "since": since or None,
            "until": until or None,
        }
        if source in ("secret", "both"):
            payload["secret_audit"] = secret_rows
        if source in ("org", "both"):
            payload["org_audit"] = org_rows
        return _json_response(f"audit-export-{stamp}.json", payload)

    # CSV: combined or single stream
    if source == "secret":
        fields = [
            "kind",
            "id",
            "created_at",
            "action",
            "secret_key",
            "actor_email",
            "team_name",
            "project_name",
            "project_id",
            "user_id",
        ]
        rows = [
            {
                "kind": "secret",
                "id": r.get("id"),
                "created_at": r.get("created_at"),
                "action": r.get("action"),
                "secret_key": r.get("secret_key"),
                "actor_email": r.get("actor_email"),
                "team_name": r.get("team_name"),
                "project_name": r.get("project_name"),
                "project_id": r.get("project_id"),
                "user_id": r.get("user_id"),
            }
            for r in secret_rows
        ]
        return _csv_response(f"secret-audit-{stamp}.csv", fields, rows)
    if source == "org":
        fields = [
            "kind",
            "id",
            "created_at",
            "action",
            "detail",
            "actor_email",
            "team_name",
            "project_name",
            "team_id",
            "project_id",
            "user_id",
        ]
        rows = [
            {
                "kind": "org",
                "id": r.get("id"),
                "created_at": r.get("created_at"),
                "action": r.get("action"),
                "detail": r.get("detail"),
                "actor_email": r.get("actor_email"),
                "team_name": r.get("team_name"),
                "project_name": r.get("project_name"),
                "team_id": r.get("team_id"),
                "project_id": r.get("project_id"),
                "user_id": r.get("user_id"),
            }
            for r in org_rows
        ]
        return _csv_response(f"org-audit-{stamp}.csv", fields, rows)

    fields = [
        "kind",
        "id",
        "created_at",
        "action",
        "detail",
        "secret_key",
        "actor_email",
        "team_name",
        "project_name",
        "team_id",
        "project_id",
        "user_id",
    ]
    rows = []
    for r in secret_rows:
        rows.append(
            {
                "kind": "secret",
                "id": r.get("id"),
                "created_at": r.get("created_at"),
                "action": r.get("action"),
                "detail": "",
                "secret_key": r.get("secret_key"),
                "actor_email": r.get("actor_email"),
                "team_name": r.get("team_name"),
                "project_name": r.get("project_name"),
                "team_id": "",
                "project_id": r.get("project_id"),
                "user_id": r.get("user_id"),
            }
        )
    for r in org_rows:
        rows.append(
            {
                "kind": "org",
                "id": r.get("id"),
                "created_at": r.get("created_at"),
                "action": r.get("action"),
                "detail": r.get("detail"),
                "secret_key": "",
                "actor_email": r.get("actor_email"),
                "team_name": r.get("team_name"),
                "project_name": r.get("project_name"),
                "team_id": r.get("team_id"),
                "project_id": r.get("project_id"),
                "user_id": r.get("user_id"),
            }
        )
    rows.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
    return _csv_response(f"audit-export-{stamp}.csv", fields, rows)
