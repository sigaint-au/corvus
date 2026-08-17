"""Sigaint Secret Server: Flask+HTMX UI, PostgREST JWT, OpenShift ESO webhook API.

Application factory pattern: ``create_app()`` builds and configures the Flask
app. The module-level ``app`` instance is kept for backward compatibility
with ``gunicorn app:app`` and ``import app as store`` in tests.
"""
import logging
import os

from flask import Flask, jsonify, render_template, request

from auth import authz
from core import config
from core import db
from ui.nav import inject_nav
from core.schema import ensure_schema
from routes import register_all

log = logging.getLogger(__name__)

config.refuse_insecure_defaults()


# User-facing messages for HTTP errors rendered as WebUI pages.
_ERROR_MESSAGES = {
    400: ("Bad request", "The request was not understood."),
    403: ("Forbidden", "You don’t have permission to view this."),
    404: ("Not found", "That page doesn’t exist."),
    405: ("Method not allowed", "This URL doesn’t accept that method."),
    413: ("Request too large", "The upload or request exceeded the size limit."),
    429: ("Too many requests", "Please slow down and try again shortly."),
    500: ("Something went wrong", "An unexpected error occurred."),
    502: ("Bad gateway", "An upstream service returned an invalid response."),
    503: ("Service unavailable", "The service is temporarily unavailable."),
}


def _error_wants_json() -> bool:
    """Return True for API/ESO/HTMX callers that want JSON, not an HTML page.

    Browser page loads (including an HTTP error) get the themed error page;
    anything asking for JSON or doing an HTMX/XHR swap gets a JSON body so it
    does not inject a full HTML page into an HTMX target.
    """
    path = request.path
    accept = request.headers.get("Accept") or ""
    return (
        path.startswith(("/api/", "/eso/", "/mgmt/"))
        or "application/json" in accept
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )


def _register_error_handlers(app) -> None:
    """Attach themed HTML error pages (JSON for API/HTMX callers)."""
    for _code, (_title, _fallback) in _ERROR_MESSAGES.items():

        def _handler(_exc, _c=_code, _t=_title, _m=_fallback):
            if _error_wants_json():
                return jsonify({"error": _t, "status": _c}), _c
            return render_template("error.html", code=_c, title=_t, message=_m), _c

        app.register_error_handler(_code, _handler)

    @app.errorhandler(Exception)
    def _unhandled(e):
        log.exception("Unhandled exception", exc_info=e)
        if _error_wants_json():
            return jsonify({"error": "Internal Server Error", "status": 500}), 500
        return (
            render_template(
                "error.html",
                code=500,
                title="Something went wrong",
                message="An unexpected error occurred.",
            ),
            500,
        )


def create_app():
    """Build and configure the Flask application.

    Returns:
        A configured Flask app instance with all routes, before/after
        request hooks, Jinja filters, and CLI commands registered.

    Example:
        >>> app = create_app()
        >>> app.config["TESTING"] = True
        >>> client = app.test_client()
    """
    app = Flask(__name__)
    app.secret_key = config.SECRET_KEY
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=config.session_cookie_secure(),
        MAX_CONTENT_LENGTH=config.MAX_CONTENT_LENGTH,
    )

    app.context_processor(inject_nav)
    register_all(app)
    _register_error_handlers(app)

    # ── Jinja filters ──────────────────────────────────────────────────
    import audit as _audit  # noqa: E402

    app.jinja_env.filters["time_ago"] = _audit.format_time_ago
    app.jinja_env.filters["time_when"] = _audit.format_when
    app.jinja_env.filters["expires"] = lambda dt: _audit.format_expires(dt, prefix=False)

    from crypto import hsm as _hsm  # noqa: E402

    app.jinja_env.filters["redact_pin"] = _hsm.redact_pkcs11_url

    # ── Schema bootstrap (runs once per process) ───────────────────────
    _schema_ready = False

    # ── Health check endpoints (no auth required) ──────────────────────
    @app.get("/healthz")
    def healthz():
        """Liveness probe — always returns 200 when the process is alive."""
        return jsonify({"status": "ok"}), 200

    @app.get("/readyz")
    def readyz():
        """Readiness probe — checks schema initialization and database connectivity."""
        if not _schema_ready:
            return jsonify({"status": "not ready"}), 503
        try:
            with db.connect_admin() as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
            return jsonify({"status": "ready"}), 200
        except Exception:
            return jsonify({"status": "not ready"}), 503

    @app.before_request
    def _bootstrap_schema():
        """Ensure the database schema is applied once before handling requests."""
        nonlocal _schema_ready
        if _schema_ready:
            return None
        if app.config.get("TESTING"):
            _schema_ready = True
            return None
        try:
            ensure_schema()
        except Exception:
            log.exception("schema initialization failed")
            return jsonify({"status": "not ready"}), 503
        _schema_ready = True
        return None

    app.before_request(authz.csrf_protect)
    app.before_request(authz.validate_registered_session)

    @app.after_request
    def security_headers(resp):
        """Attach security-related HTTP headers to every response."""
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'"
        )
        if config.session_cookie_secure():
            resp.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return resp

    return app


# ── Module-level app instance (backward compat: gunicorn app:app, tests) ─
app = create_app()


# ── CLI commands ───────────────────────────────────────────────────────
import click  # noqa: E402
from core import settings_svc  # noqa: E402


@app.cli.command("purge-audit")
@click.option(
    "--days",
    type=int,
    default=None,
    help="Retention days override (default: server setting audit_retention_days).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Print how many rows would be deleted without deleting.",
)
def purge_audit_command(days, dry_run):
    """Delete secret and org audit rows older than the retention window.

    Intended for cron / Kubernetes CronJob. Uses the server setting
    ``audit_retention_days`` when ``--days`` is omitted (0 means forever).

    Example:
        >>> # flask --app app purge-audit --days 90
        >>> # flask --app app purge-audit --dry-run
    """
    if days is None:
        try:
            days = int(settings_svc.get_settings().get("audit_retention_days") or "0")
        except ValueError:
            days = 0
    if days <= 0:
        click.echo("retention forever (0); nothing to purge")
        return
    with db.connect_admin() as conn, conn.cursor() as cur:
        if dry_run:
            cur.execute(
                """
                SELECT
                  (SELECT count(*)::int FROM api.secret_audit
                   WHERE created_at < now() - (%s || ' days')::interval) AS secret_audit,
                  (SELECT count(*)::int FROM api.org_audit
                   WHERE created_at < now() - (%s || ' days')::interval) AS org_audit,
                  (SELECT count(*)::int FROM private.login_failures
                   WHERE created_at < now() - (%s || ' days')::interval) AS login_failures
                """,
                (str(days), str(days), str(days)),
            )
            row = cur.fetchone() or {}
            click.echo(
                f"dry-run retention={days}d would purge "
                f"secret_audit={row.get('secret_audit', 0)} "
                f"org_audit={row.get('org_audit', 0)} "
                f"login_failures={row.get('login_failures', 0)}"
            )
            return
        import audit as _audit

        result = _audit.purge_old_audit(cur, days)
    click.echo(
        f"purged retention={days}d "
        f"secret_audit={result.get('secret_audit', 0)} "
        f"org_audit={result.get('org_audit', 0)} "
        f"login_failures={result.get('login_failures', 0)}"
    )


@app.cli.command("rekey-project-keys")
@click.option(
    "--old-master-key",
    type=str,
    default=None,
    help="Previous MASTER_KEY value (reads MASTER_KEY_OLD env var if omitted).",
)
def rekey_project_keys_command(old_master_key):
    """Re-wrap all project BYOK keys from an old MASTER_KEY to the current one."""
    from crypto import project_keys

    old_key = old_master_key or os.environ.get("MASTER_KEY_OLD", "")
    if not old_key:
        click.echo("Missing old MASTER_KEY — pass --old-master-key or set MASTER_KEY_OLD")
        return
    n = project_keys.rewrap_project_keys(old_key)
    click.echo(f"re-wrapped {n} project key(s) to the current MASTER_KEY")


@app.cli.command("rekey-hsm-kek")
@click.option("--slot-id", "slot_id", required=True, help="HSM slot UUID to rotate")
def rekey_hsm_kek_command(slot_id):
    """Rotate a named HSM slot's KEK, re-wrapping its project DEKs."""
    from crypto import project_keys

    n = project_keys.rotate_hsm_kek(slot_id)
    click.echo(f"rotated HSM KEK for slot {slot_id} — re-wrapped {n} project key(s)")


@app.cli.command("notify-due")
@click.option("--days", type=int, default=14, help="Due window in days.")
@click.option("--dry-run", is_flag=True, help="Count recipients without sending email.")
def notify_due_command(days, dry_run):
    """Email expiring secrets/tokens and pending approval reminders."""
    from ops import send_due_notifications

    result = send_due_notifications(days, dry_run=dry_run)
    click.echo(
        f"notify-due recipients={result['recipients']} "
        f"sent={result['sent']} failed={result['failed']}"
    )


@app.cli.command("sync-directory")
@click.option(
    "--source",
    type=click.Choice(["ldap", "oidc", "ldap,oidc"]),
    default="ldap",
    help="Directory source to deprovision.",
)
@click.option(
    "--active-email-file",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Newline-delimited active directory emails. Required for OIDC.",
)
@click.option("--dry-run", is_flag=True, help="Count affected users without changing data.")
def sync_directory_command(source, active_email_file, dry_run):
    """Disable directory users absent from the active directory roster."""
    from ops import sync_directory

    result = sync_directory(
        source=source,
        active_email_file=active_email_file,
        dry_run=dry_run,
    )
    click.echo(
        f"sync-directory source={result['source']} disabled={result['disabled']} "
        f"revoked_sessions={result['revoked_sessions']} revoked_tokens={result['revoked_tokens']}"
    )


if __name__ == "__main__":
    from crypto import decrypt, encrypt

    assert decrypt(encrypt("ping")) == "ping"
    app.run(host="0.0.0.0", port=8080, debug=os.environ.get("FLASK_DEBUG") == "1")
