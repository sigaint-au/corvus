"""Sigaint Secret Server: Flask+HTMX UI, PostgREST JWT, OpenShift ESO webhook API."""
import logging
import os

from flask import Flask

import authz
import config
from nav import inject_nav
from schema import ensure_schema
from routes import register_all

log = logging.getLogger(__name__)

config.refuse_insecure_defaults()

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    MAX_CONTENT_LENGTH=config.MAX_CONTENT_LENGTH,
)

app.context_processor(inject_nav)
register_all(app)

import audit as _audit  # noqa: E402

app.jinja_env.filters["time_ago"] = _audit.format_time_ago
app.jinja_env.filters["time_when"] = _audit.format_when
app.jinja_env.filters["expires"] = lambda dt: _audit.format_expires(dt, prefix=False)


_schema_ready = False


@app.before_request
def _bootstrap_schema():
    """Ensure the database schema is applied once before handling requests.

    Flask before_request hook. Runs on every request until the schema has been
    successfully ensured; subsequent requests skip the work via a module flag.
    When ``app.config['TESTING']`` is true, marks ready without touching the DB.

    Args:
        None. Uses the current Flask request/app context implicitly.

    Returns:
        None. May raise if ``ensure_schema()`` fails (misconfig or DB error);
        in that case the ready flag is not set so the next request retries.

    Example:
        >>> # Registered via @app.before_request; Flask invokes it automatically.
        >>> # In tests with TESTING=True, it only sets _schema_ready and returns.
        >>> with app.test_request_context('/'):
        ...     _bootstrap_schema()
    """
    global _schema_ready
    if _schema_ready:
        return
    # TESTING: unit tests mock the DB and do not run real schema upgrades.
    if app.config.get("TESTING"):
        _schema_ready = True
        return
    ensure_schema()  # raises on misconfig / DB failure (do not mark ready)
    _schema_ready = True


app.before_request(authz.csrf_protect)
app.before_request(authz.validate_registered_session)


@app.after_request
def security_headers(resp):
    """Attach security-related HTTP headers to every response.

    Flask after_request hook. Sets content-type sniffing protection, frame
    denial, referrer policy, and a restrictive Content-Security-Policy. When
    ``COOKIE_SECURE=1`` is set in the environment, also adds HSTS.

    Args:
        resp: The Flask response object for the current request. Headers are
            mutated in place and the same object is returned.

    Returns:
        The same response object with security headers applied.

    Example:
        >>> # Registered via @app.after_request; Flask invokes it automatically.
        >>> with app.test_request_context('/'):
        ...     from flask import make_response
        ...     r = security_headers(make_response('ok'))
        ...     assert r.headers['X-Frame-Options'] == 'DENY'
    """
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://unpkg.com 'unsafe-inline'; "
        "style-src 'self' https://unpkg.com 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )
    if os.environ.get("COOKIE_SECURE") == "1":
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


import click  # noqa: E402
import db  # noqa: E402
import settings_svc  # noqa: E402


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

    Args:
        days: Retention days override. If None, loaded from
            ``settings_svc.get_settings()['audit_retention_days']`` (default 0).
            Values <= 0 skip purging (retention forever).
        dry_run: If True, print how many rows would be deleted from
            ``api.secret_audit``, ``api.org_audit``, and ``private.login_failures``
            without deleting anything.

    Returns:
        None. Prints a summary line to stdout via click.echo.

    Example:
        >>> # flask --app app purge-audit --days 90
        >>> # flask --app app purge-audit --dry-run
        >>> # flask --app app purge-audit  # uses audit_retention_days setting
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
    """Re-wrap all project BYOK keys from an old MASTER_KEY to the current one.

    Run after rotating ``MASTER_KEY`` so per-project encryption keys survive.
    The old key is only used to unwrap the wrapped DEKs; pass it explicitly or
    via the ``MASTER_KEY_OLD`` environment variable.
    """
    import project_keys

    old_key = old_master_key or os.environ.get("MASTER_KEY_OLD", "")
    if not old_key:
        click.echo(
            "Missing old MASTER_KEY — pass --old-master-key or set MASTER_KEY_OLD"
        )
        return
    n = project_keys.rewrap_project_keys(old_key)
    click.echo(f"re-wrapped {n} project key(s) to the current MASTER_KEY")


@app.cli.command("rekey-hsm-kek")
def rekey_hsm_kek_command():
    """Rotate the HSM KEK, re-wrapping every HSM-backed project DEK."""
    import hsm
    import project_keys

    if not hsm.available():
        click.echo("HSM is not configured (HSM_PIN unset or module missing)")
        return
    n = project_keys.rotate_hsm_kek()
    click.echo(f"rotated HSM KEK — re-wrapped {n} project key(s)")


if __name__ == "__main__":
    from crypto import decrypt, encrypt

    assert decrypt(encrypt("ping")) == "ping"
    app.run(host="0.0.0.0", port=8080, debug=os.environ.get("FLASK_DEBUG") == "1")
