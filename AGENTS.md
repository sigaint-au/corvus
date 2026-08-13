# AGENTS.md

Secret server: self-hosted team secrets store (Flask + HTMX, Postgres RLS, oat.ink UI).

## Run / verify

- Tests: `pytest` from repo root (pythonpath = `.` `app` is in `tests/helpers.py`). **Tests mock the DB — no Postgres needed.** `str | None` syntax requires Python 3.10+; the system `python3` on macOS (3.9) will NOT work.
- Single test: `pytest tests/test_x.py::Class::test_y` (or `tests/...`).
- Lint: from `app/` run `pylint --rcfile=../.pylintrc <modules...>` with `PYTHONPATH=app` (repo tox `-e lint` does this). Full-list of lint modules: app.py, audit, authz.py, config.py, crypto.py, db.py, dir_sync.py, ldap_auth.py, lockout.py, mailer.py, nav.py, oidc_auth.py, paging.py, passwords.py, pats.py, pins.py, schema.py, secret_kinds.py, secret_ops.py, settings_svc.py, totp_svc.py, user_sessions.py, `lib`, and `routes`.

## Run the app / dev containers

- `scripts/_lib.sh` picks `podman-compose` or `docker compose` (whichever exists), roots the repo, loads `.env`.
- `scripts/up.sh` (build+start, `ALLOW_INSECURE_DEFAULTS=1` for local dev), `rebuild.sh`, `restart.sh`, `down.sh`, `logs.sh`, `status.sh`. Fresh DB is bootstrapped from `db/init.sql` then `db/rbac.sql`; `schema.ensure_schema()` re-applies DDL via `legacy_markers` filtering (rbac.sql is the sole source of truth).

## DB / RLS / RBAC (hard-earned)

- `app/rbac.sql` is the **sole source** for RBAC tables/functions/policies. `app/schema.py` has a `legacy_markers` filter that skips old DDL, then `_apply_rbac_sql(cur)` every boot. **Do not add a second RBAC function/table definition** — put it in `rbac.sql` (and re-apply).
- Fresh DB bootstrap: `db/init.sql` (base tables) then `db/rbac.sql` (RBAC schema, kept in sync with `app/rbac.sql`).

Roles in the UI are **RBAC names** (`team-owner/team-admin/...` and project-role & secret roles). Machine-token `role` column uses `read/reveal/write` (`service-*` is the RBAC name).

## Secrets / templates

- `app/templates/` = server-rendered, oat.ink + HTMX. Tabs on server pages are `<nav class="tabs">` links (not `role=tablist`); responsive tables by wrap `<div class="table">` (oat does horizontal scroll).
- Binding forms re-use `partials/access_bindings_panel.html` (POST rbac role names + subject_kind).
- Keep user-facing copy plain; use RBAC role names everywhere.

## Gotchas

- `MASTER_KEY` encrypts secret values; `crypto.py`. Schema changes usually need only editing `app/schema.py` and `db/init.sql` (fresh volumes) — not a migration story.
- `ALLOW_INSECURE_DEFAULTS=1` only for local dev; `refuse_insecure_defaults()` otherwise errors.
- Don't add `pyotp`/TOTP libs — the stdlib TOTP (hmac/hashlib/struct/time) is the chosen one.

## References

- `docs/` — user guide, admin deploy/config, RBAC, machine tokens; `CONTRIBUTING.md`.
- `scripts/seed_mock.py`, `scripts/*.sh` — dev tooling.