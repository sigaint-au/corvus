# AGENTS.md

Secret server: self-hosted team secrets store (Flask + HTMX, Postgres RLS, oat.ink UI).

## Run / verify

- Tests: `pytest` from repo root (pythonpath = `.` `app` is in `tests/helpers.py`). **Tests mock the DB — no Postgres needed.** `str | None` syntax requires Python 3.10+; the system `python3` on macOS (3.9) will NOT work.
- Single test: `pytest tests/test_x.py::Class::test_y` (or `tests/...`).
- Lint: from `app/` run `pylint --rcfile=../.pylintrc <modules...>` with `PYTHONPATH=app` (repo tox `-e lint` does this). Full-list of lint modules: app.py, audit, authz.py, config.py, crypto.py, db.py, dir_sync.py, ldap_auth.py, lockout.py, mailer.py, migrations.py, nav.py, oidc_auth.py, paging.py, passwords.py, pats.py, pins.py, schema.py, secret_kinds.py, secret_ops.py, settings_svc.py, totp_svc.py, user_sessions.py, `lib`, and `routes`.

## Run the app / dev containers

- `scripts/_lib.sh` picks `podman-compose` or `docker compose` (whichever exists), roots the repo, loads `.env`.
- `scripts/up.sh` (build+start, `ALLOW_INSECURE_DEFAULTS=1` for local dev), `rebuild.sh`, `restart.sh`, `down.sh`, `logs.sh`, `status.sh`. Fresh DB is bootstrapped by `docker-entrypoint-initdb.d` running `db/migrations/0001_init.sql` then `0002_rbac.sql`; the app applies the remaining migrations via `migrations.apply_pending()` at startup.

## DB / RLS / RBAC / migrations (hard-earned)

- **Migrations are the sole source of truth for DDL.** Versioned SQL lives in `db/migrations/*.sql`, applied once, in order, by `app/migrations.py` (records version + sha256 checksum in `private.schema_migrations`). `0001_init.sql` and `0002_rbac.sql` are the non-idempotent baseline (run by docker-entrypoint on a fresh volume); everything after is additive/idempotent.
- **Do not add a second RBAC function/table definition** — put it in `db/migrations/0002_rbac.sql` (and add a new numbered migration for any later change).
- **Adding a migration:** create `db/migrations/NNNN_slug.sql` (zero-padded, next number), make it idempotent where possible, and run `pytest` + `tox -e lint`. Never edit an already-released migration file — its checksum is recorded.
- Machine-token `role` column uses `read/reveal/write` (`service-*` is the RBAC name).

Roles in the UI are **RBAC names** (`team-owner/team-admin/...` and project-role & secret roles). Machine-token `role` column uses `read/reveal/write` (`service-*` is the RBAC name).

## Secrets / templates

- `app/templates/` = server-rendered, oat.ink + HTMX. Tabs on server pages are `<nav class="tabs">` links (not `role=tablist`); responsive tables by wrap `<div class="table">` (oat does horizontal scroll).
- Binding forms re-use `partials/access_bindings_panel.html` (POST rbac role names + subject_kind).
- Keep user-facing copy plain; use RBAC role names everywhere.

## Gotchas

- `MASTER_KEY` encrypts secret values; `crypto.py`. Schema changes are a **migration story** — add a new `db/migrations/NNNN_slug.sql` file, never edit the baseline.
- Per-project BYOK: a project may have its own data-encryption key (`private.project_crypto_keys`, DEK wrapped by `MASTER_KEY`). Secret rows record `crypto_provider` (`master`/`project`); server settings always use `MASTER_KEY`. Management lives in `app/project_keys.py`; onboarding is the new-project wizard page (`routes/teams/projects.py`).
- `ALLOW_INSECURE_DEFAULTS=1` only for local dev; `refuse_insecure_defaults()` otherwise errors.
- Don't add `pyotp`/TOTP libs — the stdlib TOTP (hmac/hashlib/struct/time) is the chosen one.

## References

- `docs/` — user guide, admin deploy/config, RBAC, machine tokens; `CONTRIBUTING.md`.
- `scripts/seed_mock.py`, `scripts/*.sh` — dev tooling.