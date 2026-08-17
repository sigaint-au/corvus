# AGENTS.md

Secret server: self-hosted team secrets store (Flask + HTMX, Postgres RLS, oat.ink UI).

## Run / verify

- Tests: `pytest` from repo root (pythonpath = `.` `app` is in `pyproject.toml`). **Tests mock the DB — no Postgres needed.** `str | None` syntax requires Python 3.10+; the system `python3` on macOS (3.9) will NOT work.
- Install dev deps: `pip install -e ".[dev]"` (uses `pyproject.toml` `[project.optional-dependencies] dev`).
- Single test: `pytest tests/test_x.py::Class::test_y` (or `tests/...`).
- Lint: `tox -e lint` or `make lint`. Format: `make format` (ruff). Type-check: `make typecheck` (mypy).

## Run the app / dev containers

- `scripts/_lib.sh` picks `podman-compose` or `docker compose` (whichever exists), roots the repo, loads `.env`.
- `scripts/up.sh` (build+start, `ALLOW_INSECURE_DEFAULTS=1` for local dev), `rebuild.sh`, `restart.sh`, `down.sh`, `logs.sh`, `status.sh`. Fresh DB is bootstrapped by `docker-entrypoint-initdb.d` running the complete squashed `db/migrations/0001_init.sql`. This branch is fresh-install-only; recreate existing databases after baseline changes.

## DB / RLS / RBAC / migrations (hard-earned)

- **Migrations are the sole source of truth for DDL.** The fresh-install baseline lives in `db/migrations/0001_init.sql`. Existing databases are not supported by this squashed baseline.
- **Adding migrations is allowed and is the preferred way to change the schema — do it when a change needs one.** Create `db/migrations/NNNN_slug.sql` (zero-padded, next number), make it idempotent where possible, and run `pytest` + `tox -e lint`. Never edit an already-released migration file whose checksum is recorded — add a new `NNNN_` migration instead.
- **Keep the squashed baseline ordered** — RBAC definitions live inside `db/migrations/0001_init.sql`; do not create a second baseline definition. Do not edit the baseline unless the change is part of an unreleased fresh-install revision (and then recreate the database).
- Machine-token `role` column uses `service-read`/`service-reveal`/`service-write`.

Roles in the UI are **RBAC names** (`team-owner/team-admin/...` and project-role & secret roles). Machine-token `role` column uses `service-read`/`service-reveal`/`service-write`.

## Secrets / templates

- `app/templates/` = server-rendered, oat.ink + HTMX. Tabs on server pages are `<nav class="tabs">` links (not `role=tablist`); responsive tables by wrap `<div class="table">` (oat does horizontal scroll).
- Health checks: `/healthz` (liveness, always 200) and `/readyz` (readiness, checks DB). No auth required.
- Config: `pyproject.toml` consolidates ruff, pytest, pyright, mypy, pylint settings. `.pylintrc` and `tox.ini` remain for their respective tools.
- Connection pool: `db.py` uses `psycopg_pool` for admin connections (reduces overhead). User connections (`as_user`) stay direct (need `SET ROLE` per checkout).
- Binding forms re-use `partials/access_bindings_panel.html` (POST rbac role names + subject_kind).
- Keep user-facing copy plain; use RBAC role names everywhere.

## Gotchas

- `MASTER_KEY` encrypts secret values; `crypto/__init__.py`. Schema changes are a **migration story** — add a new `db/migrations/NNNN_slug.sql` file when a change needs DDL (allowed when necessary), never edit the baseline.
- Per-project BYOK: a project may have its own data-encryption key (`private.project_crypto_keys`, DEK wrapped by `MASTER_KEY`). Secret rows record `crypto_provider` (`master`/`project`); server settings always use `MASTER_KEY`. Management lives in `app/crypto/project_keys.py`; onboarding is the new-project wizard page (`routes/teams/projects.py`).
- `ALLOW_INSECURE_DEFAULTS=1` only for local dev; `refuse_insecure_defaults()` otherwise errors.
- Don't add `pyotp`/TOTP libs — the stdlib TOTP (hmac/hashlib/struct/time) is the chosen one.

## References

- `docs/` — user guide, admin deploy/config, RBAC, machine tokens; `CONTRIBUTING.md`.
- `scripts/seed_mock.py`, `scripts/*.sh` — dev tooling.
