# Corvus

Self-hosted secrets server: Flask + HTMX + oat.ink UI, Postgres RLS, kustomize deploy.

## Layout
- `app/` Python package (routes, domain, templates)
- `tests/` pytest, mocked DB — no Postgres for unit tests
- `db/migrations/` `0001_init.sql` is the fresh-install baseline (large). Additive DDL = new `NNNN_slug.sql` only
- `deploy/` kustomize `base/` + overlays (`prod`, `staging`, `corvus-syd`)
- `docs/` human docs — do not load unless the task is documentation
- `scripts/` compose helpers (`up.sh`, `reset.sh`)
- `softhsm2/` HSM fixtures — ignore unless the task is HSM

## Do not read by default
- `db/migrations/0001_init.sql`
- `docs/`, `DESIGN.md`, `PRODUCT.md`, `CHANGELOG.md`, `site/`
- `app/static/`
- `.env`, `softhsm2/`, `.tox/`, `.venv/`

Search with grep/glob first. `@` only the files you will change.

## Verify
- One file: `pytest tests/test_foo.py -q --tb=short`
- One test: `pytest tests/test_foo.py::test_bar -q --tb=short`
- Do not run bare `pytest` or `tox -e lint` unless asked
- Python 3.10+ (`str | None`). macOS system 3.9 will fail
- Dev install: `pip install -e ".[dev]"`

## Shell
Prefix supported tools with `rtk` (`rtk git`, `rtk pytest`, `rtk kubectl`, …).

## Invariants
- Role vocab is DB-driven (`rbac.roles` via `app/auth/roles.py`); `app/core/config.py` dropdowns are offline fallback/seed only. Do not hardcode role names in routes, gates, or templates.
- Machine-token `role` column: `service-read` | `service-reveal` | `service-write`
- No `pyotp` — stdlib TOTP stays
- `ALLOW_INSECURE_DEFAULTS=1` is local only
- Do not `kubectl apply` unless asked. Prefer `kubectl kustomize` / `kubectl diff -k`
- User-facing copy stays plain; use RBAC role names in UI