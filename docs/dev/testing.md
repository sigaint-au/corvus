# Testing & Lint

Unit tests use **pytest** with a mocked DB — Postgres is not required.

---

## Prerequisites

```bash
pip install -e ".[dev]"
```

---

## Run tests

```bash
# From repo root
pytest

# Or via tox
tox -e py
```

### Test layout

```
tests/
  conftest.py          # env + fixtures
  helpers.py           # mock_conn, REPO_ROOT / APP_ROOT
  test_auth.py         # login, register, CSRF, sessions
  test_audit.py        # audit logging
  test_crypto.py       # AES-256-GCM encrypt/decrypt (+ FIPS primitives)
  test_eso.py          # /eso/v1 machine + PAT API
  test_health.py       # /health endpoint
  test_live_api.py     # opt-in live app/PostgREST/ESO smoke tests
  test_helpers.py      # test utility helpers
  test_jwt.py          # JWT generation/validation
  test_ldap.py         # LDAP bind + group sync
  test_lockout.py      # login lockout
  test_mailer.py      # SMTP
  test_nav.py          # sidebar navigation
  test_org_access.py   # org RBAC / RLS schema assertions
  test_paging.py       # pagination + access_mode filter
  test_pats.py         # personal access tokens
  test_rbac.py         # RBAC config, SQL, routes
  test_schema.py       # schema migration assertions
  test_secret_lifecycle.py # secret create/reveal/update/delete
  test_secrets.py      # secret CRUD / reveal / project delete
  test_settings.py     # server settings
  test_teams.py        # teams, members, groups, invites
  test_tokens.py       # machine tokens, scopes, RBAC function checks
  test_totp.py         # TOTP 2FA
  test_ui.py           # template rendering, role tooltips
```

`pyproject.toml` `[tool.pytest.ini_options]` sets `testpaths = tests`,
`pythonpath = . app`, and strict markers. The `live` marker is opt-in and
skips unless its required environment variables are configured.

---

## Lint

```bash
# From repo root
tox -e lint

# Or directly (from app/)
cd app
pylint --rcfile=../.pylintrc \
  app.py \
  core auth crypto integrations secret_svc ui \
  audit lib routes
```

---

## Live API smoke tests

The default suite uses mocked database connections. To exercise a running
Compose deployment, configure the endpoints and credentials, then run:

```bash
LIVE_APP_URL=http://127.0.0.1:8080 \
LIVE_POSTGREST_URL=http://127.0.0.1:3000 \
LIVE_API_JWT="$JWT" \
LIVE_MACHINE_TOKEN="$MACHINE_TOKEN" \
LIVE_PROJECT_REF="$PROJECT_UUID" \
pytest -m live tests/test_live_api.py
```

`LIVE_API_JWT` must be a user JWT from `/api/token`; use a non-global-admin JWT
for the URL-redaction assertion. Set `LIVE_API_JWT_IS_GLOBAL_ADMIN=1` only when
the JWT belongs to a global admin. The live tests verify the health endpoint,
anonymous denial of both sensitive HSM RPCs, authenticated PostgREST access
without HSM URLs, and optional machine-token project access. Migration assertion
tests cover the database triggers and grants; a live PostgreSQL run is still
required to verify effective ACLs and RLS behavior.
Run `scripts/seed_mock.py` in the app container first; it prints the machine
API token and project reference for the optional test.

## Test conventions

- Tests mock the DB connection (`helpers.mock_conn`) — no live Postgres.
- The app is imported with `TESTING=True`, so `ensure_schema()` is skipped.
- Tests cover auth, CSRF, sessions, secrets, ESO, PATs, teams, groups, RLS
  schema, pagination, machine token scopes, audit, TOTP, LDAP, mailer, lockout.
- Schema assertion tests check the consolidated `db/migrations/0001_init.sql`
  baseline for RBAC functions and RLS policies.
- Role names in tests use RBAC names: `team-owner`, `team-admin`,
  `team-member`, `team-viewer`, `project-admin`, `project-write`,
  `project-read`, `service-read`, `service-reveal`, `service-write`.

---

## Related docs

- [architecture.md](architecture.md) — app layout
- [contributing.md](contributing.md) — how to contribute
- [database.md](database.md) — schema & RLS
