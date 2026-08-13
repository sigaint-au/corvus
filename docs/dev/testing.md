# Testing & Lint

Unit tests use **pytest** with a mocked DB — Postgres is not required.

---

## Prerequisites

```bash
pip install -r app/requirements.txt -r requirements-dev.txt
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
  test_crypto.py       # Fernet encrypt/decrypt
  test_eso.py          # /eso/v1 machine + PAT API
  test_health.py       # /health endpoint
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

`pytest.ini` sets `testpaths = tests`, `pythonpath = . app`, and strict
markers.

---

## Lint

```bash
# From repo root
tox -e lint

# Or directly (from app/)
cd app
pylint --rcfile=../.pylintrc \
  app.py audit.py authz.py config.py crypto.py db.py dir_sync.py \
  ldap_auth.py lockout.py mailer.py nav.py oidc_auth.py paging.py \
  passwords.py pats.py pins.py rbac_sync.py schema.py secret_kinds.py secret_ops.py \
  settings_svc.py totp_svc.py user_sessions.py routes
```

---

## Test conventions

- Tests mock the DB connection (`helpers.mock_conn`) — no live Postgres.
- The app is imported with `TESTING=True`, so `ensure_schema()` is skipped.
- Tests cover auth, CSRF, sessions, secrets, ESO, PATs, teams, groups, RLS
  schema, pagination, machine token scopes, audit, TOTP, LDAP, mailer, lockout.
- Schema assertion tests check `db/rbac.sql` (not `db/init.sql`) for RBAC
  functions and RLS policies, since these were moved from `init.sql` to
  `rbac.sql`.
- Role names in tests use RBAC names: `team-owner`, `team-admin`,
  `team-member`, `team-viewer`, `project-admin`, `project-write`,
  `project-read`, `service-read`, `service-reveal`, `service-write`.

---

## Related docs

- [architecture.md](architecture.md) — app layout
- [contributing.md](contributing.md) — how to contribute
- [database.md](database.md) — schema & RLS
