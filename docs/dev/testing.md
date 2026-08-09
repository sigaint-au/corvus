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
  test_secrets.py      # secret CRUD / reveal
  test_eso.py          # /eso/v1 machine + PAT API
  test_paging.py       # pagination + machine token scopes
  test_org_access.py   # org RBAC / RLS schema
  …                    # ~24 test modules total
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
  passwords.py pats.py pins.py schema.py secret_kinds.py secret_ops.py \
  settings_svc.py totp_svc.py user_sessions.py routes
```

---

## Test conventions

- Tests mock the DB connection (`helpers.mock_conn`) — no live Postgres.
- The app is imported with `TESTING=True`, so `ensure_schema()` is skipped.
- Tests cover auth, CSRF, sessions, secrets, ESO, PATs, teams, groups, RLS
  schema, pagination, machine token scopes, audit, TOTP, LDAP, mailer, lockout.

---

## Related docs

- [architecture.md](architecture.md) — app layout
- [contributing.md](contributing.md) — how to contribute
