# Architecture

How Sigaint Secret Server is put together and how a request flows through it.

---

## Components

```
Browser ──► Flask app (:8080) ──► Postgres (RLS)
                │  ▲
                │  └── HTMX partials (UI)
                │
CLI / CI / ESO ─┴─► /eso/v1 (machine/PAT) ──► SECURITY DEFINER functions
                │
PostgREST (:3000) ◄── JWT (via /api/token) ──► Postgres (RLS)
```

| Component | Role |
|-----------|------|
| **Flask app** | Browser UI (HTMX), session auth, `/eso/v1` API, `/api/token` |
| **Postgres** | Source of truth; RLS is the access-control plane |
| **PostgREST** | SQL-style API over the `api` schema, JWT auth |
| **CLI** | Sibling repo `secretserver-cli`, talks to `/eso/v1` |
| **ESO** | OpenShift External Secrets Operator, webhook to `/eso/v1` |

---

## App layout

```
app/
  app.py            # WSGI entry, security headers, schema bootstrap, CLI cmds
  config.py         # env vars + constants
  db.py             # connections + JWT/RLS helpers (connect, as_user, make_jwt)
  schema.py         # idempotent schema migrations (ensure_schema)
  authz.py          # auth decorators, CSRF, safe redirect
  crypto.py         # Fernet encrypt/decrypt (MASTER_KEY)
  audit.py          # audit helpers + formatting
  nav.py            # sidebar navigation context
  pins.py           # secret pins / recent
  paging.py         # pagination helpers
  secret_kinds.py   # structured secret parsing (db/cert/ssh/kv)
  secret_ops.py     # shared secret DB helpers
  settings_svc.py   # server settings
  totp_svc.py       # TOTP 2FA
  pats.py           # personal access tokens
  ldap_auth.py      # LDAP bind + group sync
  oidc_auth.py      # OIDC SSO
  dir_sync.py       # directory group sync
  mailer.py         # SMTP
  lockout.py        # login lockout
  user_sessions.py  # server-side sessions
  routes/
    auth.py         # login, register, 2FA, reset
    teams.py        # teams, members, groups, invites
    projects.py     # projects, members, group roles, settings
    secrets.py      # secret CRUD, reveal, history, access requests, ACL
    project_io.py   # import/export
    project_tokens.py # machine token scopes
    admin.py        # server settings, users, audit
    api.py          # /api/token, /api/users/suggest, /health
    eso.py          # /eso/v1 machine + PAT secret API
    mgmt_api.py     # management API
```

---

## Database access model

The app connects as the `authenticator` role, then switches to `authenticated`
and sets `request.jwt.claims` with the verified session `user_id`
([db.py](../app/db.py)):

```python
conn = connect()                      # authenticator role
cur.execute("SET ROLE authenticated")
cur.execute("SELECT set_config('request.jwt.claims', %s, false)", (claims,))
```

`api.current_user_id()` reads the `sub` claim. All RLS policies and helper
functions key off that value. See [database.md](database.md).

---

## Request flow (browser)

1. Browser loads a page → Flask `before_request` runs `ensure_schema()` (once)
   and `validate_registered_session()`.
2. The route opens a connection via `db.as_user(session["user_id"])`.
3. Queries run under RLS — the user only sees rows they are allowed to see.
4. HTMX requests swap partials (secret list, reveal cell, dialogs) without a
   full page reload.
5. Every response gets security headers (CSP, X-Frame-Options, nosniff).

---

## Request flow (machine / PAT API)

1. Client sends `Authorization: Bearer ss_…` or `pat_…` to `/eso/v1`.
2. `_parse_auth()` resolves the token:
   - `ss_…` → machine token hash → SECURITY DEFINER helpers (bypass RLS).
   - `pat_…` → user id → `db.as_user()` → RLS.
3. Machine helpers gate on `auth_machine(project, hash)` (validity + expiry)
   and the token role (`read-only`/`write`).
4. Secret values are decrypted with `MASTER_KEY` and returned as plaintext.
5. Reveals are audited.

---

## Security model

- **RLS at the database** is the enforcement plane — the UI and APIs call the
  same SQL helpers; there is no separate app-only ACL.
- **SECURITY DEFINER** functions with `SET row_security = off` implement the
  access checks and machine paths; they are granted narrowly.
- **Audit rows are append-only** via SECURITY DEFINER functions.
- **Secret values** are Fernet-encrypted at rest; only the app and `/eso/v1`
  decrypt them. PostgREST only ever sees `value_enc`.

See [database.md](database.md) for the full RLS reference.

---

## Related docs

- [database.md](database.md) — schema, RLS, functions
- [api.md](api.md) — API reference
- [testing.md](testing.md) — tests
- [contributing.md](contributing.md) — how to contribute
