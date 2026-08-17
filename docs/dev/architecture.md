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
  app.py               # WSGI entry, security headers, schema bootstrap, CLI cmds
  core/                # core infrastructure
    config.py          # env vars + RBAC constants
    db.py              # connections + JWT/RLS helpers (connect, as_user, make_jwt)
    schema.py          # schema bootstrap: apply pending migrations + promote admin
    migrations.py      # versioned migration runner (db/migrations/*.sql)
    settings_svc.py    # server settings
  crypto/              # encryption & key management
    __init__.py        # Fernet encrypt/decrypt (MASTER_KEY) + per-project BYOK seam
    project_keys.py    # per-project DEK lifecycle (create/adopt/re-encrypt)
    hsm.py             # PKCS#11 wrapper for external-HSM (SoftHSM2) BYOK
  auth/                # authentication & authorization services
    authz.py           # auth decorators, CSRF, safe redirect
    lockout.py         # login lockout
    passwords.py       # password change/reset
    totp_svc.py        # TOTP 2FA
    user_sessions.py   # server-side sessions
    pats.py            # personal access tokens
    rbac_sync.py       # RBAC binding sync helpers (sync_user_team_binding, etc.)
  integrations/        # external integrations
    ldap_auth.py       # LDAP bind + group sync
    oidc_auth.py       # OIDC SSO
    mailer.py          # SMTP
    dir_sync.py        # directory group sync
  secret_svc/          # secret service
    secret_kinds.py    # structured secret parsing (db/cert/ssh/kv)
    secret_ops.py      # shared secret DB helpers (list, parse, upsert)
  ui/                  # UI helpers
    nav.py             # sidebar navigation context
    pins.py            # secret pins / recent
    paging.py          # pagination helpers
  audit/               # audit logging (constants, dates, export, queries, write)
  lib/                 # shared helpers (auth_tokens, datetime_utils, serialize, users, validate)
  routes/
    auth/              # login, register, 2FA, reset
    teams/             # teams, members, groups, invites
    projects/          # projects, members, group roles, settings
    secrets/           # secret CRUD, reveal, history, access requests, access mode
    project_io.py      # import/export
    project_tokens.py  # machine token scopes
    admin/             # server settings, users, audit
    api.py             # /api/token, /api/users/suggest, /health
    eso/               # /eso/v1 machine + PAT secret API
    mgmt_api/          # management API (teams, members via PAT)
```

---

## Database files

```
db/migrations/
  0001_init.sql                  # Complete squashed schema/security baseline (01-init.sql)
  0002_rls_authz_hardening.sql   # Additive RLS/authz hardening (applied by apply_pending)
```

On fresh databases, `docker-entrypoint-initdb.d` runs the `0001_init.sql`
baseline. On every startup the app checks migrations via
`migrations.apply_pending()`, seeding the `0001` baseline and applying newer
ones (`0002_rls_authz_hardening.sql`), recording versions and checksums in
`private.schema_migrations`.

---

## Database access model

The app connects as the `authenticator` role, then switches to `authenticated`
and sets `request.jwt.claims` with the verified session `user_id`:

```python
conn = connect()                      # authenticator role
cur.execute("SET ROLE authenticated")
cur.execute("SELECT set_config('request.jwt.claims', %s, false)", (claims,))
```

`api.current_user_id()` reads the `sub` claim. All RLS policies and helper
functions key off that value.

Mutable application caches use Redis when `REDIS_URL` is configured:
project-key rows, HSM slot URLs, and OIDC discovery documents use shared epoch
keys, so updates invalidate every app replica. JWKS clients are not retained in process memory; Fernet objects
are cached per process via ``@lru_cache(maxsize=1)`` on ``_fernet()``. If Redis is unavailable, the app bypasses
caching and reads the source directly; it never uses a process-local stale-key
cache. If Redis is unavailable during invalidation, an already-populated Redis
entry can survive until its TTL; use a database-backed generation or
transactional outbox if that failure mode must be eliminated.

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
   and the token role (`service-read`/`service-reveal`/`service-write`).
   `service-read` tokens are rejected at both the DB function level
   (``machine_get_row`` / ``machine_list_enc`` return no rows) and the app
   layer (explicit 403 before decryption) — they can only list metadata.
4. Secret values are decrypted with the project DEK (or ``MASTER_KEY``)
   and returned as plaintext. Only ``service-reveal`` and ``service-write``
   tokens receive plaintext.
5. Reveals are audited.
6. Management API (``/api/v1/manage``) POST/DELETE/PATCH routes are
   CSRF-exempt when a Bearer token is present (PAT auth, not session cookie).

---

## Security model

- **RLS at the database** is the enforcement plane — the UI and APIs call the
  same SQL helpers; there is no separate app-only ACL.
- **SECURITY DEFINER** functions with `SET row_security = off` implement the
  access checks and machine paths; they are granted narrowly.
- **Audit rows are append-only** via SECURITY DEFINER functions.
- **Secret values** are Fernet-encrypted at rest; only the app and `/eso/v1`
  decrypt them. PostgREST only ever sees `value_enc`.
- **RBAC** is the only authorization model — `rbac.bindings` stores all
  user/group/service-account access at cluster/team/project/secret scope.
- **Per-project crypto keys are not an RBAC resource.** Key lifecycle
  (create/adopt/rotate) is gated by app-side admin predicates (team
  owner/admin or global admin), not `rbac.role_rules` — keep `keys` out of
  `RBAC_RESOURCES` so wildcard grants never cover key management.

---

## Related docs

- [database.md](database.md) — schema, RLS, functions
- [api.md](api.md) — API reference
- [testing.md](testing.md) — tests
- [contributing.md](contributing.md) — how to contribute
- [../admin/rbac.md](../admin/rbac.md) — RBAC access model
- [../admin/rbac-k8s.md](../admin/rbac-k8s.md) — K8s RBAC model
