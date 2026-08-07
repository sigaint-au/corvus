# Deploy

Also: [API reference](./api.md) · [ESO sample](./openshift-eso.yaml) · [audit purge CronJob](./openshift-purge-audit-cronjob.yaml)

## Compose

```bash
export JWT_SECRET=… MASTER_KEY=… SECRET_KEY=…
export GLOBAL_ADMIN_EMAIL=you@example.com
podman-compose up -d --build
# UI http://localhost:8080 · PostgREST http://localhost:3000
```

Local defaults only (dev):

```bash
export GLOBAL_ADMIN_EMAIL=you@example.com
ALLOW_INSECURE_DEFAULTS=1 podman-compose up -d --build
```

Without `ALLOW_INSECURE_DEFAULTS=1` / `FLASK_ENV=development`, the app **refuses** default `JWT_SECRET` / `MASTER_KEY` / `SECRET_KEY`.

## Environment (important)

| Variable | Purpose |
|----------|---------|
| `JWT_SECRET` | Flask ↔ PostgREST JWT |
| `MASTER_KEY` | Encrypt secret values |
| `SECRET_KEY` | Session cookie (+ TOTP recovery HMAC) |
| `DATABASE_URL` | App role (RLS) |
| `DATABASE_ADMIN_URL` | Schema upgrades (**required**) |
| `POSTGREST_URL` | Default `http://localhost:3000` |
| `GLOBAL_ADMIN_EMAIL` | Promote this email to global admin |
| `ALLOW_INSECURE_DEFAULTS` | `1` only for local defaults |
| `COOKIE_SECURE` | `1` → Secure cookie + HSTS |
| `CLIPBOARD_CLEAR_SECONDS` | UI clipboard clear (default `30`; `0` off) |
| `REVEAL_AUTO_HIDE_SECONDS` | Auto-hide reveal (default `30`; `0` off) |

`BOOTSTRAP_ADMIN_EMAIL` is an alias for `GLOBAL_ADMIN_EMAIL`.

## Bootstrap

1. Set `GLOBAL_ADMIN_EMAIL` → register/sign in as that email → global admin.
2. Without an admin email and with no admins, registration stays closed.
3. Team → project → secrets → machine account (prefer **read-only** for ESO).
4. Wire ESO: [openshift-eso.yaml](./openshift-eso.yaml).
5. Optional: OIDC/LDAP, SMTP, TOTP, audit retention under **Administration**.

## Machine accounts (ESO / CI)

| Role | GET secret / list | POST upsert |
|------|-------------------|-------------|
| `read-only` | yes | 403 |
| `write` | yes | yes |

```
GET /eso/v1/projects/{id}/secrets/{key}
Authorization: Bearer ss_…
→ {"value":"…"}
```

Details: [api.md](./api.md#eso--machine-api-8080esov1).

## PAT → PostgREST

```bash
JWT=$(curl -s -H "Authorization: Bearer pat_…" \
  -H "Accept: application/json" \
  https://secrets.example.com/api/token | jq -r .access_token)
curl -H "Authorization: Bearer $JWT" http://localhost:3000/projects
```

PostgREST returns **`value_enc`**, not plaintext. Use ESO or the UI for plaintext.

## OIDC / LDAP (short)

Configure under **Administration → Server settings**.

- **Server URL** — public base (no trailing slash); OIDC redirect = `{url}/login/oidc/callback`
- **OIDC** — issuer, client id/secret, scopes (`openid email profile`); group → global-admin / team role maps
- **LDAP** — bind URL + user filter; group → team role maps

Maps apply on each login; manual memberships are not removed.

## TOTP

Enable under **My profile → Security**. Force global admins via **Server settings** (`totp_enforce_global_admins`).

## Login lockout

5 failures → 5 minutes (`private.login_failures`). Cleaned by the same purge job as audit tables.

## Audit retention

UI: **Administration → Auditing → Export & retention** (`audit_retention_days`; `0` = forever).

```bash
podman exec secretstore_app_1 flask --app app purge-audit --dry-run
podman exec secretstore_app_1 flask --app app purge-audit
# optional: --days 90
```

OpenShift CronJob: [openshift-purge-audit-cronjob.yaml](./openshift-purge-audit-cronjob.yaml).

## Layout

| Path | Role |
|------|------|
| `compose.yml` | Postgres + PostgREST + app |
| `db/init.sql` | Schema + RLS (first init) |
| `app/` | Flask; `schema.py` upgrades volumes |
| `docs/` | This file, API, samples |
