# Deploy

## Compose (local or single host)

```bash
# Set strong secrets (required unless you opt out)
export JWT_SECRET=… MASTER_KEY=… SECRET_KEY=…

podman-compose up -d --build
# UI  http://localhost:8080
# API http://localhost:3000  (PostgREST)
```

Local play with baked-in secrets only:

```bash
export GLOBAL_ADMIN_EMAIL=you@example.com
ALLOW_INSECURE_DEFAULTS=1 podman-compose up -d --build
```

Without `ALLOW_INSECURE_DEFAULTS=1` or `FLASK_ENV=development`, the app refuses
to start if `JWT_SECRET` / `MASTER_KEY` / `SECRET_KEY` are still the compose
defaults.

## Environment

| Variable | Purpose |
|----------|---------|
| `JWT_SECRET` | Flask ↔ PostgREST JWT signing |
| `MASTER_KEY` | Fernet key for secret values |
| `SECRET_KEY` | Flask session cookie |
| `DATABASE_URL` | App role (authenticator); RLS applies |
| `DATABASE_ADMIN_URL` | Superuser DSN for schema upgrades (**required**) |
| `POSTGREST_URL` | PostgREST base URL (default `http://localhost:3000`) |
| `GLOBAL_ADMIN_EMAIL` | Promote this email to global admin (startup + login/register) |
| `BOOTSTRAP_ADMIN_EMAIL` | Same as above if `GLOBAL_ADMIN_EMAIL` unset |
| `ALLOW_INSECURE_DEFAULTS` | `0` by default; `1` only for local defaults |
| `COOKIE_SECURE` | `1` Secure session cookie + HSTS |

## First-run / bootstrap

Registration **does not** auto-promote the first user (avoids a race/takeover).

1. Set `GLOBAL_ADMIN_EMAIL=you@example.com` (or `BOOTSTRAP_ADMIN_EMAIL`).
2. Register or sign in as that email → promoted to global admin.
3. If neither env is set and no admin exists, registration is disabled until you set one.
4. Create team → project → secrets.
5. Create a **machine account** (prefer `read-only` for ESO).
6. Wire OpenShift ESO — see [openshift-eso.yaml](./openshift-eso.yaml).

## Machine accounts (ESO / CI)

| Role | `GET` secret / list | `POST /eso/v1/projects/{id}/secrets` |
|------|---------------------|--------------------------------------|
| `read-only` (default) | yes | 403 |
| `write` | yes | upsert `{"key","value","note?"}` |

```
GET /eso/v1/projects/{id}/secrets/{key}
Authorization: Bearer ss_…
→ {"value":"…"}   # ESO jsonPath: $.value
```

## PostgREST

After browser login, `GET /api/token` returns a JWT:

```bash
curl -H "Authorization: Bearer $JWT" http://localhost:3000/projects
```

RLS enforces team/project membership.

## Login lockout

5 failed attempts → locked for 5 minutes (`private.login_failures`, shared across workers).

## Layout

| Path | Role |
|------|------|
| `Dockerfile` | App image (build context = repo root) |
| `compose.yml` | Postgres + PostgREST + app |
| `db/init.sql` | Schema + RLS (first DB init only) |
| `app/` | Flask app; `schema.py` upgrades existing volumes |
| `docs/` | Deploy notes and examples |
