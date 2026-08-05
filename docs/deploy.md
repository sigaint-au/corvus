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
| `GLOBAL_ADMIN_EMAIL` | Optional; promote this user on startup |
| `ALLOW_INSECURE_DEFAULTS` | `0` by default; `1` only for local defaults |
| `COOKIE_SECURE` | `1` to set Secure on session cookie (HTTPS) |

## First-run

1. Register at `/register` (or enable LDAP under **Server settings** after first admin).
2. First user becomes global admin.
3. Create team → project → secrets.
4. Create a **machine account** (prefer `read-only` for ESO).
5. Wire OpenShift ESO — see [openshift-eso.yaml](./openshift-eso.yaml).

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
