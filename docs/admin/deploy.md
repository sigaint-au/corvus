# Deploy Guide

Deploy Sigaint Secret Server end to end. Every step is a **copy-paste code
block** — replace the `…` placeholders.

Also see [configuration.md](configuration.md) for the full env/settings
reference, [authentication.md](authentication.md) for auth flows, and
[building.md](../dev/building.md) for building images.

---

## 1. Quick start (local, single host)

### 1a. Configure secrets

Create a `.env` in the repo root (Compose reads it automatically):

```bash
openssl rand -hex 32   # → JWT_SECRET
openssl rand -hex 32   # → MASTER_KEY
openssl rand -hex 32   # → SECRET_KEY
```

```bash
# .env
JWT_SECRET=<64 hex chars>
MASTER_KEY=<64 hex chars>
SECRET_KEY=<64 hex chars>
GLOBAL_ADMIN_EMAIL=you@example.com
```

> The app **refuses to start** if `JWT_SECRET`, `MASTER_KEY`, or `SECRET_KEY`
> are still the baked-in defaults. Set real values — do not use
> `ALLOW_INSECURE_DEFAULTS=1` outside local testing.

### 1b. Start the stack

```bash
podman-compose up -d --build
# or: docker compose up -d --build
```

| Service | URL |
|---------|-----|
| UI (Flask app) | http://localhost:8080 |
| PostgREST | http://localhost:3000 |

### 1c. Local play with baked-in secrets (dev only)

```bash
export GLOBAL_ADMIN_EMAIL=you@example.com
ALLOW_INSECURE_DEFAULTS=1 podman-compose up -d --build
```

---

## 2. First-run / bootstrap

Registration does **not** auto-promote the first user (avoids a takeover race).

1. Set `GLOBAL_ADMIN_EMAIL=you@example.com` (or `BOOTSTRAP_ADMIN_EMAIL`).
2. Open the UI, register or sign in as that email → promoted to **global admin**.
3. If neither env var is set and no admin exists, registration stays disabled.

```bash
# Confirm admin: open http://localhost:8080/settings
# You should see Administration / Server settings.
```

Then, in order:

```text
1. Create a team
2. Create a project inside the team
3. Add secrets to the project
4. (ESO) create a machine account — use reveal for value reads
5. (optional) OIDC/LDAP, SMTP, TOTP enforcement, audit retention
```

---

## 3. Environment variables

See [configuration.md](configuration.md) for the complete table.

Required:

| Variable | Purpose |
|----------|---------|
| `JWT_SECRET` | Flask ↔ PostgREST JWT signing |
| `MASTER_KEY` | Fernet key for secret values |
| `SECRET_KEY` | Flask session cookie (+ TOTP recovery HMAC) |
| `DATABASE_URL` | App role (`authenticator`); RLS applies |
| `DATABASE_ADMIN_URL` | Superuser DSN for schema upgrades (**required**) |

---

## 4. PostgREST & personal access tokens

`GET /api/token` returns a short-lived JWT (also under **My profile → Security
→ API access → Show JWT**):

```bash
# With a browser session cookie:
curl -s -b cookies.txt -H "Accept: application/json" \
  http://localhost:8080/api/token
```

For scripts without a browser, create a PAT under **My profile → Security**
(`pat_…`, shown once), then exchange it for a JWT:

```bash
JWT=$(curl -s \
  -H "Authorization: Bearer pat_…" \
  -H "Accept: application/json" \
  http://localhost:8080/api/token | jq -r .access_token)

curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/projects?select=id,name,team_id"
```

PATs act as that user under RLS. Machine tokens (`ss_…`) are for project
ESO/CI. PostgREST returns encrypted `value_enc` — use ESO routes or the UI for
plaintext. See [api.md](../dev/api.md) and
[postgrest-openapi.json](../postgrest-openapi.json).

---

## 5. Server URL

Set **Administration → Server settings → General → Server URL** to the public
base URL (no trailing slash), e.g. `https://secrets.example.com`. Used for:

- OIDC redirect URI in the SSO checklist and login callback preference
- Default app base URL in project **Integrations** ESO YAML

If unset, the app falls back to the request host.

---

## 6. Login lockout

5 failed attempts → locked for 5 minutes (`private.login_failures`, shared
across workers). Old failure rows are removed by the same **purge-audit** job
as the audit tables (section 8).

---

## 7. Two-factor authentication (TOTP)

Users enable TOTP under **My profile → Security**. Recovery codes are shown
once (HMAC-hashed at rest). Global admins can be forced to enroll via
**Administration → Server settings** (`totp_enforce_global_admins`).

---

## 8. Audit retention purge (daily cron)

Retention is configured in the UI (**Administration → Auditing → Export &
retention**, `audit_retention_days`). `0` = keep forever. Rows are **not**
deleted until something runs the CLI.

Purge targets:

- `api.secret_audit`
- `api.org_audit`
- `private.login_failures`

### Run manually

```bash
flask --app app purge-audit --dry-run
flask --app app purge-audit
flask --app app purge-audit --days 90
```

Inside the running container:

```bash
podman exec secretstore_app_1 flask --app app purge-audit --dry-run
podman exec secretstore_app_1 flask --app app purge-audit
```

### Host crontab

Podman:

```cron
15 3 * * * podman exec secretstore_app_1 flask --app app purge-audit >> /var/log/secretstore-purge-audit.log 2>&1
```

Docker Compose:

```cron
15 3 * * * cd /path/to/secretstore && docker compose exec -T app flask --app app purge-audit >> /var/log/secretstore-purge-audit.log 2>&1
```

### OpenShift CronJob

Use the same app image and env as the Deployment. Full manifest:
[openshift-purge-audit-cronjob.yaml](../openshift-purge-audit-cronjob.yaml).

```bash
oc apply -f docs/openshift-purge-audit-cronjob.yaml
oc get cronjobs -n secretstore
oc create job --from=cronjob/secretstore-purge-audit purge-audit-manual -n secretstore
oc logs job/purge-audit-manual -n secretstore
```

---

## 9. OpenShift (ESO)

See [machine-tokens.md](machine-tokens.md) for ESO setup and the sample
manifest [openshift-eso.yaml](../openshift-eso.yaml).

---

## Layout

| Path | Role |
|------|------|
| `Dockerfile` | App image (build context = repo root) |
| `compose.yml` | Postgres + PostgREST + app |
| `db/migrations/0001_init.sql` | Tables + `ENABLE/FORCE RLS` (baseline, applied as `01-init.sql`) |
| `db/migrations/0002_rbac.sql` | RBAC functions + all RLS policies (baseline, applied as `02-rbac.sql`) |
| `app/` | Flask app; `migrations.py` applies remaining migrations on existing volumes |
| `docs/` | This documentation set |
