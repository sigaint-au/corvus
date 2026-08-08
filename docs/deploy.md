# Deploy

This guide walks you through deploying Sigaint Secret Server end to end.
Every step is a **copy-paste code block** — replace the `…` placeholders with
your own values.

Also see **[api.md](./api.md)** for the HTTP / ESO / PostgREST reference and
**[authentication.md](./authentication.md)** for every auth flow with `curl`
examples.

---

## 1. Quick start (local, single host)

### 1a. Configure secrets

Create a `.env` file in the repo root. Compose reads it automatically.

```bash
# Generate strong secrets (run each once, paste the output into .env)
openssl rand -hex 32   # → JWT_SECRET
openssl rand -hex 32   # → MASTER_KEY
openssl rand -hex 32   # → SECRET_KEY
```

```bash
# .env  — copy this whole block
JWT_SECRET=<paste 64 hex chars>
MASTER_KEY=<paste 64 hex chars>
SECRET_KEY=<paste 64 hex chars>

# The email that becomes global admin on first register/login
GLOBAL_ADMIN_EMAIL=you@example.com
```

> **Security defaults:** the app refuses to start if `JWT_SECRET`, `MASTER_KEY`
> or `SECRET_KEY` are still the baked-in compose defaults. Set real values in
> `.env` (above) — do **not** use `ALLOW_INSECURE_DEFAULTS=1` outside local
> testing.

### 1b. Start the stack

```bash
podman-compose up -d --build
```

or with Docker:

```bash
docker compose up -d --build
```

```bash
# Verify everything is up
podman-compose ps
```

| Service | URL |
|---------|-----|
| UI (Flask app) | http://localhost:8080 |
| PostgREST | http://localhost:3000 |

### 1c. Local play with baked-in secrets (dev only)

Skip the `.env` secrets and use the compose defaults:

```bash
export GLOBAL_ADMIN_EMAIL=you@example.com
ALLOW_INSECURE_DEFAULTS=1 podman-compose up -d --build
```

---

## 2. First-run / bootstrap

Registration **does not** auto-promote the first user (avoids a race/takeover).

1. Set `GLOBAL_ADMIN_EMAIL=you@example.com` (or `BOOTSTRAP_ADMIN_EMAIL`) — done
   in step 1a.
2. Open the UI, register or sign in as that email → promoted to **global admin**.
3. If neither env var is set and no admin exists, registration stays disabled
   until you set one.

```bash
# After registering, confirm you're admin by opening:
#   http://localhost:8080/settings
# You should see the Administration / Server settings page.
```

Then, in order:

```bash
# 1. Create a team
# 2. Create a project inside the team
# 3. Add secrets to the project
# 4. (ESO) create a machine account — prefer read-only
# 5. (optional) OIDC/LDAP, SMTP, TOTP enforcement, audit retention
```

---

## 3. Environment variables

### Required

| Variable | Purpose | Example |
|----------|---------|---------|
| `JWT_SECRET` | Flask ↔ PostgREST JWT signing | 64 hex chars |
| `MASTER_KEY` | Fernet key for secret values (plaintext) | 64 hex chars |
| `SECRET_KEY` | Flask session cookie (+ TOTP recovery HMAC) | 64 hex chars |
| `DATABASE_URL` | App role (`authenticator`); RLS applies | `postgres://authenticator:…@db:5432/secretstore` |
| `DATABASE_ADMIN_URL` | Superuser DSN for schema upgrades (**required**) | `postgres://postgres:…@db:5432/secretstore` |

### Optional

| Variable | Default | Purpose |
|----------|---------|---------|
| `POSTGREST_URL` | `http://localhost:3000` | PostgREST base URL |
| `GLOBAL_ADMIN_EMAIL` | — | Promote this email to global admin |
| `BOOTSTRAP_ADMIN_EMAIL` | — | Same as `GLOBAL_ADMIN_EMAIL` if unset |
| `ALLOW_INSECURE_DEFAULTS` | `0` | `1` only for local defaults |
| `COOKIE_SECURE` | `0` | `1` = Secure session cookie + HSTS |
| `CLIPBOARD_CLEAR_SECONDS` | `30` | UI clipboard auto-clear; `0` disables |
| `REVEAL_AUTO_HIDE_SECONDS` | `30` | Auto-hide revealed values; `0` disables |
| `MAX_CONTENT_LENGTH` | `1 MiB` | Request/import size cap (memory DoS guard) |

> `DATABASE_ADMIN_URL` is **required** — the app uses it for idempotent schema
> upgrades (`app/schema.py`). Compose sets it for you.

---

## 4. Machine accounts (ESO / CI)

Machine tokens (`ss_…`) are project-scoped and only authenticate the `/eso/v1`
routes.

| Role | `GET` secret / list | `POST /eso/v1/projects/{id}/secrets` |
|------|---------------------|--------------------------------------|
| `read-only` (default) | yes | 403 |
| `write` | yes | upsert `{"key","value","note?"}` |

Create one under a project (**Integrations** or **Tokens**), then test it:

```bash
# Fetch a single secret
curl -s -H "Authorization: Bearer ss_…" \
  "http://localhost:8080/eso/v1/projects/<PROJECT_ID>/secrets/DATABASE_URL"

# Fetch all secrets (bulk)
curl -s -H "Authorization: Bearer ss_…" \
  "http://localhost:8080/eso/v1/projects/<PROJECT_ID>/secrets"

# Upsert (write role only)
curl -s -X POST \
  -H "Authorization: Bearer ss_…" \
  -H "Content-Type: application/json" \
  -d '{"key":"API_KEY","value":"new-value","note":"optional"}' \
  "http://localhost:8080/eso/v1/projects/<PROJECT_ID>/secrets"
```

Full request/response shapes: [api.md](./api.md#eso--machine-api-8080esov1).

---

## 5. PostgREST & personal access tokens

After login, `GET /api/token` returns a short-lived JWT (also available from
**My profile → Security → API access → Show JWT**):

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

# Use the JWT against PostgREST
curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/projects?select=id,name,team_id"
```

PATs act as that user under RLS. Machine tokens (`ss_…`) remain for project
ESO/CI. PostgREST returns encrypted `value_enc` — use ESO routes or the UI for
plaintext.

Details and resource list: [api.md](./api.md). Checked-in PostgREST OpenAPI
snapshot: [postgrest-openapi.json](./postgrest-openapi.json) (regenerate with a
JWT after schema changes).

---

## 6. Server URL

Set **Administration → Server settings → General → Server URL** to the public
base URL of this app (no trailing slash), e.g. `https://secrets.example.com` or
`http://secrets.internal`. Used for:

- OIDC redirect URI in the SSO checklist and login callback preference
- Default app base URL in project **Integrations** ESO YAML

If unset, the app falls back to the request host for those features.

---

## 7. Login lockout

5 failed attempts → locked for 5 minutes (`private.login_failures`, shared
across workers). Old failure rows are removed by the same **purge-audit** job
as the audit tables (section 10).

---

## 8. Two-factor authentication (TOTP)

Users enable TOTP under **My profile → Security**. Recovery codes are shown
once (HMAC-hashed at rest). Global admins can be forced to enroll via
**Administration → Server settings** (`totp_enforce_global_admins`).

---

## 9. OIDC / SSO and LDAP

### 9a. OIDC / SSO

Authorization-code login for any OpenID Connect IdP. Configure under
**Administration → Server settings → OIDC / SSO**.

| Setting | Example |
|---------|---------|
| Server URL (General) | `https://secrets.example.com` or `http://…` |
| Issuer | `https://idp.example.com/realms/myrealm` (or `http://localhost` for dev) |
| Client ID | `secretstore` |
| Client secret | confidential client secret |
| Scopes | `openid email profile` (email required) |
| Username claim | `preferred_username` |
| Groups claim | `groups` (plus `realm_access.roles` when present) |
| Require verified email | on by default (`email_verified` claim) |
| Redirect URI | `{server_url}/login/oidc/callback` |

Create a confidential OIDC client with the authorization code flow and the
redirect URI above. Users are upserted by email (`auth_source=oidc`). When
**Require verified email** is on (default), the ID token must assert
`email_verified` so self-asserted emails cannot hijack existing accounts.
Disable only if your IdP never sends that claim and you trust its email. Local
password login still works for break-glass accounts.

**Group → role maps:**

- **Server settings → OIDC / SSO → OIDC group → roles** — map a group to `global_admin`
- **Team → Settings → OIDC group membership** — map a group to a team role

Groups come from the configured groups claim (default `groups`) plus
`realm_access.roles` when present. Maps apply on each SSO login; manual team
memberships are not removed. ID token signatures are restricted to asymmetric
algorithms (RS/ES/PS). Discovery documents are cached 1 hour (cleared when
OIDC settings are saved).

### 9b. LDAP

Optional bind login and group → team role maps under
**Administration → Server settings → LDAP** and **Team → Settings**. Same
membership-sync idea as OIDC team maps. LDAP over cleartext is rejected unless
StartTLS is enabled.

---

## 10. Audit retention purge (daily cron)

Retention is configured in the UI (**Administration → Auditing → Export &
retention**, setting `audit_retention_days`). **0** = keep forever (purge is a
no-op). Rows are **not** deleted automatically until something runs the CLI.

Purge targets:

- `api.secret_audit`
- `api.org_audit`
- `private.login_failures`

### 10a. Run the CLI manually

```bash
# Dry-run (counts only)
flask --app app purge-audit --dry-run

# Use server setting audit_retention_days
flask --app app purge-audit

# Override retention for this run
flask --app app purge-audit --days 90
```

Inside the running container (name may vary):

```bash
podman exec secretstore_app_1 flask --app app purge-audit --dry-run
podman exec secretstore_app_1 flask --app app purge-audit
```

### 10b. Host crontab

Run once per day (e.g. 03:15 UTC). Adjust container name and log path.

Podman:

```cron
15 3 * * * podman exec secretstore_app_1 flask --app app purge-audit >> /var/log/secretstore-purge-audit.log 2>&1
```

Docker Compose:

```cron
15 3 * * * cd /path/to/secretstore && docker compose exec -T app flask --app app purge-audit >> /var/log/secretstore-purge-audit.log 2>&1
```

### 10c. OpenShift CronJob

Use the **same app image and env** as the Deployment (especially `DATABASE_URL`
/ `DATABASE_ADMIN_URL` / secrets). Full manifest:
[openshift-purge-audit-cronjob.yaml](./openshift-purge-audit-cronjob.yaml).

```bash
oc apply -f docs/openshift-purge-audit-cronjob.yaml
oc get cronjobs -n secretstore

# Manual one-shot test:
oc create job --from=cronjob/secretstore-purge-audit purge-audit-manual -n secretstore
oc logs job/purge-audit-manual -n secretstore
```

---

## Layout

| Path | Role |
|------|------|
| `Dockerfile` | App image (build context = repo root) |
| `compose.yml` | Postgres + PostgREST + app |
| `db/init.sql` | Schema + RLS (first DB init only) |
| `app/` | Flask app; `schema.py` upgrades existing volumes |
| `docs/deploy.md` | This file |
| `docs/authentication.md` | Auth flows + curl examples |
| `docs/building.md` | Build & push the app container image |
| `docs/api.md` | API reference (app JSON, ESO, PAT, PostgREST) |
| `docs/postgrest-openapi.json` | Generated PostgREST OpenAPI snapshot |
| `docs/openshift-eso.yaml` | Sample ESO SecretStore |
| `docs/openshift-purge-audit-cronjob.yaml` | Audit purge CronJob |
