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

## Server URL

**Administration → Server settings → General → Server URL** — public base URL of this app
(e.g. `https://secrets.example.com`, no trailing slash). Used for:

- OIDC redirect URI in the SSO checklist and login callback preference
- Default app base URL in project **Integrations** ESO YAML

If unset, the app falls back to the request host for those features.

## OIDC / SSO

Authorization-code login for any OpenID Connect IdP. Configure under
**Administration → Server settings → OIDC / SSO**.

| Setting | Example |
|---------|---------|
| Server URL (General) | `https://secrets.example.com` |
| Issuer | `https://idp.example.com/realms/myrealm` |
| Client ID | `secretstore` |
| Client secret | confidential client secret |
| Scopes | `openid email profile` (email required) |
| Username claim | `preferred_username` (display name on onboarding) |
| Redirect URI | `{server_url}/login/oidc/callback` |

Create a confidential OIDC client with the authorization code flow and the redirect URI
above. Users are upserted by email (`auth_source=oidc`). Local password login still works.

**Group → role maps** (same idea as LDAP):

- **Server settings → OIDC / SSO → OIDC group → roles** — map a group name to `global_admin`
- **Team → Settings → OIDC group membership** — map a group to a team role

Groups are read from the ID token claim `oidc_groups_claim` (default `groups`) plus
`realm_access.roles` when present. Maps apply on each SSO login; manual team memberships are not removed.

## Audit retention purge (daily cron)

Retention is configured in the UI (**Administration → Auditing → Export & retention**,
setting `audit_retention_days`). **0** means keep forever (purge is a no-op).
Rows are **not** deleted automatically until something runs the CLI.

### CLI

Runs inside the app image (needs `DATABASE_ADMIN_URL` like the web process):

```bash
# Dry-run (counts only)
flask --app app purge-audit --dry-run

# Use server setting audit_retention_days
flask --app app purge-audit

# Override retention for this run
flask --app app purge-audit --days 90
```

Compose / Podman example (container name may vary):

```bash
podman exec secretstore_app_1 flask --app app purge-audit --dry-run
podman exec secretstore_app_1 flask --app app purge-audit
```

### Host crontab

Run once per day (e.g. 03:15 UTC). Adjust container name and log path:

```cron
15 3 * * * podman exec secretstore_app_1 flask --app app purge-audit >> /var/log/secretstore-purge-audit.log 2>&1
```

Docker Compose variant:

```cron
15 3 * * * cd /path/to/secretstore && docker compose exec -T app flask --app app purge-audit >> /var/log/secretstore-purge-audit.log 2>&1
```

### OpenShift CronJob

Use the **same app image and env** as the Deployment (especially `DATABASE_URL` /
`DATABASE_ADMIN_URL` / secrets). Example:

```yaml
# docs/openshift-purge-audit-cronjob.yaml — also see that file for a full copy
apiVersion: batch/v1
kind: CronJob
metadata:
  name: secretstore-purge-audit
  namespace: secretstore   # change me
spec:
  # 03:15 UTC daily
  schedule: "15 3 * * *"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: purge-audit
              image: image-registry.openshift-image-registry.svc:5000/secretstore/secretstore:latest
              imagePullPolicy: IfNotPresent
              command: ["flask", "--app", "app", "purge-audit"]
              # Optional dry-run first: ["flask", "--app", "app", "purge-audit", "--dry-run"]
              envFrom:
                - secretRef:
                    name: secretstore-app-env   # JWT_SECRET, MASTER_KEY, SECRET_KEY, DATABASE_*
              # If env is not in a single Secret, copy the Deployment env: block instead.
          # Uncomment if the app uses a service account / pull secrets:
          # serviceAccountName: secretstore
```

Apply:

```bash
oc apply -f docs/openshift-purge-audit-cronjob.yaml
oc get cronjobs -n secretstore
# Manual one-shot test:
oc create job --from=cronjob/secretstore-purge-audit purge-audit-manual -n secretstore
oc logs job/purge-audit-manual -n secretstore
```

See [openshift-purge-audit-cronjob.yaml](./openshift-purge-audit-cronjob.yaml) for a
standalone manifest.

## Layout

| Path | Role |
|------|------|
| `Dockerfile` | App image (build context = repo root) |
| `compose.yml` | Postgres + PostgREST + app |
| `db/init.sql` | Schema + RLS (first DB init only) |
| `app/` | Flask app; `schema.py` upgrades existing volumes |
| `docs/` | Deploy notes and examples |
