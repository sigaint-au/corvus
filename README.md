# Sigaint Secret Server

A small **team secrets store** for people and platforms.

## What it does

- Stores secrets as **team → project → key/value** (with optional structured kinds: plain, database, certificate, SSH, KV).
- Lets humans manage secrets in a browser (Flask + HTMX): multi-select bulk actions, trash, version history, search, pins.
- Lets **OpenShift External Secrets Operator** (and other machines) pull secrets with a project-scoped bearer token (`ss_…`).
- Enforces access in **Postgres RLS** (not only in the app), with optional **PostgREST** for API clients.
- Supports optional **LDAP** and **OIDC / SSO** login, with group → team / global-admin role maps.
- **Personal access tokens** (`pat_…`) for scripts: exchange for a short-lived PostgREST JWT via `/api/token`.
- Optional **TOTP 2FA**, SMTP password-reset / login alerts, and **Administration → Auditing** (export + retention purge).

Values are encrypted at rest with `MASTER_KEY`. Notes are plain labels for search — do not put credentials in notes.

## Why it exists

Teams need a place for shared app secrets that is:

1. **Simpler than enterprise vaults** when you only need projects, membership, and ESO webhooks.
2. **Safe by default at the database** — membership and write rights live in RLS, so a buggy route cannot “just SELECT *”.
3. **Built for the cluster path** — machine accounts for ESO/CI, with **read-only** tokens for fetch and optional **write** tokens for automation upserts.

It is not a password manager for individuals, a full PAM platform, or a multi-cloud secrets fabric. It is a focused secrets server for org teams and OpenShift-style consumers.

## Roles (short)

**Rule:** when a user has a **project role**, that role is authoritative on that project and **overrides** their team default. With no project role, the team role’s default applies.

| Who | Can do |
|-----|--------|
| Team `owner` | Manage members, projects, secrets; **delete team** |
| Team `admin` | Manage members, projects, secrets; **delete projects** |
| Team `member` | Default writer: read + write secrets; create projects |
| Team `viewer` | Read-only default: view secrets only |
| Project `admin` | Write secrets + manage project members (overrides team) |
| Project `write` | Write secrets on that project only (overrides team) |
| Project `read` | Read-only on that project only (can restrict a team member) |
| Global admin | Server settings, all teams, auditing |
| Machine `read-only` | ESO fetch / list |
| Machine `write` | Fetch + machine upsert API |
| User PAT (`pat_…`) | Same as that user under RLS (via JWT) |

## Auth methods

| Method | Prefix / form | Use for |
|--------|----------------|---------|
| Browser session | cookie | UI |
| Personal access token | `pat_…` | Scripts → `GET /api/token` → JWT |
| Short-lived JWT | HS256 JWT | PostgREST (`:3000`) |
| Machine token | `ss_…` | ESO webhook + machine upsert |

## Quick start

```bash
# Bootstrap admin: that email becomes global admin on register/login (no first-user race).
export GLOBAL_ADMIN_EMAIL=you@example.com
ALLOW_INSECURE_DEFAULTS=1 podman-compose up -d --build
# UI: http://localhost:8080 — register as you@example.com
```

Without `GLOBAL_ADMIN_EMAIL` (or `BOOTSTRAP_ADMIN_EMAIL`) and no existing admin, registration stays closed until you set one.

## Documentation

| Doc | Contents |
|-----|----------|
| **[docs/deploy.md](docs/deploy.md)** | Env vars, bootstrap, OIDC/LDAP, audit purge, layout |
| **[docs/api.md](docs/api.md)** | HTTP / machine / PAT / PostgREST API reference |
| **[docs/openshift-eso.yaml](docs/openshift-eso.yaml)** | Sample SecretStore + ExternalSecret |
| **[docs/openshift-purge-audit-cronjob.yaml](docs/openshift-purge-audit-cronjob.yaml)** | Daily audit retention CronJob |
