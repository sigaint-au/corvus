# Sigaint Secret Server

A small **team secrets store** for people and platforms.

## What it does

- Stores secrets as **team → project → key/value** (Bitwarden-shaped, not a full vault product).
- Lets humans manage secrets in a browser (Flask + HTMX).
- Lets **OpenShift External Secrets Operator** (and other machines) pull secrets with a project-scoped bearer token.
- Enforces access in **Postgres RLS** (not only in the app), with optional **PostgREST** for API clients.
- Supports optional **LDAP** login and group → team role maps.

Values are encrypted at rest with `MASTER_KEY`. Notes are plain labels for search — do not put credentials in notes.

## Why it exists

Teams need a place for shared app secrets that is:

1. **Simpler than enterprise vaults** when you only need projects, membership, and ESO webhooks.
2. **Safe by default at the database** — membership and write rights live in RLS, so a buggy route cannot “just SELECT *”.
3. **Built for the cluster path** — machine accounts for ESO/CI, with **read-only** tokens for fetch and optional **write** tokens for automation upserts.

It is not a password manager for individuals, a full PAM platform, or a multi-cloud secrets fabric. It is a focused secrets server for org teams and OpenShift-style consumers.

## Roles (short)

| Who | Can do |
|-----|--------|
| Team `owner` | Manage members, projects, secrets; **delete team** |
| Team `admin` | Manage members, projects, secrets; **delete projects** |
| Team `member` | Read + write secrets; create projects |
| Team `read-only` | View secrets only |
| Global admin | Server settings, all teams |
| Machine `read-only` | ESO fetch / list |
| Machine `write` | Fetch + machine upsert API |

## Quick start

```bash
# Bootstrap admin: that email becomes global admin on register/login (no first-user race).
export GLOBAL_ADMIN_EMAIL=you@example.com
ALLOW_INSECURE_DEFAULTS=1 podman-compose up -d --build
# UI: http://localhost:8080 — register as you@example.com
```

Without `GLOBAL_ADMIN_EMAIL` (or `BOOTSTRAP_ADMIN_EMAIL`) and no existing admin, registration stays closed until you set one.

Deploy, env vars, ESO examples: **[docs/deploy.md](docs/deploy.md)** · **[docs/openshift-eso.yaml](docs/openshift-eso.yaml)**
