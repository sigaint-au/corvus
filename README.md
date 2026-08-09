# Sigaint Secret Server

A small **team secrets store** for people and platforms: team, project,
key/value secrets with Postgres RLS enforcement, a browser UI, OpenShift
External Secrets Operator (ESO) webhooks, and PostgREST for API clients.
Values are encrypted at rest with `MASTER_KEY`.

This repository is a mirror of [https://git.sigaint.au/Sigaint/secretserver](https://git.sigaint.au/Sigaint/secretserver).

## Quick start

```bash
export GLOBAL_ADMIN_EMAIL=you@example.com
ALLOW_INSECURE_DEFAULTS=1 podman-compose up -d --build
# UI: http://localhost:8080; register as you@example.com
```

See [docs/deploy.md](docs/deploy.md) for production setup (strong secrets,
OIDC/LDAP, audit retention).

## Documentation

| Doc | Contents |
|-----|----------|
| **[docs/deploy.md](docs/deploy.md)** | Deploy, env vars, bootstrap, OIDC/LDAP, audit purge |
| **[docs/authentication.md](docs/authentication.md)** | Every auth flow (session, PAT, machine, JWT, OIDC, LDAP) + curl examples |
| **[docs/building.md](docs/building.md)** | Build & push the app container image (Docker/Podman/OpenShift) |
| **[docs/api.md](docs/api.md)** | API reference — **manage secrets via CLI/CI** (list/get/create/update/delete), ESO, PAT, PostgREST |
| **[docs/openshift-eso.yaml](docs/openshift-eso.yaml)** | Sample SecretStore + ExternalSecret |
| **[docs/openshift-purge-audit-cronjob.yaml](docs/openshift-purge-audit-cronjob.yaml)** | Daily audit retention CronJob |

### Manage secrets from the CLI

Unified **`/eso/v1`** API accepts **machine tokens** (`ss_…`) or **PATs**
(`pat_…`). Full details:
[docs/api.md — Managing secrets](docs/api.md#managing-secrets-via-the-unified-api-esov1).

```bash
# Official CLI (sibling secretserver-cli/)
secretserver login --url http://localhost:8080 --token ss_… --project <uuid>
# or: --token pat_… --project ios-app
secretserver list && secretserver get API_KEY

# curl
export SS_URL=http://localhost:8080 SS_TOKEN=ss_… SS_PROJECT=<project-uuid>
AUTH=(-H "Authorization: Bearer $SS_TOKEN")
curl -s "${AUTH[@]}" "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets?meta=1"
curl -s "${AUTH[@]}" "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets/API_KEY"
```

## Features

| Feature | Description |
|---------|-------------|
| Team / project / secret store | Organise secrets as **team / project / key/value** |
| Per-secret ACLs | Restrict a secret beyond project membership (writers / admins / owners / custom user list) |
| Structured secret kinds | Plain, database URL, certificate (PEM), SSH key, key/value pairs |
| Browser UI | Bulk actions, trash, version history, search, pins |
| Postgres RLS enforcement | Access control at the database, not just the app |
| Unified secret API (`/eso/v1`) | `ss_…` or `pat_…`: list, get, create, update, soft-delete (plaintext) |
| PostgREST API | SQL-style API with JWT auth for metadata / org clients |
| ESO integration | Same machine API powers OpenShift External Secrets Operator webhooks |
| Personal access tokens | `pat_…` for `/eso/v1` secrets (RLS) and `/api/token` → PostgREST JWT |
| TOTP 2FA | Per-user 2FA with single-use recovery codes |
| LDAP & OIDC / SSO | Group to team role / global-admin maps |
| SMTP | Password-reset emails and login alerts |
| Auditing | Secret & org audit logs, access review, export, retention purge |
| Secret expiry | Optional per-secret expiry with overdue/soon dashboard |
| Import / export | `.env`, JSON, CSV bulk import and export with audit trail |
| Classification banner | Optional per-server / per-team banner (e.g. OFFICIAL) |
| Server-side sessions | Multi-device sign-out and per-session revocation |
| Login lockout | 5 failed attempts lock out for 5 minutes |

## Screenshots

![Login with classification banner](docs/images/login-classiification-banner.png)

![Secrets dashboard](docs/images/secrets-dashboard.png)

![Secret revealed inline](docs/images/secret-inline-show.png)

![Certificate secret view](docs/images/secret-show-cert.png)

![Projects list](<docs/images/projects list.png>)

![Search](docs/images/search.png)

![Profile / security](docs/images/profile.png)

![Server settings](docs/images/settings.png)

![Auditing](docs/images/audit.png)

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).
