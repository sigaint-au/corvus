<p align="center">
  <img src="app/static/logo.svg" alt="Corvus" width="96">
</p>

# Corvus

Self-hosted secrets management for engineering teams. Centralize credentials,
certificates, and configuration with role-based access control enforced at the
database level, full audit logging, and integrations for CI/CD and Kubernetes.

This repository is a mirror of https://git.sigaint.au/Sigaint/corvus

## Live demo

Open **[https://secretserver-dev.sigaint.au](https://secretserver-dev.sigaint.au)** and sign in with the seeded mock accounts (password is `password` for all of them):

| Role | Email |
|------|-------|
| Global admin | `admin@example.com` |
| Engineer | `alice@example.com` |
| Ops | `bob@example.com` |
| Viewer | `carol@example.com` |
| Contractor | `dave@example.com` |

This instance is for evaluation only. Do not store real secrets there.

## Overview

Corvus organizes access around a `team → project → secret` hierarchy.
Authorization is enforced by PostgreSQL Row-Level Security (RLS), not
application code alone: the database itself rejects rows a caller is not
allowed to read or write. Secret values are encrypted at rest with a managed
master key; projects can optionally use their own dedicated encryption key.

Access is available through three interfaces:

- **Browser UI** for daily operations: search, bulk actions, version history,
  reveal approvals, import/export
- **Unified secret API** (`/eso/v1`) for machines and pipelines, using machine
  tokens or personal access tokens
- **PostgREST API** for SQL-style queries from metadata and org tooling, plus
  an External Secrets Operator webhook provider for Kubernetes

## Key capabilities

**Access control**

- Role-based access control at team, project, and secret scope, backed by
  directory groups over LDAP/OIDC
- Per-secret modes: inherit project permissions, or restrict to explicit
  bindings only
- Reveal approval workflow with time-limited grants
- Personal access tokens and scoped machine accounts with key allow-lists
- TOTP two-factor authentication with single-use recovery codes

**Operations**

- Secret expiry with overdue/soon dashboards
- Soft-delete trash, version history, structured kinds (database URL,
  certificate, SSH key, key/value)
- Custom searchable metadata per secret
- Bulk import/export in `.env`, JSON, and CSV formats
- Audit logs with access review, export, and retention purge
- Optional classification banners per server or team

**Integrations**

- External Secrets Operator: pull (`ExternalSecret`), push (`PushSecret`)
- LDAP and OIDC single sign-on with group mapping
- SMTP notifications: password reset, login alerts, verification emails

## Security model

| Layer | Control |
|-------|---------|
| Encryption | Fernet (AES-128-CBC + HMAC) at rest via `MASTER_KEY`; optional per-project data-encryption keys |
| Authorization | PostgreSQL RLS policies; `SECURITY DEFINER` functions for auth flows |
| Sessions | Server-side sessions with per-device revocation |
| Hardening | Login lockout (5 attempts / 5 minutes), bcrypt password hashing in SQL |

For responsible disclosure, see [SECURITY.md](SECURITY.md).

## Quick start (local)

```bash
export GLOBAL_ADMIN_EMAIL=you@example.com
ALLOW_INSECURE_DEFAULTS=1 podman-compose up -d --build
# UI: http://localhost:8080  → register as you@example.com (becomes global admin)
# PostgREST: http://localhost:3000
```

`ALLOW_INSECURE_DEFAULTS=1` is for local evaluation only. Production deploys
require strong generated secrets; the app refuses to start without them.

To discard local data and reseed:

```bash
scripts/reset.sh       # asks for confirmation
scripts/reset.sh --yes # non-interactive
```

This removes only `pgdata`; HSM state remains in `hsmdata`.

## Deployment

- **Docker / Podman Compose**: see [docs/admin/deploy.md](docs/admin/deploy.md)
- **Kubernetes**: kustomize base + overlays in
  [deploy/README.md](deploy/README.md); worked example in
  [deploy/overlays/corvus-syd/README.md](deploy/overlays/corvus-syd/README.md)

Schema changes ship as ordered SQL migrations applied automatically at startup;
existing databases upgrade in place.

## Documentation

### Users

| Doc | Contents |
|-----|----------|
| [docs/user/guide.md](docs/user/guide.md) | Using the UI: teams, projects, secrets, reveal, access requests, metadata, import/export |
| [docs/user/cli.md](docs/user/cli.md) | CLI install + usage (get / apply / reveal / approve / deny) |

### Administrators

| Doc | Contents |
|-----|----------|
| [docs/admin/deploy.md](docs/admin/deploy.md) | Deploy, first-run bootstrap, Kubernetes |
| [docs/admin/configuration.md](docs/admin/configuration.md) | All environment variables and server settings |
| [docs/admin/rbac.md](docs/admin/rbac.md) | Roles, groups, project/secret permissions, setup checklist |
| [docs/admin/authentication.md](docs/admin/authentication.md) | Session, PAT, JWT, machine token, OIDC, LDAP, SMTP, password reset |
| [docs/admin/machine-tokens.md](docs/admin/machine-tokens.md) | Machine accounts, key allow-lists |
| [docs/admin/external-secrets.md](docs/admin/external-secrets.md) | External Secrets Operator: pull, push, copy-paste YAML |
| [docs/admin/webhooks.md](docs/admin/webhooks.md) | Webhooks: events, payloads, signature verification |
| [docs/admin/audit.md](docs/admin/audit.md) | Audit logs, access review, export, retention |
| [docs/admin/backup.md](docs/admin/backup.md) | Backup and restore |

### Developers

| Doc | Contents |
|-----|----------|
| [docs/dev/architecture.md](docs/dev/architecture.md) | Architecture, components, request flow |
| [docs/dev/database.md](docs/dev/database.md) | Schema, RLS policies, SECURITY DEFINER functions |
| [docs/dev/api.md](docs/dev/api.md) | API reference: `/eso/v1`, PostgREST, app JSON |
| [docs/dev/building.md](docs/dev/building.md) | Build & push container images |
| [docs/dev/testing.md](docs/dev/testing.md) | Running tests and lint |
| [docs/dev/docs-site.md](docs/dev/docs-site.md) | MkDocs documentation site: preview, build, deploy |
| [docs/dev/contributing.md](docs/dev/contributing.md) | Contribution guide |

## Development

Unit tests use pytest against a mocked database; no Postgres required.

```bash
pip install -e ".[dev]"
pytest
```

See [docs/dev/testing.md](docs/dev/testing.md).

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).
Corresponding source is this repository. Third-party works shipped with the
app (htmx, Oat, Python libraries) are listed in [THIRD_PARTY.md](THIRD_PARTY.md).
