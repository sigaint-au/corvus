# Sigaint Secret Server

A self-hosted **team secrets store** for people and platforms: team → project →
key/value secrets, enforced with **Postgres Row-Level Security (RLS)**. Ships a
browser UI, an OpenShift External Secrets Operator (ESO) webhook API, a CLI, and
PostgREST for API clients. Secret values are encrypted at rest with `MASTER_KEY`.

This repository is a mirror of https://git.sigaint.au/Sigaint/secretserver

---

## Quick start (local)

```bash
export GLOBAL_ADMIN_EMAIL=you@example.com
ALLOW_INSECURE_DEFAULTS=1 podman-compose up -d --build
# UI: http://localhost:8080  → register as you@example.com (becomes global admin)
# PostgREST: http://localhost:3000
```

For production setup (strong secrets, OIDC/LDAP, audit retention) see
[docs/admin/deploy.md](docs/admin/deploy.md).

---

## Documentation index

Documentation is organised by audience.

### Users

| Doc | Contents |
|-----|----------|
| [docs/user/guide.md](docs/user/guide.md) | Using the UI: teams, projects, secrets, reveal, access requests, metadata, import/export |
| [docs/user/cli.md](docs/user/cli.md) | CLI install + usage (get / apply / reveal / approve / deny) |

### Administrators

| Doc | Contents |
|-----|----------|
| [docs/admin/deploy.md](docs/admin/deploy.md) | Deploy, first-run bootstrap, OpenShift |
| [docs/admin/configuration.md](docs/admin/configuration.md) | All environment variables and server settings |
| [docs/admin/rbac.md](docs/admin/rbac.md) | Roles, groups, project/secret permissions, setup checklist |
| [docs/admin/authentication.md](docs/admin/authentication.md) | Session, PAT, JWT, machine token, OIDC, LDAP, SMTP, password reset |
| [docs/admin/machine-tokens.md](docs/admin/machine-tokens.md) | Machine accounts, key allow-lists, ESO integration |
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
| [docs/dev/contributing.md](docs/dev/contributing.md) | Contribution guide |

---

## Feature summary

| Feature | Description |
|---------|-------------|
| Team / project / secret store | `team → project → key/value`; optional project description |
| Org groups RBAC | Team-scoped groups (manual or LDAP/OIDC-mapped) at team, project, and secret level |
| Per-secret ACLs | Modes: `inherit` / `writers` / `admins` / `owners` / `custom` (user or group grants) |
| Secret metadata | System (created, updated, last accessed) + custom searchable key/values |
| Structured kinds | Plain, database URL, certificate (PEM), SSH key, key/value pairs |
| Browser UI | Bulk actions, trash, version history, search (incl. metadata), pins, mobile nav |
| Postgres RLS | Access control enforced at the database, not just the app |
| Unified secret API | `/eso/v1` with `ss_…` (machine) or `pat_…` (PAT): list, get, create, update, soft-delete |
| PostgREST API | SQL-style API with JWT auth for metadata / org clients |
| ESO integration | Machine API powers OpenShift External Secrets Operator webhooks |
| Personal access tokens | `pat_…` for `/eso/v1` and `/api/token` → PostgREST JWT |
| TOTP 2FA | Per-user 2FA with single-use recovery codes |
| LDAP & OIDC / SSO | Directory groups → team maps, first-class groups, global-admin maps |
| SMTP | Password-reset emails and login alerts |
| Auditing | Secret & org audit logs, access review, export, retention purge |
| Reveal access approval | Project default + per-secret override; time-limited grants (machine/ESO exempt) |
| Secret expiry | Optional per-secret expiry with overdue/soon dashboard |
| Import / export | `.env`, JSON, CSV bulk import and export |
| Classification banner | Optional per-server / per-team banner |
| Server-side sessions | Multi-device sign-out and per-session revocation |
| Login lockout | 5 failed attempts lock out for 5 minutes |

---

## Tests

Unit tests live under `tests/` (not shipped in the container image). They use
**pytest** with a mocked DB — Postgres is not required.

```bash
pip install -r app/requirements.txt -r requirements-dev.txt
pytest
# or: tox -e py
```

See [docs/dev/testing.md](docs/dev/testing.md).

---

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).
