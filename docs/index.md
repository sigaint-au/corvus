# Corvus

Self-hosted secrets management for engineering teams. Centralize credentials,
certificates, and configuration with role-based access control enforced at the
database level, full audit logging, and integrations for CI/CD and Kubernetes.

Access is organized around a `team → project → secret` hierarchy. Authorization
is enforced by PostgreSQL Row-Level Security (RLS): the database itself rejects
rows a caller is not allowed to read or write. Secret values are encrypted at
rest; projects can optionally use their own dedicated encryption key.

Three interfaces cover every workflow:

- **Browser UI** — daily operations: search, bulk actions, version history,
  reveal approvals, import/export
- **Unified secret API** (`/eso/v1`) — machines and pipelines via machine
  tokens or personal access tokens
- **PostgREST API** — SQL-style queries for metadata and org tooling, plus an
  External Secrets Operator webhook provider for Kubernetes

## Where to start

| Task | Start here |
|------|------------|
| Evaluate locally | [Deployment → Quick start](admin/deploy.md) |
| Production deploy (Compose or Kubernetes) | [Deployment](admin/deploy.md), [Kubernetes overlays](https://git.sigaint.au/Sigaint/corvus/src/branch/main/deploy/README.md) |
| Set up roles and permissions | [Access control](admin/rbac.md) |
| Connect SSO / LDAP / OIDC | [Authentication](admin/authentication.md) |
| Sync secrets into Kubernetes | [External Secrets Operator](admin/external-secrets.md) |
| Operate: backup, audit, upgrades | [Backup](admin/backup.md), [Audit](admin/audit.md), [Upgrades](admin/deploy.md#upgrades) |
| Daily use in the UI or CLI | [User guide](user/guide.md), [CLI](user/cli.md) |
| Integrate an application | [API reference](dev/api.md) |

## Security disclosures

For responsible disclosure, see
[SECURITY.md](https://git.sigaint.au/Sigaint/corvus/src/branch/main/SECURITY.md).

## License

[GNU Affero General Public License v3.0](https://git.sigaint.au/Sigaint/corvus/src/branch/main/LICENSE) (AGPL-3.0).
Third-party notices: [THIRD_PARTY.md](https://git.sigaint.au/Sigaint/corvus/src/branch/main/THIRD_PARTY.md).
