# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/) for
tagged releases.

## [Unreleased]

### Added

- **Kubernetes-style RBAC** (branch `feature/k8s-rbac`): `rbac.roles` /
  `role_rules` / `bindings`, `api.can(verb, resource, scope…)`, scope chain
  cluster→team→project→secret, built-in roles, admin UI (Roles, Bindings,
  Access review). Start-fresh: no data migration from legacy membership tables.
- Pytest suite under `tests/` (domain modules) run via `tox -e py`

### Changed

- Regenerated `docs/postgrest-openapi.json` from live PostgREST (authenticated
  role): groups, secret ACL/meta/access requests, machine token scope,
  project description / ACL / last_accessed columns, new `api.can_*` RPCs
- `can_*` / `team_role` / `project_role` helpers evaluate RBAC bindings (legacy
  tables retained but not used for authorization on this branch)

- CI workflows (Forgejo/GitHub Actions): unit tests + pylint
- `SECURITY.md`, `CONTRIBUTING.md`, and this changelog
- Machine token key allow-list (exact keys + `*` / `?` globs)
- Team secrets / projects list pagination and filters
- Secret Metadata tab (last accessed, custom fields)
- Org RBAC: team-scoped groups (manual / LDAP / OIDC maps)
- Per-secret ACL modes and reveal-approval workflow

### Changed

- UI modernisation (oat.ink components, machine accounts table layout)
- Project access helpers simplified (`api.team_role` / `api.project_role`)
- Unit tests moved out of `app/` so the container image stays deploy-only

### Fixed

- PostgREST RBAC gaps (FORCE RLS, project update policy, owner assignment)
- Full secret page now stamps `last_accessed_*` on reveal
- Team switch from another project’s secrets view no longer no-ops
- Pager controls and various mobile / label UX issues
- Screenshot filename: `login-classification-banner.png`

## [0.1.0] - 2026-01-01

### Added

- Initial team / project / secret store with Postgres RLS
- Browser UI, machine tokens (`ss_…`), PATs (`pat_…`), `/eso/v1` API
- LDAP/OIDC, TOTP, audit logs, import/export
