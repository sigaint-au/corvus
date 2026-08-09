# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/) for
tagged releases.

## [Unreleased]

### Added

- Pytest suite under `tests/` (domain modules) run via `tox -e py`
- CI workflows (Gitea/GitHub Actions): unit tests + pylint
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
