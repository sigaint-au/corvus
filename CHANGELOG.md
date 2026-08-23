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
- **Configurable DoD/policy login banner** on all sign-in pages: new server
  settings `login_banner_enabled` / `_text` / `_link_text` / `_link_url`
  (Server settings → General) with URL validation; plain text only, no HTML
- Themed error pages (400/403/404/405/413/429/500/502/503 + catch-all 500):
  sidebar layout signed-in, auth card signed-out; API/ESO/mgmt and HTMX/JSON
  callers get JSON instead of a page
- Search filter on the machine accounts list
- Reusable empty-state component applied to teams, projects, machine accounts,
  trash, shared/secrets, and global search

### Removed

- Legacy `api.secret_acl` table and `private.secret_acl_rows` (per-secret grants
  are secret-scope `rbac.bindings` only; dropped on schema ensure)
- Legacy secret access-mode values and aliases (`custom`, `writers`, `admins`,
  `owners`): only `inherit` / `restricted` remain; `ensure_schema` scrubs old
  rows and drops leftover `acl_mode` columns

### Changed

- Project **Members** / **Group roles** write **RBAC bindings only** (no dual-write
  to `project_members` / `project_group_roles`); managed on **Project → Access**
- Project reveal-approval tab renamed **Requests**; new **Access** tab for
  project-scope role bindings (shared panel with improved Team Access form)
- Access nav: separate **Role bindings** and **Roles** items again (same page,
  different panels); removed quick-paths blurb
- Team admin RBAC UX: Access nav (Role bindings / Roles / Review) open to all
  signed-in users; **Team → Access** tab; bindings page breadcrumb + scope-aware
  project/group pickers; `can_manage_rbac` allows project admins on secret scope
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
- UI modernisation (oat.ink components, machine accounts table layout)
- Project access helpers simplified (`api.team_role` / `api.project_role`)
- Unit tests moved out of `app/` so the container image stays deploy-only
- Vendor `oat` + `htmx` under `app/static/vendor` and reference them self-hosted
- API JWTs shortened to a 1-hour lifetime (was 24h) so revoked/disabled users
  lose API access within an hour; `/api/token` reflects `expires_in: 3600`
- Clipboard-clear, reveal auto-hide, and reveal access-grant windows are now
  **DB-backed server settings** (Settings → General) instead of env vars;
  deploy-bound config (DB/Redis/crypto/bootstrap/DoS guard) stays env-based
- Login banner layout: plain-text disclosure beside the auth card
  (left-third card layout; centered when banner disabled); on mobile it is a
  fixed bottom bar; subtle dot-matrix tiling on the auth background
- Error/exception layer simplified: secret service raises Werkzeug
  `Forbidden`/`NotFound` directly instead of a wrapping hierarchy that masked
  real errors; `routes/rbac.py` split into a package (helpers/roles/bindings/
  review); `routes/project_io.py` renamed `import_export.py`; shared
  `db.team()` and `paging.paged_rows()` helpers
- Tree is mypy- and ruff-clean (enforced); pylint 10.00/10; dedupe
  color-picker JS into a shared partial and extract the HTMX
  partial-or-redirect tail in secret create/delete

### Fixed

- PostgREST RBAC gaps (FORCE RLS, project update policy, owner assignment)
- Full secret page now stamps `last_accessed_*` on reveal
- Team switch from another project’s secrets view no longer no-ops
- Pager controls and various mobile / label UX issues
- Screenshot filename: `login-classification-banner.png`
- LDAP authentication now verifies the server TLS certificate (no MITM-prone
  blind TLS); permanent trash purge requires project admin
- Leftover `</script><script>` wrappers in `app.js` broke sidebar group
  persistence (SyntaxError)
- Vendored `oat.min.css` SRI hash typo made browsers refuse the stylesheet;
  regression test guards the HTMX `<script>` tag close
- Server-opened sidebar sections (e.g. Organisation → Role bindings) no longer
  collapse when navigating to pages whose endpoint default differs

## [0.1.0] - 2026-01-01

### Added

- Initial team / project / secret store with Postgres RLS
- Browser UI, machine tokens (`ss_…`), PATs (`pat_…`), `/eso/v1` API
- LDAP/OIDC, TOTP, audit logs, import/export
