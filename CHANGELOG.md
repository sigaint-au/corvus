# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions use calendar versioning: `<year>-<month>-<day>.<build>` (pip-normalized
form `YYYY.M.D.build`).

## [2026-08-31.2] - 2026-08-31

### Added

- `notify-due` skips secrets with metadata key `exclude-due-notify` (any
  value) — documented in the user guide Metadata section

## [2026-08-31.1] - 2026-08-31

### Added

- `eso_get_secret` supports `?meta=1` — returns secret metadata without
  revealing the value or recording a `revealed` audit event

## [2026-08-23.1] - 2026-08-23

### Changed

- **Rebrand to Corvus**: product name, UI branding, package name (`corvus`),
  compose project/DB/image names, Kubernetes namespace and resource names,
  HSM token label default, Redis cache key prefixes, docs, and CLI examples.
  Compose project/volume names changed: local stacks created as `secretserver`
  should be recreated with `scripts/reset.sh`. Existing Postgres databases
  keep their data and take additive migrations (`0002`–`0006`) in place —
  do not edit released `0001`. Kubernetes namespace rename is an operator
  choice.
- Default brand tagline is `Keep your secrets.`
- `scripts/build.sh` tags and pushes the app image to
  `quay.io/sigaint/corvus` (`<pyproject version>` and `latest`)

### Added

- **RBAC**: `rbac.roles` / `role_rules` / `bindings`, `api.can(verb, resource,
  scope…)`, scope chain cluster→team→project→secret, built-in roles, admin UI
  (Roles, Bindings, Access review). Start-fresh: no data migration from legacy
  membership tables.
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
- **Email verification for local signups**: verification email after signup,
  `/verify-email` page shown on unverified sign-in (no standalone resend route)
- **External Secrets Operator guides** (`docs/admin/external-secrets.md`):
  pull and push setups with example manifests; generic Kubernetes ESO wording
- Kubernetes deploy overlays: kustomize base + overlay how-to (`deploy/`)
- Migration `0005_sql_password_crypt.sql`: bcrypt-in-SQL helpers so databases
  bootstrapped from older baselines can run the current app in place
- Migration `0006_smtp_from_name_corvus.sql`: rewrite leftover branding
  defaults (`smtp_from_name` / `brand_name` / `brand_tagline`) without
  editing `0001`

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
- CI workflows (Forgejo/GitHub Actions): unit tests + pylint on `main`,
  `release`, and tags
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
- Ruff-clean application tree (local `make format`); pylint in CI
  (`tox -e lint`); dedupe color-picker JS into a shared partial and extract
  the HTMX partial-or-redirect tail in secret create/delete

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
- Login no longer 500s at the email-verification gate
- Leftover Sigaint product-name fallbacks in branding, error pages, and docs
- Example overlay image tags pin to `2026.8.23.1` (not `v1.0.0` / an old SHA)
- Copy pass: consistent permission-denied flashes (teams/RBAC), clearer audit
  retention message, sharper auth flashes and transactional emails, tightened
  secrets flash copy; dropped compliance claim from classification banner

## [0.1.0] - 2026-01-01

### Added

- Initial team / project / secret store with Postgres RLS
- Browser UI, machine tokens (`ss_…`), PATs (`pat_…`), `/eso/v1` API
- LDAP/OIDC, TOTP, audit logs, import/export
