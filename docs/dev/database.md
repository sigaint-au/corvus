# Database & RLS Reference

Schema, Row-Level Security policies, and the SECURITY DEFINER functions that
enforce access control.

---

## Schema management

Schema DDL is maintained in the squashed `db/migrations/0001_init.sql` baseline
and applied by the migration runner (`app/core/migrations.py`).

- **Fresh installs** run the baseline via `docker-entrypoint-initdb.d` (mounted
  by `compose.yml`):
  `db/migrations/0001_init.sql` (mounted as `01-init.sql`): the complete squashed schema,
  functions, policies, grants, and security hardening.
- **Every startup** the app checks migrations via `migrations.apply_pending()`
  (requires `DATABASE_ADMIN_URL`), serialized by a `pg_advisory_lock`. It seeds
  the `0001` baseline as applied, then applies any newer numbered migrations (e.g.
  `0002_rls_authz_hardening.sql`). Versions and sha256 checksums are recorded in
  `private.schema_migrations`.
- This branch uses a **fresh-install-only squash**. Existing databases must be
  recreated; there is no compatibility upgrade path from older schemas.

> Do **not** edit an already-released migration file. Its checksum is recorded
> and drift fails startup. Add a new numbered migration instead.

### Baseline files

| File | Contains | Does NOT contain |
|------|----------|------------------|
| `0001_init.sql` | Complete squashed schema and security baseline | None |
| `0002_rls_authz_hardening.sql` | Additive RLS / authz hardening (pin `project.team_id`, guard secret/team-owner updates, restrict admin assignment) | Schema DDL for new tables |

The squashed `0001` file preserves the original dependency order internally. Do
not split it into new numbered files without defining a replacement upgrade plan.

### Adding a migration

Create `db/migrations/NNNN_slug.sql` (zero-padded, next number), make it
idempotent where possible, and run the test/lint checks. It is applied by
`migrations.apply_pending()` at startup. For fresh-only development databases
you may instead edit `0001_init.sql` directly and recreate the volume. Do not
apply this baseline to an existing database.

---

## Roles

| Role | Purpose |
|------|---------|
| `authenticator` | App connection role (NOINHERIT LOGIN) |
| `anon` | Unauthenticated (PostgREST) |
| `authenticated` | Logged-in users; RLS applies |

The app connects as `authenticator`, then `SET ROLE authenticated` and sets
`request.jwt.claims` (`sub` = user id).

---

## Schemas

| Schema | Contents |
|--------|----------|
| `api` | Public tables, views, RLS policies, access helpers (PostgREST surface) |
| `private` | Users, sessions, tokens, settings, SECURITY DEFINER helpers (not exposed to PostgREST) |
| `rbac` | RBAC tables: `roles`, `role_rules`, `bindings` |

---

## Core tables

| Table | Schema | Purpose |
|-------|--------|---------|
| `teams` | api | Teams and settings |
| `projects` | api | Projects and settings |
| `groups` / `group_members` | api | Team-scoped groups + membership |
| `secrets` | api | Secret rows (`value_enc` = Fernet ciphertext; `crypto_provider` records which key) |
| `project_crypto_keys.hsm_slot_id` | uuid FK → `hsm_slots` | NULL = legacy pre-named-slot HSM row; non-NULL = named slot's KEK wraps the DEK |
| `secret_versions` | api | Archived prior ciphertext on update (also carries `crypto_provider`) |
| `secret_meta` | api | Custom searchable metadata |
| `secret_access_requests` | api | Reveal-approval requests + grants |
| `secret_audit` / `org_audit` | api | Append-only audit |
| `machine_tokens` | api | Machine tokens (hash only) |
| `machine_token_scope` | api | Per-token key allow-lists |
| `secret_pins` / `secret_recent` | api | User pins / recent |
| `roles` / `role_rules` / `bindings` | rbac | K8s-style RBAC |
| `project_crypto_keys` | private | Per-project BYOK data-encryption keys (wrapped by MASTER_KEY or a named HSM slot) |
| `hsm_slots` | private | Named PKCS#11 URL slot configurations (multi-HSM) |
| `users` | private | Users (not exposed) |
| `user_sessions` | private | Server-side sessions |
| `personal_access_tokens` | private | PATs (hash only) |

---

## RBAC tables

### `rbac.roles`

| Column | Type | Purpose |
|--------|------|---------|
| `id` | uuid PK | Role id |
| `name` | text UNIQUE | Role name (e.g. `team-owner`, `project-write`) |
| `description` | text | Human-readable description |

### `rbac.role_rules`

| Column | Type | Purpose |
|--------|------|---------|
| `role_id` | uuid FK → roles | Role this rule belongs to |
| `resources` | text[] | Resource types (e.g. `['secrets']`, `['*']`) |
| `verbs` | text[] | Allowed verbs (e.g. `['get','list','reveal']`) |

### `rbac.bindings`

| Column | Type | Purpose |
|--------|------|---------|
| `id` | uuid PK | Binding id |
| `role_id` | uuid FK → roles | Role granted |
| `subject_kind` | text | `User`, `Group`, or `ServiceAccount` |
| `subject_id` | uuid | User/group id |
| `scope_kind` | text | `cluster`, `team`, `project`, or `secret` |
| `scope_id` | uuid | Scope id (null for cluster) |
| `source` | text | `manual`, `ldap`, or `oidc` |
| `updated_at` | timestamptz | Last update |
| `updated_by` | uuid | Who last updated |

Unique index on `(role_id, subject_kind, subject_id, scope_kind, scope_id)`.

---

## RLS helpers (SECURITY DEFINER)

All helpers set `SET search_path = api, private` and `SET row_security = off`.
Defined in the `0001_init.sql` baseline.

| Function | Returns |
|----------|---------|
| `api.current_user_id()` | User id from JWT `sub` claim |
| `api.is_global_admin()` | Whether current user is a global admin |
| `api.is_team_member(tid)` | Direct member OR in a group with a team role |
| `api.team_role(tid)` | Highest team role (`team-owner`/`team-admin`/`team-member`/`team-viewer`) |
| `api.project_role(pid)` | Highest project role or null |
| `api.can_read_project(pid)` | Read access |
| `api.can_write_project(pid)` | Write access |
| `api.can_admin_project(pid)` | Admin access |
| `api.can_manage_rbac(scope_kind, scope_id)` | Can manage bindings at scope |
| `api.can_access_secret_row(sid,pid,mode,need,deleted_at)` | Secret access (safe for INSERT…RETURNING) |
| `api.can_access_secret(sid,need)` | Loads row then applies `can_access_secret_row` |
| `api.can_reveal_secret(sid)` | Can reveal now (RBAC + approval + grant) |
| `api.secret_requires_approval(sid)` | Effective approval policy |
| `api.can(verb, resource, scope_kind, scope_id)` | Core RBAC check via scope chain; subject overrides are limited to the current user or global admins |
| `api.rbac_scope_chain(scope_kind, scope_id)` | Returns scope chain CTE |
| `api.rbac_subjects(user_id)` | Returns subject rows for the current user; another user requires global-admin authorization |
| `api.my_access_rows()` | User's own bindings across scopes |
| `api.effective_access_rows(scope_kind, scope_id)` | Who can access a resource and why |

---

## HSM slot RPC security

`private.hsm_slots` is never exposed as a table to PostgREST. The migration
The squashed baseline applies these HSM protections:

- `api.list_hsm_slots()` is unavailable to `anon`; authenticated callers receive
  slot metadata with `pkcs11_url = null`, while global-admin calls may receive the
  URL for the admin UI.
- `api.hsm_slot_url(uuid)` is revoked from PostgREST roles. Internal crypto and
  admin code read the private table through privileged application connections;
  the unused RPC is no longer exposed.
- `api.hsm_slot_upsert` and `api.hsm_slot_delete` require a global admin, and the
  write RPCs are not executable by `anon`.
- A slot URL cannot change while project keys reference that slot. Use a new slot
  and migrate the projects instead.

The baseline also includes the remaining database-boundary controls:

- `PUBLIC` function execution is revoked from the `api` schema; functions must
  be explicitly granted to `anon`, `authenticated`, or `authenticator`.
- `PUBLIC` function execution is also revoked from the `rbac` schema; only the
  startup role-seeding function is granted to `authenticator`.
- `machine_tokens.token_hash` is not selectable by `authenticated`; only token
  metadata columns are exposed.
- Access requests must reference a secret in the same project and cannot have
  their identity fields rewritten after creation.
- RBAC bindings enforce the same role/scope compatibility as the web UI.
- All API tables use `FORCE ROW LEVEL SECURITY`. PostgreSQL superusers still
  bypass RLS, so user-scoped application code must use `db.as_user()` rather
  than `db.connect_admin()`.

---

## RLS policies

All RLS policies are defined in the `0001_init.sql` baseline. Every `api` table
has `ENABLE` (and sensitive tables `FORCE`) ROW LEVEL SECURITY with
`USING`/`WITH CHECK` policies for `authenticated`.

| Table | Policy highlights |
|-------|-------------------|
| `teams` | select: team member; insert: creator/global-admin; update: team-owner/team-admin; delete: team-owner |
| `projects` | select: `can_read_project`; update: `can_admin_project`; delete: team-owner/team-admin |
| `rbac.bindings` | select: scope manager or subject; write: `can_manage_rbac` |
| `rbac.roles` / `role_rules` | select: all authenticated; write: global admin |
| `groups` / `group_members` | team-owner/team-admin manage; members select |
| `secrets` | select/update/delete: `can_access_secret_row`; insert: `can_write_project` |
| `secret_versions` | select: parent readable; **no client insert** (trigger-only) |
| `secret_access_requests` | select: project-admin or self; insert: self + can_read; update: project-admin |
| `secret_audit` / `org_audit` | select only; no client insert |
| `machine_tokens` | select: can_read; insert/delete: can_write |
| `machine_token_scope` | project-admin manages; members select |

---

## SECURITY DEFINER functions (private)

Machine/auth helpers run as the function owner and bypass RLS. Gated on token
hash and granted only to `authenticator` (not `authenticated`).

| Function | Purpose |
|----------|---------|
| `private.auth_machine(project, hash)` | Validate machine token (hash + expiry) |
| `private.machine_role(project, hash)` | Machine role (`service-read`/`service-reveal`/`service-write`) |
| `private.machine_get_row` / `machine_list_enc` / `machine_list_meta` | Read secrets (respects token scope) |
| `private.machine_delete` / `machine_upsert_enc` | Write secrets (service-write role) |
| `private.audit_secret` / `audit_org` | Append-only audit (actor from JWT) |
| `private.register_user` / `verify_user` / `change_password` | Auth |
| `private.lookup_user` | Email → user id (app only) |
| `private.team_group_rows` / `group_member_rows` | Group listing (calls `is_team_member`) |
| `private.secret_meta_rows` | Secret metadata (calls `can_access_secret`) |
| `private.secret_access_request_rows` | Access requests (calls `can_admin_project`) |
| `private.pending_access_requests_for_admin` | Pending requests for admin |

> Functions that call RBAC auth helpers are `LANGUAGE plpgsql` (deferred
> validation) so they can be created before the auth functions they call
> are defined later in the same baseline.

---

## Machine token scopes

`api.machine_token_scope` stores exact keys and/or glob patterns per token.
The machine read functions filter by scope; an empty scope = all keys.

```sql
-- example scope rows
INSERT INTO api.machine_token_scope (token_id, secret_key) VALUES (tok, 'API_KEY');
INSERT INTO api.machine_token_scope (token_id, key_pattern) VALUES (tok, 'prod/*');
```

---

## Audit integrity

- `api.secret_audit` / `api.org_audit` have **no client INSERT** policy and
  `REVOKE INSERT` from `authenticated`.
- Writes go through `private.audit_secret` / `private.audit_org`, which derive
  the actor from JWT claims and ignore caller-supplied `user_id`.

---

## Related docs

- [architecture.md](architecture.md): request flow
- [../admin/rbac.md](../admin/rbac.md): access rules in plain terms
- [../admin/byok.md](../admin/byok.md): per-project encryption keys (BYOK)
- [hsm.md](hsm.md): external HSM (SoftHSM2) key management for BYOK
- [rbac-k8s.md](../admin/rbac-k8s.md): K8s RBAC model
- [api.md](api.md): API reference
