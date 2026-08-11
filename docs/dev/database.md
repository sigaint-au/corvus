# Database & RLS Reference

Schema, Row-Level Security policies, and the SECURITY DEFINER functions that
enforce access control.

---

## Schema management

- **Fresh installs** use `db/init.sql` (creates roles, schemas, tables, RLS,
  functions).
- **Existing databases** are upgraded by `ensure_schema()` in `app/schema.py`
  at app startup (requires `DATABASE_ADMIN_URL`). It is idempotent and must
  mirror `init.sql`.

> Do **not** re-run `init.sql` over an existing database — use `schema.py`.

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

---

## Core tables

| Table | Purpose |
|-------|---------|
| `api.teams` | Teams and settings |
| `api.projects` | Projects and settings |
| `api.groups` / `api.group_members` | Team-scoped groups + membership |
| `rbac.roles` / `rbac.role_rules` / `rbac.bindings` | User, group, and machine-account access at cluster/team/project/secret scopes |
| `api.secrets` | Secret rows (`value_enc` = Fernet ciphertext) |
| `api.secret_versions` | Archived prior ciphertext on update |
| `api.secret_meta` | Custom searchable metadata |
| `rbac.roles` / `rbac.role_rules` / `rbac.bindings` | K8s-style RBAC (incl. secret-scope grants) |
| `api.secret_access_requests` | Reveal-approval requests + grants |
| `api.secret_audit` / `api.org_audit` | Append-only audit |
| `api.machine_tokens` | Machine tokens (hash only) |
| `api.machine_token_scope` | Per-token key allow-lists |
| `api.secret_pins` / `api.secret_recent` | User pins / recent |
| `private.users` | Users (not exposed) |
| `private.user_sessions` | Server-side sessions |
| `private.personal_access_tokens` | PATs (hash only) |

---

## RLS helpers (SECURITY DEFINER)

All helpers set `SET search_path = api, private` and `SET row_security = off`
(to avoid RLS recursion), and are granted to `authenticated`/`anon`.

| Function | Returns |
|----------|---------|
| `api.current_user_id()` | User id from JWT `sub` claim |
| `api.is_global_admin()` | Whether current user is a global admin |
| `api.is_team_member(tid)` | Direct member OR in a group with a team role |
| `api.team_role(tid)` | Highest team role (owner/admin/member/viewer) |
| `api.project_role(pid)` | Highest project role (admin/write/read) or null |
| `api.can_read_project(pid)` | Read access |
| `api.can_write_project(pid)` | Write access |
| `api.can_admin_project(pid)` | Admin access |
| `api.can_access_secret_row(sid,pid,mode,need,deleted_at)` | Secret access using inherited or restricted RBAC bindings (safe for INSERT…RETURNING) |
| `api.can_access_secret(sid,need)` | Loads row then applies `can_access_secret_row` |
| `api.can_reveal_secret(sid)` | Can reveal now (ACL + approval + grant) |
| `api.secret_requires_approval(sid)` | Effective approval policy |

---

## RLS policies

Every `api` table has `ENABLE` (and sensitive tables `FORCE`) ROW LEVEL
SECURITY with `USING`/`WITH CHECK` policies for `authenticated`. Key ones:

| Table | Policy highlights |
|-------|-------------------|
| `teams` | select: member/admin; update: owner/admin; delete: owner |
| `projects` | select: RBAC-readable; update: `can_admin_project`; delete: owner/admin |
| `rbac.bindings` | select: scope manager or subject; write: `can_manage_rbac` |
| `groups` / `group_members` | owner/admin manage; members select |
| `secrets` | select/update/delete: `can_access_secret_row`; insert: `can_write_project` |
| `secret_versions` | select: parent readable; **no client insert** (trigger-only) |
| `rbac.bindings` | select: manage scope or self subject; write: `can_manage_rbac` |
| `secret_access_requests` | select: admin or self; insert: self + can_read; update: admin |
| `secret_audit` / `org_audit` | select only; no client insert |
| `machine_tokens` | select: can_read; insert/delete: can_write |
| `machine_token_scope` | admin manages; members select |

---

## SECURITY DEFINER functions (private)

Machine / auth helpers run as the function owner and bypass RLS; they are
gated on the token hash and granted only to `authenticator` (not
`authenticated`), so users cannot call them directly via PostgREST.

| Function | Purpose |
|----------|---------|
| `private.auth_machine(project, hash)` | Validate machine token (hash + expiry) |
| `private.machine_role(project, hash)` | Machine-account role (read/reveal/write) |
| `private.machine_get_row` / `machine_list_enc` / `machine_list_meta` | Read secrets (respects token scope) |
| `private.machine_delete` / `machine_upsert_enc` | Write secrets (write role) |
| `private.audit_secret` / `audit_org` | Append-only audit (actor from JWT, never caller) |
| `private.register_user` / `verify_user` / `change_password` | Auth |
| `private.lookup_user` | Email → user id (app only) |

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
  the actor from JWT claims and ignore caller-supplied `user_id` (defense
  against forged attribution).

---

## Related docs

- [architecture.md](architecture.md) — request flow
- [rbac.md](../admin/rbac.md) — access rules in plain terms
- [api.md](api.md) — API reference
