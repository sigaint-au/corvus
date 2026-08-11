# Kubernetes-style RBAC

Sigaint Secret Server uses a single access model:

**Subjects** (User, Group, ServiceAccount) + **Roles** (verbs × resources) +
**Bindings** (subject + role + scope).

The RBAC tables are the only authorization source. Team, project, group, and
secret access is represented by `rbac.bindings`; new installations have no
legacy membership or ACL tables. Existing installations are migrated and the
legacy tables are removed during schema ensure. Team creation inserts a
**team-owner** binding for the creator.

## Scope hierarchy

```
cluster → team → project → secret
```

A binding at an ancestor applies to descendants. Evaluation uses
`api.rbac_scope_chain` then `api.can(verb, resource, scope_kind, scope_id)`.

## Built-in roles

| Role | Typical scope | Intent |
|------|---------------|--------|
| `global-admin` | cluster | Full access (`*` / `*`) — only role with wildcard |
| `audit-viewer` | cluster | Read all audit logs |
| `team-owner` | team | Full control of team tree (scoped, not wildcard) |
| `team-admin` | team | Admin without ownership transfer; can read roles |
| `team-member` | team | Create/update secrets (no reveal — grant separately) |
| `team-viewer` | team | Read-only (metadata, no plaintext) |
| `project-admin` | project | Full admin of a single project |
| `project-write` | project | Create, update, reveal secrets |
| `project-reveal` | project | Read + reveal (no edit/create/delete) |
| `project-read` | project | Read metadata only |
| `secret-read` | secret | Read secret metadata (not plaintext) |
| `secret-reveal` | secret | Read metadata + reveal plaintext |
| `secret-write` | secret | Create, update, delete, reveal |
| `team-audit-viewer` | team | Read audit logs for a specific team |
| `service-read` | project | Machine token: metadata only (no plaintext) |
| `service-reveal` | project | Machine token: metadata + plaintext (ESO) |
| `service-write` | project | Machine token: read + write secrets |

**Reveal** is a distinct verb. Approval gating (`api.can_reveal_secret`) still
requires `reveal` via RBAC, then applies the approval layer.

**Team members do not auto-reveal.** Grant `project-write`, `project-reveal`,
or a `secret-reveal` binding to allow reveal.

## Admin UI

| Screen | Path | Who | Purpose |
|--------|------|-----|---------|
| Role bindings | `/rbac/bindings` | Global admin | Bind subject + role at a scope |
| Roles | `/rbac/roles` | Global admin (create) | Built-in catalogue + custom roles |
| Access review | `/rbac/access-review` | Global admin | Who can do X on a resource |
| Team → **Members** | team tab | Team owner/admin | Team-scope bindings (users + groups) |
| Project → **Access** | project tab | Project admin | Project-scope bindings |
| Secret → **Access** | secret view | Project admin | Secret-scope bindings + access mode |

Non-admins do not see Role bindings, Roles, or Access review in the sidebar.

## Team admin: manage access easily

Day-to-day people management uses the **Team → Members** tab (writes
`rbac.bindings` directly):

| Task | Easiest UI |
|------|------------|
| Add a person to the team | **Team → Members** (role Owner/Admin/Member/Viewer) |
| Add a group or service account | **Team → Members** → Advanced |
| Manage groups | **Team → Groups** |
| Project-only access | **Project → Access** |
| Restrict one secret | **Secret → Access** → Restricted + bindings |

## Per-secret access (Access tab)

| Access mode (`acl_mode`) | Behaviour |
|--------------------------|-----------|
| **Inherit** (`inherit`) | Project/team bindings apply via the scope chain. Secret-level bindings add extra grants. |
| **Restricted** (`restricted`) | Only secret-scope bindings (+ project admins) apply. Team/project roles do not. |

Legacy `custom` is treated as `restricted`. Legacy `writers`/`admins`/`owners`
are treated as `inherit`.

**Warning:** switching to Restricted immediately cuts off inherited access
for all users who currently have access via team/project roles (except project
admins). The UI shows a warning before saving.

Project-level `default_acl_mode` sets the default for new secrets.

Reveal approval remains a separate layer after the `reveal` verb.

## Schema

- `rbac.roles`, `rbac.role_rules`, `rbac.bindings` — see `db/rbac.sql`
- Unique index on `bindings(role_id, subject_kind, subject_id, scope_kind, scope_id)`
- `updated_at` / `updated_by` columns on bindings
- Applied by `ensure_schema()` and on fresh volumes via compose `02-rbac.sql`
- Legacy membership and ACL tables are removed during schema ensure
- `can()` rejects deleted secrets at the authorizer level
- Compatibility helpers `can_read_project`, `can_write_project`,
  `can_admin_project`, `can_access_secret`, `team_role`, `project_role` are
  reimplemented on top of `api.can`

## Design notes

### Admin floor (R3)

Anyone for whom `api.can_admin_project(project_id)` is true has **full access**
to every secret in that project. Secret-scope bindings cannot remove it.

### Restricted secrets / no deny list (R1)

RBAC is additive on the scope chain. To **exclude** broader team/project grants
from a sensitive secret, set `acl_mode = restricted`. Then only secret-scope
bindings (+ project admins) apply.

### Role edits (R2 — deferred)

Editing a custom role's rules immediately affects every binding to that role.
Versioning / blast-radius warnings are not implemented yet.

### Performance (R4)

`rbac.bindings` is indexed on `(subject_kind, subject_id)`, `(scope_kind, scope_id)`,
`role_id`, and a unique index. Materialized membership caches are not required
at current scale.
