# Kubernetes-style RBAC

Sigaint Secret Server is moving from separate team / project / secret role
systems to a single model:

**Subjects** (User, Group, ServiceAccount) + **Roles** (verbs × resources) +
**Bindings** (subject + role + scope).

> **Start-fresh:** existing `team_members` / `project_members` and machine-token
> roles are **not** migrated into bindings automatically (membership UIs dual-write
> going forward). The legacy `api.secret_acl` table is **dropped**; per-secret
> grants use secret-scope `rbac.bindings`. New installs get built-in roles plus
> empty bindings. Team creation still inserts a **team-owner** binding for the
> creator (and a transitional `team_members` owner row for the Members UI).

## Scope hierarchy

```
cluster → team → project → secret
```

A binding at an ancestor applies to descendants. Evaluation uses
`api.rbac_scope_chain` then `api.can(verb, resource, scope_kind, scope_id)`.

## Built-in roles

| Role | Typical scope | Intent |
|------|---------------|--------|
| `cluster-admin` | cluster | Full access (`*` / `*`) |
| `audit-viewer` | cluster / team | Read audit |
| `team-owner` | team | Full control of team tree |
| `team-admin` | team | Admin without ownership transfer semantics |
| `team-member` | team | Write secrets; list projects |
| `team-viewer` | team | Read-only |
| `project-admin` / `project-write` / `project-read` | project | Classic project roles |
| `secret-read` / `secret-reveal` / `secret-write` | secret | Fine-grained secret access |
| `service-readonly` / `service-write` | project | Machine tokens |

**Reveal** is a distinct verb. Approval gating (`api.can_reveal_secret`) still
requires `reveal` via RBAC, then applies the approval layer.

## Admin UI

| Screen | Path | Who | Purpose |
|--------|------|-----|---------|
| Role bindings | `/rbac/bindings` | Team/project admins + global | Bind subject + role at a scope |
| Roles | `/rbac/bindings?panel=roles` (or `/rbac/roles`) | Global admin (create) | Built-in catalogue + custom roles |
| Access review | `/rbac/access-review` | Anyone who can open Access | Who can do X on a resource |
| Team → **Access** | team tab | Team owner/admin | Team-scope bindings |
| Project → **Access** | project tab | Project admin | Project-scope bindings |
| Secret → **Permissions** | secret view | Project admin | Secret-scope bindings + access mode |

## Team admin: manage RBAC easily

Day-to-day people management still uses familiar tabs (they dual-write
`rbac.bindings`):

| Task | Easiest UI |
|------|------------|
| Add a person to the team | **Team → Members** (role owner/admin/member/viewer) |
| Manage groups | **Team → Groups** |
| Project-only access | **Project → Settings → Members** |
| Advanced (group as subject, SA, extra roles) | **Team → Access** or **Access → Role bindings** |
| Restrict one secret | **Secret → Permissions** → Restricted + bindings |

Authorization for binding writes uses `api.can_manage_rbac(scope, id)`:
team owner/admin for team scope; project admin for project/secret scopes;
global admin for cluster.

## Schema

- `rbac.roles`, `rbac.role_rules`, `rbac.bindings` — see `db/rbac.sql`
- Applied by `ensure_schema()` and on fresh volumes via compose `02-rbac.sql`
- **`api.secret_acl` is dropped** on ensure (no dual-write)
- Compatibility helpers `can_read_project`, `can_write_project`,
  `can_admin_project`, `can_access_secret`, `team_role`, `project_role` are
  reimplemented on top of `api.can` (legacy membership tables not consulted
  for authorization).

## Granting access after upgrade

1. Sign in as a **global admin** (still bypasses all checks), or as a team
   owner if bindings already exist for that team.
2. Open **Access → Role bindings** (or **Team → Access**).
3. Scope **team**, pick the team, bind users with **Owner** / **Admin** /
   **Member** / **Viewer** (maps to `team-*` roles).
4. Optionally bind at project or secret scopes for tighter grants.
   Custom roles: **Access → Roles** (global admin).

## Per-secret permissions (Permissions tab)

The secret **Permissions** tab manages **secret-scope role bindings**
(`secret-read` / `secret-reveal` / `secret-write`). The old `api.secret_acl`
table is gone.

| Access mode (`acl_mode`) | Behaviour |
|--------------------------|-----------|
| **Inherit** (`inherit`) | Project/team bindings apply via the scope chain. Secret-level bindings add extra grants. |
| **Restricted** (`custom`) | Only secret-scope bindings (+ project admins) apply. Team/project roles do not. |

Reveal approval remains a separate layer after the `reveal` verb.

## Design notes (review)

### Admin floor (R3)

Anyone for whom `api.can_admin_project(project_id)` is true has **full access**
to every secret in that project (`can_access_secret_row` short-circuits to true).
Project-admin / team-owner-or-admin bindings imply that floor. Secret-scope
bindings cannot remove it.

### Exclusive secrets / no pure deny list (R1)

RBAC is additive on the scope chain. To **exclude** broader team/project grants
from a sensitive secret (crown-jewel), set `acl_mode = custom` (**Restricted** on
the Permissions tab). Then only secret-scope bindings (+ project admins) apply —
team/project roles are ignored for that secret. There is no separate deny ACE.

### Role edits (R2 — deferred)

Editing a custom role’s rules immediately affects every binding to that role.
Versioning / blast-radius warnings are not implemented yet.

### Performance (R4)

`rbac.bindings` is indexed on `(subject_kind, subject_id)`, `(scope_kind, scope_id)`,
and `role_id`. Materialized membership caches are not required at current scale.
