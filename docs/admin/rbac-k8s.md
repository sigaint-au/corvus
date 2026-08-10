# Kubernetes-style RBAC

Sigaint Secret Server is moving from separate team / project / secret role
systems to a single model:

**Subjects** (User, Group, ServiceAccount) + **Roles** (verbs × resources) +
**Bindings** (subject + role + scope).

> **Start-fresh:** existing `team_members`, `project_members`, `secret_acl`, and
> machine-token roles are **not** migrated into bindings. New installs and
> upgraded databases get empty bindings plus built-in role definitions. Team
> creation still inserts a **team-owner** binding for the creator (and a legacy
> `team_members` owner row for transitional UI).

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

| Screen | Path | Purpose |
|--------|------|---------|
| Roles | `/rbac/roles` | List built-in / create custom roles |
| Bindings | `/rbac/bindings` | Bind subject + role at a scope (familiar dropdowns) |
| Access review | `/rbac/access-review` | Who can do X on a resource |

## Schema

- `rbac.roles`, `rbac.role_rules`, `rbac.bindings` — see `db/rbac.sql`
- Applied by `ensure_schema()` and on fresh volumes via compose `02-rbac.sql`
- Compatibility helpers `can_read_project`, `can_write_project`,
  `can_admin_project`, `can_access_secret`, `team_role`, `project_role` are
  reimplemented on top of `api.can` (legacy membership tables not consulted
  for authorization).

## Granting access after upgrade

1. Sign in as a **global admin** (still bypasses all checks).
2. Open **Access → Role bindings**.
3. Scope **team**, pick the team, bind users with **Owner** / **Admin** /
   **Member** / **Viewer** (maps to `team-*` roles).
4. Optionally bind at project or secret scopes for tighter grants.

## Per-secret permissions (Permissions tab)

The secret **Permissions** tab manages **secret-scope role bindings**
(`secret-read` / `secret-reveal` / `secret-write`), not the legacy
`api.secret_acl` table.

| Access mode (`acl_mode`) | Behaviour |
|--------------------------|-----------|
| **Inherit** (`inherit`) | Project/team bindings apply via the scope chain. Secret-level bindings add extra grants. |
| **Restricted** (`custom`) | Only secret-scope bindings (+ project admins) apply. Team/project roles do not. |

Reveal approval remains a separate layer after the `reveal` verb.
