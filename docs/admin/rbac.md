# Organisation RBAC Guide

Access control using Kubernetes-style RBAC: subjects, roles, bindings, and
scope hierarchy. Enforcement is in **Postgres RLS** via `api.can()`,
`api.team_role()`, `api.project_role()`, and `api.can_access_secret()`.

---

## 1. Mental model

```
Cluster
 └── Team
      ├── Bindings (User/Group → team-scope role)
      ├── Groups (principals: manual, LDAP, or OIDC)
      └── Project
           ├── Bindings (User/Group → project-scope role)
           └── Secrets
                └── Bindings (User/Group → secret-scope role) + access_mode
```

| Layer | What it controls | How you grant it |
|-------|------------------|------------------|
| **Team** | See team, projects, settings | `rbac.bindings` with team-scope role |
| **Project** | Read/write/admin secrets | `rbac.bindings` with project-scope role |
| **Secret** | Tighter than project (who may list/reveal/edit) | Secret `access_mode` + secret-scope `rbac.bindings` |
| **Global admin** | Everything | `global-admin` cluster-scope binding |

---

## 2. Built-in roles

### Team roles

| Role | Can |
|------|-----|
| `team-owner` | Full team control; delete team; always project admin/write |
| `team-admin` | Manage members, groups, settings; always project admin/write |
| `team-member` | Create projects; write secrets (no reveal — grant separately) |
| `team-viewer` | Read-only (metadata, no plaintext) |

Only `team-owner` can assign the `team-owner` role.

### Project roles

| Role | Can |
|------|-----|
| `project-admin` | Write secrets + manage project/secret role bindings + approval settings |
| `project-write` | Create, update, delete, reveal secrets |
| `project-reveal` | Read + reveal (no edit/create/delete) |
| `project-read` | Read metadata only |

If a user has **no** project-scope binding, access falls back to their team role:

| Team role | Effective project access (no project binding) |
|-----------|-----------------------------------------------|
| `team-owner` / `team-admin` | `project-admin` |
| `team-member` | `project-write` |
| `team-viewer` | `project-read` |

### Secret roles

| Role | Can |
|------|-----|
| `secret-write` | Create, update, delete, reveal |
| `secret-reveal` | Read metadata + reveal plaintext |
| `secret-read` | Read metadata only |

### Machine token (service) roles

| Role | Metadata | Reveal values | Write |
|------|----------|---------------|-------|
| `service-read` | yes | no | no |
| `service-reveal` | yes | yes | no |
| `service-write` | yes | yes | yes |

### Other roles

| Role | Scope | Can |
|------|-------|-----|
| `global-admin` | cluster | Full access (`*` / `*`) — only role with wildcard |
| `audit-viewer` | cluster | Read all audit logs |
| `team-audit-viewer` | team | Read audit logs for a specific team |

---

## 3. Per-secret access

| `access_mode` | Who can access |
|---------------|----------------|
| `inherit` (default) | Project/team bindings via scope chain; secret-scope bindings add grants |
| `restricted` | Only secret-scope bindings + project admins |

**Always full access:** global admins and anyone with `can_admin_project`.

**Machine tokens** (`ss_…`) bypass per-secret human bindings and
reveal-approval (SECURITY DEFINER helpers). Use a **key allow-list** or
**separate project** for sensitive values. See [machine-tokens.md](machine-tokens.md).

### Reveal approval (separate from RBAC)

Optional project default (`require_reveal_approval`) and per-secret override
(`requires_approval`). Sits on top of RBAC: user must already have `reveal`
via RBAC, then also hold a valid approval grant.

---

## 4. Quick setup checklist

```text
1. Bootstrap a global admin (GLOBAL_ADMIN_EMAIL or BOOTSTRAP_ADMIN_EMAIL).
2. Create a team (you become team-owner).
3. Add people (Team → Members): email + role.
4. Create groups (recommended for orgs) — see §5 and §6.
5. Create projects (Team → Projects).
6. Tighten sensitive secrets (access_mode = restricted + bindings).
7. (Optional) Wire LDAP/OIDC.
8. (Optional) Machine / CLI access (machine token or PAT).
```

---

## 5. Groups

Groups are **team-scoped** principals. They are not global across the server.

### Create a group (UI)

1. Open **Team → Groups**.
2. **Create group**:
   - **Name** — human label (e.g. `platform-ops`).
   - **Source** — `manual`, `ldap`, or `oidc`.
   - **External key** — required when source is `ldap`/`oidc`.
   - **Team role** — optional: `team-admin` / `team-member` / `team-viewer` (not `team-owner`).
3. Add members (email) for manual groups. Directory members sync on login.

### When to set a team role on the group

| Goal | Team role on group |
|------|--------------------|
| Group only for project/secret grants | Leave empty (**— none —**) |
| Group should see team + inherit default project access | Set `team-viewer` or `team-member` |
| Group should administer team | Set `team-admin` (groups cannot be `team-owner`) |

### Manual-only group example

**Scenario:** Contractors should write only to project `demo-api`.

```text
1. Team → Groups → create "contractors", source manual, team role none.
2. Add contractor emails as group members.
3. Project demo-api → Access → bind contractors → project-write.
4. They use that project only; they do not inherit other projects.
```

---

## 6. Directory integration (LDAP / OIDC)

### Directory-managed RBAC bindings

| Where | Effect |
|-------|--------|
| Team → Settings → LDAP group membership | Matching LDAP group → directory-managed `rbac.bindings` row |
| Team → Settings → OIDC group membership | Matching OIDC group → directory-managed `rbac.bindings` row |
| Server settings → LDAP/OIDC group → roles | Matching group → `global-admin` |

- Applied on each login. Manual bindings are never overwritten.
- Highest matching role wins if several maps match.

### First-class groups (Team → Groups + external_key)

| Field | LDAP example | OIDC example |
|-------|--------------|--------------|
| source | `ldap` | `oidc` |
| external_key | `cn=platform-admins,ou=groups,dc=example,dc=com` | `platform-admins` |

On login, the app syncs `group_members` for matching `external_key`. Then
grant that group a team, project, or secret role through `rbac.bindings`.

### Recommended org pattern

```text
1. One first-class group per major directory group.
2. Set team role only when the group should open the whole team.
3. Use project-scope bindings for least privilege per app/environment.
4. Use secret-scope bindings + restricted mode for crown-jewel secrets.
5. Keep a small set of manual team-owners for break-glass.
6. Map a directory admin group to global-admin only if you accept full
   server control from that IdP group.
```

---

## 7. How effective access is computed

```
team_role(user, team) =
  global-admin → team-owner
  else max(direct team-scope binding, team-scope binding for groups)

is_team_member = global-admin OR direct member OR in a group with team role

project_role(user, project) =
  max(direct project-scope binding, project-scope binding for groups)
  # may be null → fall back to team role

can_admin_project =
  global-admin OR team_role in (team-owner, team-admin) OR project_role = project-admin

can_write_project =
  can_admin_project
  OR project_role in (project-admin, project-write)
  OR (project_role is null AND team_role = team-member)

can_read_project =
  can_write_project OR project_role is not null OR is_team_member

can_access_secret(secret, need) =
  live secret AND can_read_project
  AND (
    can_admin_project
    OR access_mode = inherit AND api.can(need, 'secrets', scope_chain)
    OR access_mode = restricted AND secret-scope binding with permission >= need
  )
```

Permission rank: `read` < `reveal` < `write`.

---

## 8. Common pitfalls

| Symptom | Likely cause |
|---------|----------------|
| User has directory group but no access | Wrong `external_key`; user has not logged in since map created; team role empty and no project/secret grant |
| Manual member disappeared | They were directory-sourced only and no longer match maps |
| Can see project but not secret value | Secret `access_mode = restricted`; or reveal approval pending |
| Machine token ignores restricted mode | By design — use a separate project or key allow-list |
| `ensure_schema` fails at startup | `DATABASE_ADMIN_URL` must be a superuser DSN |

---

## 9. Minimal "day one" recipe

```text
1. GLOBAL_ADMIN_EMAIL=you@company.com  →  start stack  →  register / SSO as you
2. Create team "Platform"
3. Team → Groups → "eng" (manual or oidc + external_key), team_role = team-member
4. Team → Groups → "sec-leads" (manual), team_role = team-admin
5. Create project "prod-api"
6. Project → Access → bind eng → project-write, sec-leads → project-admin
7. Create secret DB_PASSWORD; leave access_mode inherit
8. Create secret ROOT_CA_KEY; access_mode restricted → bind group sec-leads → secret-reveal
9. Invite break-glass local team-owner on team Members if using SSO for everyone else
```

---

## Related docs

- [rbac-k8s.md](rbac-k8s.md) — K8s RBAC model details
- [deploy.md](deploy.md) — env vars, bootstrap admin, OIDC/LDAP server config
- [authentication.md](authentication.md) — login flows, PAT, machine tokens, JWT
- [machine-tokens.md](machine-tokens.md) — machine accounts, key allow-lists, ESO
- [api.md](../dev/api.md) — secret API, access modes, PostgREST
