# Organisation RBAC Guide

How access control works and how to set it up for a real organisation: users,
groups (manual or directory-synced), and permissions at team, project, and
secret level.

Enforcement is in **Postgres RLS** via helpers such as `api.is_team_member`,
`api.team_role`, `api.project_role`, `api.can_read|write|admin_project`, and
`api.can_access_secret`. The UI and APIs call the same helpers — there is no
separate "app-only" ACL.

---

## 1. Mental model

```
Organisation
 └── Team
      ├── Members (direct user → team role)
      ├── Groups (principals: users and/or LDAP/OIDC)
      │    ├── optional team_role  → members inherit team access
      │    └── used as grant target on projects / secrets
      └── Project
           ├── Project members (direct user → project role)
           ├── Project group roles (group → project role)
           └── Secrets
                └── optional per-secret ACL (user and/or group grants)
```

| Layer | What it controls | How you grant it |
|-------|------------------|------------------|
| **Team** | See the team, its projects (default), team settings | Direct **Members**, or a **Group** with a team role |
| **Project** | Read / write secrets, manage project settings | Direct **project members**, **group roles**, or inherit from team role |
| **Secret** | Tighter than project (who may list / reveal / edit) | Secret **ACL mode** + optional user/group grants |
| **Global admin** | Everything | Server bootstrap email or LDAP/OIDC → `global_admin` map |

**Highest matching role wins** when a user has both a direct grant and one or
more group grants. Manual memberships are **never** removed by directory sync.

---

## 2. Roles and permissions

### 2a. Team roles

| Role | Typical use | Can |
|------|-------------|-----|
| **owner** | Team lead / break-glass | Full team control; delete team; always project admin/write |
| **admin** | Team operators | Manage members, groups, maps, settings; always project admin/write |
| **member** | Day-to-day contributors | Create projects; write secrets (unless project demotes them) |
| **viewer** | Read-only observers | Read projects/secrets (unless project elevates them) |

Team **owner** and **admin** cannot be demoted by project-level grants: they
always keep project admin/write on every project in the team.

### 2b. Project roles

| Role | Can |
|------|-----|
| **admin** | Write secrets + manage project members / group roles / secret ACLs / approval settings |
| **write** | Create, edit, delete secrets |
| **read** | List secrets and metadata; reveal depends on ACL + approval policy |

If a user has **no** project-level grant (neither user nor group), access falls
back to their **team role**:

| Team role | Effective project access (no project grant) |
|-----------|-----------------------------------------------|
| owner / admin | Project admin |
| member | Write |
| viewer | Read |

If they **do** have a project grant, that role is used for read/write/admin
checks (still subject to "team owner/admin always admin/write").

### 2c. Per-secret access (role bindings)

Set on the secret (create form or secret full view). See also
[rbac-k8s.md](rbac-k8s.md) for the Kubernetes-style model.

| `acl_mode` | Who may access |
|------------|----------------|
| **inherit** (default) | Project/team RBAC via the scope chain; optional secret-scope bindings add grants |
| **custom** (restricted) | Only secret-scope bindings (`secret-read` / `secret-reveal` / `secret-write`) plus project admins |

**Always full access on a secret:** global admins and anyone with
`can_admin_project` for that secret's project. The legacy `api.secret_acl`
table has been removed.

**Machine tokens** (`ss_…`) and ESO use SECURITY DEFINER helpers and are **not**
gated by per-secret human ACLs or reveal-approval (project-scoped only). Prefer
a dedicated project, **key allow-list** (exact keys and/or globs like `prod/*`
on the token), or both when automation must not see every secret in a shared
project. See [machine-tokens.md](machine-tokens.md).

### 2d. Reveal approval (separate from RBAC)

Optional **project default** and **per-secret override** can require an admin
to approve reveals for non-admins. That sits on top of RBAC: the user must
already be allowed to reveal via ACL, then also hold a valid approval grant.
See the Access tab on the project and [api.md](../dev/api.md).

---

## 3. Quick setup checklist (new organisation)

```text
1. Bootstrap a global admin (GLOBAL_ADMIN_EMAIL or BOOTSTRAP_ADMIN_EMAIL).
2. Create a team.
3. Add people (Team → Members): email + role.
4. Create groups (recommended for orgs) — see §4 and §5.
5. Create projects (Team → Projects).
6. Tighten sensitive secrets (ACL mode + grants).
7. (Optional) Wire LDAP/OIDC.
8. (Optional) Machine / CLI access (machine token or PAT).
```

---

## 4. Groups (manual and directory)

Groups are **team-scoped** principals. They are not global across the server.

### 4a. Create a group (UI)

1. Open **Team → Groups**.
2. **Create group**:
   - **Name** — human label (e.g. `platform-ops`).
   - **Source** — `manual`, `ldap`, or `oidc`.
   - **External key** — required when source is `ldap`/`oidc` (directory DN/CN
     or OIDC groups claim value).
   - **Team role** — optional: `admin` / `member` / `viewer` only (not owner).
3. Click the group name → **Add member** (email) for manual members. Directory
   members appear after login when `external_key` matches.

### 4b. When to set a team role on the group

| Goal | Team role on group |
|------|--------------------|
| Group only used for **project** or **secret** grants | Leave team role empty (**— none —**) |
| Group should see the team and inherit default project access | Set e.g. `viewer` or `member` |
| Group should administer the team | Set `admin` (use carefully; groups cannot be `owner`) |

A user who is only in a group **without** a team role is **not** a team member
until they also have a project group role or direct membership that grants
access. For secret ACLs, they still need `can_read_project` first.

### 4c. Manual-only group example

**Scenario:** Contractors should write only to project `demo-api`, not the team.

```text
1. Team → Groups → create "contractors", source manual, team role none.
2. Add contractor emails as group members.
3. Project demo-api → Settings → Group roles → contractors → write.
4. They use that project only; they do not inherit other projects.
```

### 4d. Group with team role example

**Scenario:** Ops group should act as team members on all projects by default.

```text
1. Create "platform-ops", team role member.
2. Add people (or map LDAP/OIDC).
3. They get write access on projects that do not assign a lower project role.
```

---

## 5. Directory integration (LDAP / OIDC)

Two complementary mapping styles — use either or both.

### 5a. Legacy direct maps (team membership rows)

| Where | Effect |
|-------|--------|
| **Team → Settings → LDAP group membership** | Matching LDAP group → `team_members` row |
| **Team → Settings → OIDC group membership** | Matching OIDC group → `team_members` row |
| **Server settings → LDAP / OIDC group → roles** | Matching group → `global_admin` |

- Applied on each LDAP bind login / OIDC login.
- **Manual** `team_members` rows are never overwritten or deleted by sync.
- Highest matching role wins if several maps match.

### 5b. First-class groups (`Team → Groups` + `external_key`)

| Field | LDAP example | OIDC example |
|-------|--------------|--------------|
| source | `ldap` | `oidc` |
| external_key | `cn=platform-admins,ou=groups,dc=example,dc=com` | `platform-admins` |

On login, the app:

1. Reads the user's directory groups.
2. Finds `api.groups` with the same `source` and matching `external_key`.
3. Upserts `group_members` with `source=ldap|oidc`.
4. Removes **stale directory-sourced** memberships for that source; leaves
   `source=manual` members alone.

Then grant that group: a **team role**, a **project group role**, or a
**secret ACL** (custom mode).

### 5c. Recommended org pattern

```text
1. One first-class group per major directory group.
2. Set team role only when the group should open the whole team.
3. Use project group roles for least privilege per app/environment.
4. Use custom secret ACL for crown-jewel secrets.
5. Keep a small set of manual team owners for break-glass.
6. Map a directory admin group to global_admin only if you accept full
   server control from that IdP group.
```

---

## 6. Project access (UI)

**Project → Settings** (project admins and team owner/admin):

- **Members** — email + role (`read` / `write` / `admin`). Elevates team
  viewers/members for this project only. Does not demote team owners/admins.
- **Group roles** — pick a team group + project role. Highest of user's direct
  project role and all their groups' project roles wins.

---

## 7. Secret ACL (UI)

1. Open the secret **full view**.
2. Tabs: **Secret** (value) · **Metadata** · **Permissions** (admins).
3. On **Permissions**: set **Access mode** and **Reveal approval**, then save.
4. If mode is **custom**:
   - Grant by **email** or **team group**.
   - Choose permission: read / reveal / write.
5. Remove grants from the same table.

Users must still pass project read (and any reveal-approval rules).

---

## 8. How effective access is computed

Simplified rules (same logic as the SQL helpers):

```
team_role(user, team) =
  global_admin → owner
  else max(
    direct team_members.role,
    team_role of every group the user is in on that team
  )

is_team_member = global_admin OR direct member OR in a group with non-null team_role

project_role(user, project) =
  max(
    direct project_members.role,
    project_group_roles.role for groups the user is in
  )   # may be null

can_admin_project =
  global_admin OR team_role in (owner, admin) OR project_role = admin

can_write_project =
  can_admin_project
  OR project_role in (admin, write)
  OR (project_role is null AND team_role = member)

can_read_project =
  can_write_project OR project_role is not null OR is_team_member(team)

can_access_secret(secret, need) =
  live secret AND can_read_project
  AND (
    can_admin_project
    OR acl_mode rules for need
    OR custom: matching user or group grant with permission ≥ need
  )
```

Permission rank: `read` < `reveal` < `write`.

---

## 9. Common pitfalls

| Symptom | Likely cause |
|---------|----------------|
| User has directory group but no access | Wrong `external_key` / claim value; user has not logged in since map created; team role empty and no project/secret grant |
| Manual member disappeared | They were directory-sourced only and no longer match maps — manual adds use `source=manual` and persist |
| Can see project but not secret value | Secret ACL mode restricts them; or reveal approval pending |
| Team owner blocked by project "read" | Not expected — team owner/admin always keep write/admin |
| Machine token ignores custom ACL | By design — use a separate project or key allow-list |
| ensure_schema fails at startup | Check logs; `DATABASE_ADMIN_URL` must be a superuser DSN |

---

## 10. Minimal "day one" recipe

```text
1. GLOBAL_ADMIN_EMAIL=you@company.com  →  start stack  →  register / SSO as you
2. Create team "Platform"
3. Team → Groups → "eng" (manual or oidc + external_key), team_role = member
4. Team → Groups → "sec-leads" (manual), team_role = admin
5. Create project "prod-api"
6. Project Settings → Group roles → eng = write, sec-leads = admin
7. Create secret DB_PASSWORD; leave ACL inherit
8. Create secret ROOT_CA_KEY; ACL custom → grant group sec-leads reveal
9. Invite break-glass local owner on team Members if using SSO for everyone else
```

That gives normal engineers project write via group membership, security leads
admin + the crown-jewel secret, without listing every user on every project.

---

## Related docs

- [deploy.md](deploy.md) — env vars, bootstrap admin, OIDC/LDAP server config
- [authentication.md](authentication.md) — login flows, PAT, machine tokens, JWT
- [machine-tokens.md](machine-tokens.md) — machine accounts, key allow-lists, ESO
- [api.md](../dev/api.md) — secret API, ACL modes, PostgREST
