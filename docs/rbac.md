# Organisation RBAC guide

How access control works in Sigaint Secret Server, and how to set it up for a
real organisation: **users**, **groups** (manual or directory-synced), and
permissions at **team**, **project**, and **secret** level.

Enforcement is in **Postgres RLS** via helpers such as `api.is_team_member`,
`api.team_role`, `api.project_role`, `api.can_read|write|admin_project`, and
`api.can_access_secret`. The UI and APIs call the same helpers — there is no
separate “app-only” ACL.

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
checks (still subject to “team owner/admin always admin/write”).

### 2c. Per-secret ACL modes

Set on the secret (create form or secret full view). Project membership still
required first (`can_read_project`).

| `acl_mode` | Who may access (beyond “must already see the project”) |
|------------|--------------------------------------------------------|
| **inherit** (default) | Normal project RBAC (read for readers; write needs write+) |
| **writers** | Only users who can write the project |
| **admins** | Only project admins (and team owner/admin / global admin) |
| **owners** | Only team **owners** (plus global admin) |
| **custom** | Explicit grants in the secret ACL list (user and/or group) |

On **custom**, each grant has a permission:

| Permission | Meaning |
|------------|---------|
| **read** | See the secret exists / metadata |
| **reveal** | Decrypt and view the value |
| **write** | Edit / delete (includes reveal + read) |

**Always full access on a secret:** global admins and anyone with
`can_admin_project` for that secret’s project.

**Machine tokens** (`ss_…`) and ESO use SECURITY DEFINER helpers and are **not**
filtered by per-secret human ACLs. Prefer a dedicated project (or tighter
token scope) for highly sensitive automation.

### 2d. Reveal approval (separate from RBAC)

Optional **project default** and **per-secret override** can require an admin
to approve reveals for non-admins. That sits on top of RBAC: the user must
already be allowed to reveal via ACL, then also hold a valid approval grant.
See the Access tab on the project and [docs/api.md](./api.md).

---

## 3. Quick setup checklist (new organisation)

1. **Bootstrap a global admin**  
   Set `GLOBAL_ADMIN_EMAIL` (or `BOOTSTRAP_ADMIN_EMAIL`) to the first admin’s
   email before first login, or promote via admin UI after they register.

2. **Create a team**  
   Teams → create (if user team creation is disabled, only global admins can).

3. **Add people**  
   Team → **Members**: email + role. Users must already exist (registered or
   signed in via LDAP/OIDC once).

4. **Create groups (recommended for orgs)**  
   Team → **Groups** — see [§4](#4-groups-manual-and-directory) and
   [§5](#5-directory-integration-ldap--oidc).

5. **Create projects**  
   Team → Projects → create. Optionally open Project → **Settings** for
   project members and **Group roles**.

6. **Tighten sensitive secrets**  
   Secret full view → ACL mode (e.g. **custom**) → grant users and/or groups.

7. **(Optional) Wire LDAP/OIDC**  
   Server settings for LDAP or OIDC; map global admin groups; map team groups
   via `external_key` or legacy team LDAP/OIDC maps.

8. **(Optional) Machine / CLI access**  
   Project → Integrations → machine token (`ss_…`), or user PAT (`pat_…`).
   Documented in [docs/api.md](./api.md) and [docs/authentication.md](./authentication.md).

---

## 4. Groups (manual and directory)

Groups are **team-scoped** principals. They are not global across the whole
server.

### 4a. Create a group (UI)

1. Open **Team → Groups**.
2. **Create group**:
   - **Name** — human label (e.g. `platform-ops`).
   - **Source** — `manual`, `ldap`, or `oidc`.
   - **External key** — required when source is `ldap` or `oidc` (directory
     group DN/CN or OIDC groups claim value).
   - **Team role** — optional. If set, members of this group count as team
     members with that role (max with any direct team membership).
3. Open the group → **Add member** (email) for manual members.  
   Directory members appear after they log in when `external_key` matches.

### 4b. When to set a team role on the group

| Goal | Team role on group |
|------|--------------------|
| Group only used for **project** or **secret** grants | Leave team role empty (**— none —**) |
| Group should see the team and inherit default project access | Set e.g. `viewer` or `member` |
| Group should administer the team | Set `admin` (use carefully) |

A user who is only in a group **without** a team role is **not** a team member
until they also have a project group role or direct membership somewhere that
grants access. For secret ACLs, they still need `can_read_project` first
(project grant or team membership).

### 4c. Manual-only group example

**Scenario:** Contractors should write only to project `demo-api`, not the whole
team.

1. Team → Groups → create `contractors`, source **manual**, team role **none**.
2. Add contractor emails as group members.
3. Project `demo-api` → Settings → **Group roles** → `contractors` → **write**.
4. They can use that project; they do not inherit other projects unless granted.

### 4d. Group with team role example

**Scenario:** Ops group should act as team members on all projects by default.

1. Create `platform-ops`, team role **member**.
2. Add people (or map LDAP/OIDC).
3. They get write access on projects that do not assign them a lower project
   role. Elevate or restrict per project with project members / group roles.

---

## 5. Directory integration (LDAP / OIDC)

There are **two** complementary mapping styles. You can use either or both.

### 5a. Legacy direct maps (team membership rows)

| Where | Effect |
|-------|--------|
| **Team → Settings → LDAP group membership** | Matching LDAP group → `team_members` row with chosen role |
| **Team → Settings → OIDC group membership** | Matching OIDC group → `team_members` row |
| **Server settings → LDAP / OIDC group → roles** | Matching group → `global_admin` |

- Applied on each LDAP bind login / OIDC login.
- **Manual** `team_members` rows are never overwritten or deleted by sync.
- Highest matching role wins if several maps match.

### 5b. First-class groups (`Team → Groups` + `external_key`)

| Field | LDAP example | OIDC example |
|-------|--------------|--------------|
| source | `ldap` | `oidc` |
| external_key | `cn=platform-admins,ou=groups,dc=example,dc=com` | `platform-admins` (groups claim value) |

On login, the app:

1. Reads the user’s directory groups.
2. Finds `api.groups` with the same `source` and matching `external_key`
   (same matching rules as team maps).
3. Upserts `group_members` with `source=ldap|oidc`.
4. Removes **stale directory-sourced** memberships for that source; leaves
   `source=manual` members alone.

Then grant that group:

- **Team role** on the group itself, and/or  
- **Project → Settings → Group roles**, and/or  
- **Secret ACL** (custom mode).

### 5c. Prerequisites

**OIDC**

1. Administration → Server settings → OIDC / SSO (issuer, client, secret, scopes).
2. Groups claim (default `groups`; plus `realm_access.roles` when present).
3. IdP client includes groups in the token / userinfo as configured.
4. Redirect URI: `{server_url}/login/oidc/callback`.

Details: [deploy.md §9a](./deploy.md#9a-oidc--sso), [authentication.md](./authentication.md).

**LDAP**

1. Administration → Server settings → LDAP (URL, bind, bases, filters).
2. Prefer StartTLS / LDAPS; cleartext LDAP is rejected unless allowed by policy.
3. Group filter / memberOf so login can resolve group DNs/CNs that match your
   maps and `external_key` values.

Details: [deploy.md §9b](./deploy.md#9b-ldap).

### 5d. Recommended org pattern

1. Create one first-class group per major directory group you care about.  
2. Set **team role** only when the directory group should open the whole team.  
3. Use **project group roles** for least privilege per app/environment.  
4. Use **custom secret ACL** for a few crown-jewel secrets (vault keys, break-glass).  
5. Keep a small set of **manual** team owners for break-glass local accounts.  
6. Map a directory admin group to **global_admin** only if you accept full
   server control from that IdP group.

---

## 6. Project access (UI)

**Project → Settings** (project admins and team owner/admin):

### Members (users)

- Email + role (`read` / `write` / `admin`).
- Elevates team viewers/members for this project only.
- Does not demote team owners/admins.

### Group roles

- Pick a team group + project role.
- Highest of user’s direct project role and all their groups’ project roles wins.

---

## 7. Secret ACL (UI)

1. Open the secret **full view** (not only the inline reveal cell).
2. Open the **Access** tab (project admins only).
3. Set **Access mode** and save.
4. If mode is **custom**:
   - Grant by **email**, or  
   - Grant by **group** (dropdown of team groups),  
   - Choose permission: read / reveal / write.
5. Remove grants from the same table on the Access tab.

The **Secret** tab edits value/metadata only; it does not change ACL mode.

Users must still pass project read (and any reveal-approval rules) to use the
secret.

---

## 8. How effective access is computed

Simplified rules (same logic as SQL helpers):

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

Permission rank: `read` &lt; `reveal` &lt; `write`.

---

## 9. Database objects (reference)

| Object | Purpose |
|--------|---------|
| `api.team_members` | Direct user ↔ team role (`source`: manual/ldap/oidc) |
| `api.project_members` | Direct user ↔ project role |
| `api.groups` | Team-scoped group; `source`, `external_key`, optional `team_role` |
| `api.group_members` | User ↔ group (`source`: manual/ldap/oidc) |
| `api.project_group_roles` | Group ↔ project role |
| `api.secret_acl` | Secret ↔ user **or** group + permission |
| `api.team_ldap_maps` / `api.team_oidc_maps` | Legacy directory → direct team_members |
| `private.ldap_role_maps` / `private.oidc_role_maps` | Directory → global_admin |

Listing helpers (SECURITY DEFINER): `private.team_group_rows`,
`private.group_member_rows`, `private.project_group_role_rows`,
`private.secret_acl_rows`.

Fresh installs apply `db/init.sql`. Existing volumes are upgraded by
`ensure_schema()` at app startup (`DATABASE_ADMIN_URL` required).

---

## 10. Dev seed

Mock data including groups and ACL samples:

```bash
# Copy or mount scripts/seed_mock.py into the app container, then:
podman exec -it secretserver_app_1 python /tmp/seed_mock.py
# (or your compose service name)
```

All seeded local passwords: `password`.  
Includes e.g. Platform group `platform-ops`, LDAP-mapped stub group, project
group roles, and a custom ACL on `AWS_SECRET_ACCESS_KEY`.

---

## 11. Common pitfalls

| Symptom | Likely cause |
|---------|----------------|
| User has directory group but no access | Wrong `external_key` / claim value; user has not logged in since map created; team role left empty and no project/secret grant |
| Manual member disappeared | They were directory-sourced only and no longer match maps — manual adds use `source=manual` and persist |
| Can see project but not secret value | Secret ACL mode restricts them; or reveal approval pending |
| Team owner blocked by project “read” | Not expected — team owner/admin always keep write/admin |
| Machine token ignores custom ACL | By design — use a separate project or accept project-scoped automation |
| ensure_schema fails at startup | Check app logs; `DATABASE_ADMIN_URL` must be superuser DSN |

---

## 12. Related docs

| Doc | Topic |
|-----|--------|
| [deploy.md](./deploy.md) | Env vars, bootstrap admin, OIDC/LDAP server config |
| [authentication.md](./authentication.md) | Login flows, PAT, machine tokens, JWT |
| [api.md](./api.md) | Secret API, ACL modes, PostgREST tables |

---

## 13. Minimal “day one” recipe

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
