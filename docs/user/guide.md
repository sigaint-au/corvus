# User guide

How to use Corvus day to day: teams, projects, secrets, reveal,
access requests, metadata, import/export.

---

## Concepts

```
Organisation
 └── Team            (a group of people, e.g. "Platform")
      └── Project    (a collection of secrets, e.g. "production-api")
           └── Secret (a key/value, e.g. DATABASE_URL)
```

- **Team**: the top-level access boundary. You belong to one or more teams.
- **Project**: lives inside a team. Secrets are organised per project.
- **Secret**: a named value (plain text, database URL, certificate, SSH key,
  or key/value pairs). Values are encrypted at rest.

The **sidebar team switcher** selects which team you are working in. Most
screens (Projects, Secrets, Trash) are scoped to that team.

---

## Teams

### Create a team

Sidebar → **Account → Teams → New team**.

```text
Name: Platform
```

You become the **team-owner** of any team you create.

### Team tabs

| Tab | Purpose |
|-----|---------|
| **Projects** | Create and open projects in this team |
| **Activity** | Team-level audit events |
| **Members** | Add/remove members, manage roles, invites, join requests |
| **Groups** | Create team-scoped groups (RBAC principals) |
| **Access** | Team-scope role bindings (owners/admins) |
| **Webhooks** | Team event subscriptions (owners/admins) |
| **Settings** | Team defaults, classification banner, LDAP/OIDC group maps |
| **Metadata** | Team-wide key/value labels inherited by every project and secret |

### Team roles

| Role | Can |
|------|-----|
| **team-owner** | Everything; delete team; always project admin/write |
| **team-admin** | Manage members, groups, settings; always project admin/write |
| **team-member** | Create projects; write secrets (reveal granted separately) |
| **team-viewer** | Read-only (metadata, no plaintext) |

Only **team-owners** can assign the `team-owner` role.

### Add a member

**Members → Add** (team-owner/team-admin only):

```text
User email: alice@example.com
Role: team-member
```

### Invite a member (self-service)

**Members → Invites & join requests → Create invite link**. Share the link.
The recipient signs in and requests to join; a team-owner/team-admin approves.

---

## Projects

### Create a project

Open a team → **Projects → New project**:

```text
Name: production-api
Description: optional purpose
```

### Project tabs

| Tab | Purpose |
|-----|---------|
| **Secrets** | List, search, create, reveal, pin, bulk actions |
| **Requests** | Reveal-approval request queue (approve/deny) |
| **Import / Export** | Bulk `.env` / JSON / CSV |
| **Access** | Project-scope role bindings (project admins) |
| **Webhooks** | Project event subscriptions (project admins) |
| **Settings** | Reveal-approval default, members, danger zone |
| **Metadata** | Project-wide labels inherited by every secret (cannot override team keys) |

### Folders

Secrets can be organised into **folders** inside a project. Folders are
auto-created when you include a slash-separated path in the secret key:

```text
Key:   deploy/prod/DATABASE_URL
```

This creates the folder `deploy` → subfolder `prod` → secret `DATABASE_URL`.

Folders are listed in a table above the secret list on the project **Secrets**
tab. Click a folder to open its own page:

| Tab | Purpose |
|-----|---------|
| **Contents** | Sub-folders and secrets in this folder |
| **Access** | Folder access mode (inherit/restricted) and role bindings |

**Folder access** works like per-secret access:

| `access_mode` | Who can access |
|---------------|----------------|
| `inherit` (default) | Project/team roles apply via scope chain |
| `restricted` | Only folder-scope bindings + project admins |

Only **project admins** can manage folder access, add bindings, or delete an
empty folder. A folder with secrets inside cannot be deleted.

---

## Secrets

### Create a secret (quick)

On the project **Secrets** tab, use the inline form:

```text
Key:   DATABASE_URL
Type:  Plain
Value: postgres://user:pass@host/db
Note:  optional label
Expires: (optional date)
Access: Inherit project access  (access mode)
Approval: Default (project)     (reveal approval override)
```

Click **Create**.

### Create a structured secret

Click **Create secret** (top of the Secrets tab) for the advanced form with
kind-specific fields:

| Type | Fields |
|------|--------|
| Plain text / password | single value |
| Database URL | scheme, host, port, user, password, database |
| Certificate (PEM) | certificate + optional private key |
| SSH private key | key PEM |
| Key / value pairs | multiple rows (revealed as a table / `.env`) |

### Reveal a secret value

In the secret list, click the masked `•••••••` cell (or **Reveal** in the row
menu). The value shows inline and auto-hides after a few seconds. Reveals are
**audited**.

If a secret requires approval, you'll see a **Request access** dialog instead:

```text
Why do you need access?
[ reason field ]
[Request access]
```

### Access requests (approval workflow)

- **Requester:** click **Reveal** → **Request access…** → enter a reason.
- **Approver (project admin / team owner):** open the project **Requests** tab
  (or the global **Access requests** inbox in the sidebar), choose a grant
  duration, then **Approve** or **Deny**.

Grant durations: 15 min, 1 hour, 4 hours, 1 day. The grant is time-limited.

### Pin a secret

Click the pin icon in a row to add it to your sidebar **Pinned** list.

### Bulk actions

Tick the checkboxes in the secret list, then use the bulk toolbar:

```text
Action…  →  Export .env | Export JSON | Delete
```

### Search

- **Sidebar search**: searches teams, projects, and secrets you can access
  (including custom metadata).
- **Per-project search**: the search box on the Secrets tab filters key/note.

### Trash

Deleted secrets go to **Trash** (sidebar). Restore or purge them there.

### Version history

Open a secret → **History**. You can view and roll back to a previous version.

### Metadata

Labels are searchable key/value pairs, not secret values. They inherit down
the hierarchy: **team → project → secret**. A key defined higher up cannot
be overridden lower down.

- **Team Metadata** tab: owners/admins write; members can read.
- **Project Metadata** tab: project admins write; anyone who can see the
  project can read. Inherited team keys show as inherited.
- **Secret Metadata** tab: system fields (created, updated, last accessed)
  plus custom labels. Writers add secret-level keys that are not already
  defined on the team or project.

  A secret with the key `exclude-due-notify` or `exclude_due_notify` (any
  value) is omitted from the due/expired notification email (`notify-due`
  command).

### Access (project admins)

The **Access** tab on a secret controls:

- **Access mode**: `inherit` (project/team bindings apply) or `restricted`
  (only secret-scope bindings + project admins).
- **Reveal approval**: override the project default (require / exempt).
- **Secret role bindings**: bind users/groups to `secret-read`,
  `secret-reveal`, or `secret-write` roles.

---

## Import / Export

On the project **Import / Export** tab:

### Export

```text
Format:  Encrypted JSON | .env (plaintext) | JSON (plaintext) | CSV (plaintext)
[Download]
```

Plaintext exports require a confirmation. Exports respect reveal permissions:
you only get secrets you may reveal.

### Import

```bash
# .env format
KEY=value
OTHER=secret
```

Paste or upload a `.env`, CSV (`key,value`), or JSON file. You get a **preview**
of creates vs updates before anything is written. Requires write access.

---

## Keyboard / navigation tips

- Use the **sidebar search** to jump straight to a secret across all teams.
- Use the **team switcher** at the top of the sidebar to change teams.
- Pinned secrets appear in the sidebar for quick access.

---

## Related docs

- [cli.md](cli.md): CLI guide
- [../admin/rbac.md](../admin/rbac.md): RBAC access model
- [../admin/machine-tokens.md](../admin/machine-tokens.md): machine accounts
- [../admin/external-secrets.md](../admin/external-secrets.md): External Secrets Operator pull and push
