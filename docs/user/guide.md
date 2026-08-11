# User Guide — Using the Web UI

How to use Sigaint Secret Server day to day: teams, projects, secrets, reveal,
access requests, metadata, import/export.

---

## Concepts

```
Organisation
 └── Team            (a group of people, e.g. "Platform")
      └── Project    (a collection of secrets, e.g. "production-api")
           └── Secret (a key/value, e.g. DATABASE_URL)
```

- **Team** — the top-level access boundary. You belong to one or more teams.
- **Project** — lives inside a team. Secrets are organised per project.
- **Secret** — a named value (plain text, database URL, certificate, SSH key,
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

You become the **owner** of any team you create.

### Team tabs

| Tab | Purpose |
|-----|---------|
| **Projects** | Create and open projects in this team |
| **Members** | Add/remove members, manage roles, invites, join requests |
| **Groups** | Create team-scoped groups (RBAC principals) |
| **Activity** | Team-level audit events |
| **Settings** | Team defaults, classification banner, LDAP/OIDC group maps |

### Team roles

| Role | Can |
|------|-----|
| **owner** | Everything; delete team; always project admin/write |
| **admin** | Manage members, groups, settings; always project admin/write |
| **member** | Create projects; write secrets (unless a project demotes them) |
| **viewer** | Read-only |

Only **owners** can assign the `owner` role.

### Add a member

**Members → Add** (owner/admin only):

```text
User email: alice@example.com
Role: member
```

### Invite a member (self-service)

**Members → Invites & join requests → Create invite link**. Share the link.
The recipient signs in and requests to join; an owner/admin approves.

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
| **Access** | Reveal-approval request queue (approve/deny) |
| **Audit log** | Who did what to secrets in this project |
| **Machine accounts** | Tokens for ESO / CI / CLI |
| **Import / Export** | Bulk `.env` / JSON / CSV |
| **Integrations** | ESO manifest generator |
| **Settings** | Reveal-approval default, members, group roles, danger zone |

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
Access: Project access        (access mode)
Approval: Default (project)   (reveal approval override)
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
- **Approver (project admin / team owner):** open the project **Access** tab
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

- **Sidebar search** — searches teams, projects, and secrets you can access
  (including custom metadata).
- **Per-project search** — the search box on the Secrets tab filters key/note.

### Trash

Deleted secrets go to **Trash** (sidebar). Restore or purge them there.

### Version history

Open a secret → **History**. You can view and roll back to a previous version.

### Metadata

On a secret, the **Metadata** tab shows system fields (created, updated, last
accessed) and lets writers add custom searchable key/value labels.

### Permissions (project admins)

The **Permissions** tab on a secret controls:

- **Access mode** — who may access the secret:
  `inherit` / `writers` / `admins` / `owners` / `custom`.
- **Reveal approval** — override the project default (require / exempt).
- **Custom access list** — user or group grants (only when mode is `custom`).

---

## Import / Export

On the project **Import / Export** tab:

### Export

```text
Format:  Encrypted JSON | .env (plaintext) | JSON (plaintext) | CSV (plaintext)
[Download]
```

Plaintext exports require a confirmation. Exports respect reveal permissions — you
only get secrets you may reveal.

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
