# API Reference

Sigaint Secret Server exposes three machine-facing surfaces:

| Surface | Base | Auth | Plaintext secrets? |
|---------|------|------|--------------------|
| **App JSON** | `:8080` | Session or PAT (route-dependent) | No (except via UI HTML) |
| **Unified secret API (ESO / CLI)** | `:8080/eso/v1/…` | `Authorization: Bearer ss_…` **or** `pat_…` | **Yes** (decrypt with `MASTER_KEY`) |
| **PostgREST** | `:3000` (default) | `Authorization: Bearer <JWT>` | **No** — returns `value_enc` only |

> Authentication flows, token lifecycle, and credential curl examples:
> [authentication.md](../admin/authentication.md).

---

## Which API should I use?

| Goal | Recommended API | Token |
|------|-----------------|-------|
| **CLI / CI: list, get, create, update, delete secrets (plaintext)** | `/eso/v1` secret API | `ss_…` (**write** to mutate) **or** `pat_…` (user write access) |
| **OpenShift External Secrets Operator pull** | `GET /eso/v1/…/secrets/{key}` | Machine account `ss_…` (`reveal` reads values) |
| **Scripts: list teams/projects/metadata under user RLS** | PostgREST **or** `GET /eso/v1/projects` (PAT) | PAT → JWT via `/api/token`, or PAT on `/eso/v1` |
| **Browser UI** | HTML session routes | Cookie session |

**Prefer `/eso/v1`** whenever a tool needs **plaintext** secret values or to
**create/update/delete** secrets without a browser. PostgREST cannot decrypt
values and cannot write plaintext `value` fields.

---

## Authentication (summary)

### 1. Browser session

Log in via the UI (`/login`, optional `/login/oidc`, optional `/login/2fa`).
Session cookie is used for HTML routes and for `GET /api/token` without a
Bearer header.

### 2. Personal access tokens (PAT)

Create under **My profile → Security**. Format: `pat_` + URL-safe secret
(shown once). Max 50 per user; optional expiry (1–3650 days).

- Act as that user under RLS after exchanging for a JWT (PostgREST).
- Also accepted on **`/eso/v1`** for plaintext secret CRUD (user membership).

```http
GET /api/token HTTP/1.1
Host: secrets.example.com
Authorization: Bearer pat_…
Accept: application/json
```

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "expires_in": 86400,
  "postgrest": "http://localhost:3000"
}
```

Errors: `401` `{"error":"unauthorized"}` if the PAT is invalid, revoked, or
expired.

### 3. Short-lived JWT (PostgREST)

Issued by `GET /api/token` (session or PAT). Signed with `JWT_SECRET`, role
claim `authenticated`. Lifetime: **24 hours**.

```bash
JWT=$(curl -s -H "Authorization: Bearer pat_…" \
  -H "Accept: application/json" \
  https://secrets.example.com/api/token | jq -r .access_token)

curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/projects?select=id,name,team_id"
```

Also available in the UI: **My profile → Security → API access → Show JWT**.

### 4. Machine tokens (ESO / CLI / CI)

Create on a project (**Integrations** / machine accounts). Format: `ss_…`
(shown once). Scoped to **one project**.

| Role | Metadata | Reveal values | Write |
|------|----------|---------------|-------|
| `service-read` | yes | no | no |
| `service-reveal` | yes | yes | no |
| `service-write` | yes | yes | yes |

- Prefer **`service-reveal`** for ESO pull and automation that needs values.
- Use **`service-write`** for CLI/CI that creates, rotates, or deletes secrets.

---

## App JSON endpoints (`:8080`)

### `GET /health`

Liveness / DB ping. No auth.

**200** `{"ok": true}`  
**503** `{"ok": false}`

### `GET /api/token`

Mint a PostgREST JWT.

| Auth | Result |
|------|--------|
| Session cookie (`user_id`) | JWT for that user |
| `Authorization: Bearer pat_…` | JWT for PAT owner |
| Pending 2FA only | redirect to `/login/2fa` |
| None + `Accept: application/json` or any Bearer | **401** |
| None + browser | redirect to login |

**200**

```json
{
  "access_token": "eyJ…",
  "token_type": "bearer",
  "expires_in": 86400,
  "postgrest": "http://postgrest:3000"
}
```

### `GET /api/users/suggest?q=`

Email/name autocomplete for member fields. Requires **login** (session).

| Caller | Results |
|--------|---------|
| Global admin | Any active user matching `q` |
| Other users | Active users who share a team with the caller |

- `q` required (min length 1, max 80). Limit 15 rows.

**200**

```json
[
  { "email": "ada@example.com", "name": "Ada", "label": "Ada <ada@example.com>" }
]
```

On query failure returns `[]` (does not 500).

---

## Managing secrets via the unified API (`/eso/v1`)

**Base path:** `https://<host>/eso/v1/projects/<project_ref>`

`project_ref` is a project **UUID** (required for machine tokens) or, with a
**PAT**, a UUID or a unique project **name** the user can access.

**Auth (all routes):**

```http
Authorization: Bearer ss_…   # machine token (project-scoped)
Authorization: Bearer pat_…  # personal access token (user RLS)
Content-Type: application/json   # for POST / PUT / PATCH bodies
```

| Token | Access model | `project_ref` | Mutate |
|-------|--------------|---------------|--------|
| `ss_…` | Project machine role | UUID only | machine role **write** |
| `pat_…` | User RLS (`can_read` / `can_write`) | UUID or unique name | project write access |

Invalid / wrong-project machine token → **401**. Missing PAT project → **404**.

These routes are **CSRF-exempt** (Bearer token auth; no session cookie).

Also: **`GET /eso/v1/projects`** (PAT only) lists projects visible to the user
(`?q=` / `?name=` optional filter).

### Setup for CLI / CI

**Machine token**

```text
1. Project → Integrations / Tokens → create write (or reveal).
2. Copy ss_… and the project UUID.
```

**Personal access token**

```text
1. My profile → Security → create PAT (pat_…).
2. Use any project the user can access (UUID or unique name).
```

```bash
export SS_URL="https://secrets.example.com"   # no trailing slash
export SS_TOKEN="ss_…"   # or pat_…
export SS_PROJECT="<project-uuid-or-name>"
export AUTH="Authorization: Bearer $SS_TOKEN"
```

### Endpoint map

| Method | Path | Access | Purpose |
|--------|------|--------|---------|
| `GET` | `/eso/v1/projects` | **PAT only** | List projects (name/id) |
| `GET` | `/secrets` | read | List bulk values **or** metadata (`meta=1`) |
| `GET` | `/secrets/{key}` | read | Get one secret (value + metadata) |
| `POST` | `/secrets` | **write** | Create or upsert (`key` in JSON body) |
| `PUT` | `/secrets/{key}` | **write** | Create or replace by path key |
| `PATCH` | `/secrets/{key}` | **write** | Partial update (secret must exist) |
| `DELETE` | `/secrets/{key}` | **write** | Soft-delete (moves to trash) |

Paths under `/eso/v1/projects/<project_ref>/…`. `{key}` supports path-style
keys (Flask `<path:key>`), e.g. `db/password`.

### Secret object fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID string | Secret row id |
| `key` | string | Name within the project (unique among live secrets) |
| `value` | string | Plaintext secret (only when decrypted for the caller) |
| `note` | string | Non-sensitive label / description |
| `kind` | string | `plain`, `database`, `certificate`, `ssh`, or `kv` |
| `expires_at` | ISO-8601 or `null` | Optional hard expiry |
| `access_mode` | string | Per-secret access mode; default `inherit` |
| `created_at` / `updated_at` | ISO-8601 or `null` | Timestamps |
| `last_accessed_at` / `last_accessed_by` | ISO-8601 / string | Last successful reveal |
| `metadata` | object | Custom key → value labels (`api.secret_meta`); searchable |
| `ok` | boolean | Present on successful write responses |

System fields are not set via API body. Custom `metadata` is managed in the UI
**Metadata** tab (writers).

### Per-secret access modes

| `access_mode` | Who can access |
|---------------|----------------|
| `inherit` (default) | Project/team RBAC via scope chain; secret-scope bindings add grants |
| `restricted` | Only secret-scope `rbac.bindings` (+ project admins) |

**Always full access:** global admins and users with `can_admin_project`.

**Machine tokens / ESO** use SECURITY DEFINER helpers and are **not** gated by
per-secret human role bindings or reveal-approval. Prefer a **separate project**
and/or **key allow-list** for sensitive values.

**Key allow-list (optional):** each token may list exact keys and/or glob
patterns (`prod/*`, `DB_*`, `?.api-key`). Empty allow-list = all keys. Create
via UI or PAT API body `scope: ["API_KEY", "prod/*"]`. Scoped tokens get
**404/empty** for other keys. See [machine-tokens.md](../admin/machine-tokens.md).

**PAT bulk list with values** only includes secrets the caller may
`can_access_secret(…, 'reveal')` and `can_reveal_secret` (approval).

**Permissions on secret-scope bindings:** `read` (metadata) < `reveal` (value) <
`write` (edit/delete). Higher permissions include lower ones.

---

### List secrets

#### Bulk values (ESO-compatible default)

```bash
curl -s -H "$AUTH" \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets"
```

**200**

```json
{ "secrets": { "DATABASE_URL": "postgres://…", "API_KEY": "…" } }
```

#### Metadata only (recommended for CLI)

Query flags (any one enables metadata mode):

| Query | Effect |
|-------|--------|
| `meta=1` | Metadata list (no decrypt) |
| `format=meta` | Same |
| `include_values=0` | Same |
| `q=<text>` | Filter: key, note, **or custom metadata** (case-insensitive) |

```bash
curl -s -H "$AUTH" \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets?meta=1" | jq .
curl -s -H "$AUTH" \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets?meta=1&q=api" | jq .
```

**200**

```json
{
  "items": [
    {
      "id": "a1b2c3d4-…",
      "key": "API_KEY",
      "note": "prod edge",
      "kind": "plain",
      "expires_at": null,
      "created_at": "…",
      "updated_at": "…",
      "last_accessed_at": "…",
      "last_accessed_by": "",
      "metadata": { "owner": "platform-team", "env": "prod" }
    }
  ]
}
```

---

### Get a secret

```bash
curl -s -H "$AUTH" \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets/DATABASE_URL" | jq .
```

**200**

```json
{
  "id": "a1b2c3d4-…",
  "key": "DATABASE_URL",
  "value": "postgres://user:pass@host/db",
  "note": "prod db",
  "kind": "plain",
  "expires_at": null,
  "created_at": "…",
  "updated_at": "…",
  "last_accessed_at": "…",
  "last_accessed_by": "",
  "metadata": { "owner": "platform-team" }
}
```

A successful get (PAT) updates `last_accessed_at` / `last_accessed_by`.

**404** `{"error":"not found"}` — token valid, key missing  
**401** `{"error":"unauthorized"}`  
**403** PAT may return:

| `error` | Meaning |
|---------|---------|
| `forbidden` | Per-secret access mode denies reveal |
| `approval_required` | Reveal needs admin approval (`pending` may be true) |

Machine tokens (`ss_…`) skip human access mode and reveal-approval.

**ESO:** keep using `jsonPath: $.value`. Extra fields are additive.

---

### Create or update a secret (POST)

Requires role **`write`**.

**Body**

| Field | Required | Description |
|-------|----------|-------------|
| `key` | **yes** | Secret name |
| `value` | **yes** | Plaintext (may be `""`) |
| `note` | no | Non-sensitive label |
| `kind` | no | `plain` (default), `database`, `certificate`, `ssh`, `kv` |
| `expires_at` | no | ISO date/datetime; empty/`null` clears when sent |
| `expires_days` | no | Integer days from now |
| `clear_expires` | no | Truthy → clear expiry |

```bash
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"key":"API_KEY","value":"new-value","note":"rotated by CI","kind":"plain","expires_days":90}' \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets" | jq .
```

**200** — full secret object plus `"ok": true`.

Notes:

- Soft-deleted keys with the same name can be replaced (upsert semantics).
- Omitting all expiry fields leaves existing `expires_at` unchanged on update.
- Changing `value` archives the previous ciphertext in `secret_versions`.
- Audited as `machine_upsert` with actor email `machine`.

---

### Replace a secret by key (PUT)

Same write semantics as POST, but **`key` is in the URL**. Body must include
`value`.

```bash
curl -s -X PUT -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"value":"rotated-secret","note":"from cli"}' \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets/API_KEY" | jq .
```

Creates the secret if it does not exist; replaces it if it does.

---

### Partially update a secret (PATCH)

Updates an **existing** secret. Omitted fields keep their current values.
Requires role **`write`**.

| Body field | Behavior |
|------------|----------|
| `value` | If present, replaces the secret value (version archived) |
| `note` | If present, replaces note |
| `kind` | If present, replaces kind |
| `expires_at` / `expires_days` / `clear_expires` | If present, update or clear expiry |

If `value` is omitted, the stored ciphertext is left unchanged.

```bash
curl -s -X PATCH -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"note":"rotated in CI","expires_days":90}' \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets/API_KEY" | jq .
```

**200** — updated secret object + `"ok": true`  
**404** `{"error":"not found"}`  
**403** read token cannot mutate
**400** validation errors

---

### Delete a secret (DELETE)

Soft-deletes the secret (moves it to trash). Restorable / purgeable in the UI.
Requires role **`write`**. Audited as `deleted`.

```bash
curl -s -X DELETE -H "$AUTH" \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets/API_KEY" | jq .
```

**200**

```json
{"ok": true, "id": "a1b2c3d4-…", "key": "API_KEY"}
```

---

### CLI cookbook (copy-paste)

```bash
export SS_URL="https://secrets.example.com"
export SS_TOKEN="ss_…"          # or pat_…
export SS_PROJECT="<project-uuid-or-name>"

secretserver get secrets                         # metadata table (no values)
secretserver get secrets -l platform-team        # q= key/note/custom meta
secretserver get secret API_KEY -o value         # scripts
secretserver get secret API_KEY -o json          # + metadata, last_accessed_*
secretserver get secret prod/db/password -o value  # hierarchical keys OK
printf '%s' "$NEW" | secretserver apply secret API_KEY --from-file=-
secretserver apply secret API_KEY --from-env=NEW_API_KEY --note 'ci rotate'
secretserver delete secret API_KEY
```

### Error reference (machine API)

| HTTP | Body | Typical cause |
|------|------|----------------|
| **400** | `{"error":"key and value required"}` | Missing `key`/`value` on POST/PUT |
| **400** | `{"error":"kind must be one of: …"}` | Invalid `kind` |
| **400** | `{"error":"expires_days must be …"}` / ISO parse errors | Bad expiry |
| **401** | `{"error":"unauthorized"}` | Missing/invalid/wrong-project/expired token |
| **403** | `{"error":"token does not allow writes"}` | Mutate with a `read` token |
| **403** | `{"error":"forbidden"}` | Write path denied by DB helper |
| **403** | `{"error":"approval_required",…}` | PAT reveal blocked until approved |
| **404** | `{"error":"not found"}` | Get/PATCH/DELETE on missing key |

---

### Reveal access approval (PAT)

Projects can require admin approval before a **user** (PAT / browser) may
reveal a secret. Machine tokens (`ss_…`) and ESO pulls are **exempt**.

| Level | Field | Meaning |
|-------|--------|---------|
| Project default | `projects.require_reveal_approval` (default `false`) | Inherit when secret has no override |
| Per-secret | `secrets.requires_approval` (`NULL`/`true`/`false`) | `NULL` = inherit; force require or exempt |

**Who can reveal without a grant:** global admin, team owner/admin, project
admin. Everyone else needs an **approved** request with `approved_until > now()`.

**PAT endpoints:**

| Method | Path | Who | Purpose |
|--------|------|-----|---------|
| `POST` | `…/secrets/{key}/access-request` | any reader | Request access; body optional `{"reason":"…"}` |
| `GET` | `…/access-requests` | admin: all; others: own | List requests (`?status=pending`) |
| `POST` | `…/access-requests/{id}/approve` | project admin / team owner | Approve; body optional `{"minutes":15}` |
| `POST` | `…/access-requests/{id}/deny` | project admin / team owner | Deny |

```bash
curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
  -d '{"reason":"debugging prod auth #1234"}' \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets/API_KEY/access-request" | jq .

curl -s "${AUTH[@]}" \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/access-requests?status=pending" | jq .

curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
  -d '{"minutes":15}' \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/access-requests/<id>/approve" | jq .
```

Default grant duration is **15 minutes**. Allowed choices: 15, 60, 240, 1440.

**CLI:**

```bash
secretserver reveal secret API_KEY --reason "debugging #1234"
secretserver get requests
secretserver approve <request-id> --minutes 15
secretserver get secret API_KEY -o value
```

### Audit actions written by the machine API

| HTTP operation | Audit `action` | Notes |
|----------------|----------------|-------|
| `GET …/secrets/{key}` (value returned) | `revealed` | Same as UI reveal |
| `GET …/secrets` (bulk values) | `exported` | `secret_key` = `machine/values n=N` |
| `GET …/secrets?meta=1` | `exported` | `secret_key` = `machine/meta n=N` |
| `POST`/`PUT`/`PATCH` | `machine_upsert` | Create or update |
| `DELETE …/secrets/{key}` | `deleted` | Soft-delete |
| Access request / approve / deny | `access_requested`, `access_approved`, `access_denied` | Human workflow |

**Actor:** `user_id` null (no JWT on machine connections). `actor_email` is
`machine:<token-name>:<token_prefix>` when resolvable, else `machine`.

Failed auth (401/403) and not-found (404) do **not** write audit rows.

---

## Management API (PAT)

PAT-only routes under `/eso/v1` for org automation. **Machine tokens
(`ss_…`) cannot call these.** Server settings (SMTP, LDAP, OIDC, banners) are
**not** exposed. Used by **secretserver-cli** on `main`.

Auth: `Authorization: Bearer pat_…`. Team/project refs: UUID or unique name.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/eso/v1/teams` | List teams (`?q=` filter) |
| `POST` | `/eso/v1/teams` | Create team `{"name":"…"}` |
| `GET` | `/eso/v1/teams/{ref}` | Team detail + members/projects |
| `DELETE` | `/eso/v1/teams/{ref}` | Delete team |
| `GET` | `/eso/v1/teams/{ref}/members` | Team members |
| `POST` | `/eso/v1/teams/{ref}/members` | Add member `{"email","role"}` |
| `DELETE` | `/eso/v1/teams/{ref}/members/{member}` | Remove member |
| `POST` | `/eso/v1/teams/{ref}/transfer` | Transfer ownership `{"email"}` |
| `POST` | `/eso/v1/teams/{ref}/projects` | Create project `{"name",…}` |
| `GET` | `/eso/v1/projects` | List projects |
| `GET` | `/eso/v1/projects/{ref}` | Project detail |
| `DELETE` | `/eso/v1/projects/{ref}` | Delete project |
| `GET` | `/eso/v1/projects/{ref}/members` | Project members |
| `POST` | `/eso/v1/projects/{ref}/members` | Add project member |
| `DELETE` | `/eso/v1/projects/{ref}/members/{member}` | Remove project member |
| `GET` | `/eso/v1/projects/{ref}/tokens` | Machine token metadata |
| `POST` | `/eso/v1/projects/{ref}/tokens` | Create token (raw `ss_…` once) |
| `DELETE` | `/eso/v1/projects/{ref}/tokens/{id}` | Revoke token |
| `GET` | `/eso/v1/projects/{ref}/trash` | Soft-deleted secrets |
| `POST` | `/eso/v1/projects/{ref}/trash/{id}/restore` | Restore |
| `DELETE` | `/eso/v1/projects/{ref}/trash/{id}` | Purge permanently |
| `GET` | `/eso/v1/projects/{ref}/secrets/{key}/history` | Version history (no plaintext) |
| `GET` | `/eso/v1/projects/{ref}/audit` | Project secret audit |
| `GET` | `/eso/v1/admin/users` | Global admin: user list (`?q=`) |
| `GET` | `/eso/v1/admin/audit` | Global admin: org / secret / access audit |

**Groups, secret role bindings, and custom metadata** are managed in the **browser UI**
today (Team → Groups, Secret → Permissions / Metadata).

### Management CLI examples

```bash
secretserver get teams
secretserver create team Platform
secretserver create project ios-app --team Platform
secretserver create member bob@example.com --team Platform --role team-member
secretserver create member dave@example.com --role project-write   # current project
secretserver get tokens
secretserver create token ci --role service-write             # prints ss_… once
secretserver get trash
secretserver restore trash <secret-uuid>
secretserver get history API_KEY
secretserver get users -l alice                            # global admin
secretserver get audit --source org                        # global admin
```

---

## PostgREST (`:3000`)

PostgREST exposes the Postgres **`api`** schema with **row-level security**.
Use the JWT from `/api/token`. Default compose port: **3000**.

### What PostgREST is good for

- Listing teams, projects, and **secret metadata** as the authenticated user
- Membership and org automation under RLS
- Reading `secret_audit` / `org_audit` where permitted

### What PostgREST is **not** for

- Reading **plaintext** secret values (`value_enc` is Fernet ciphertext)
- Creating secrets with a plaintext `value` field

### Conventions

- Prefer explicit `select=` columns.
- Filter: `?project_id=eq.<uuid>`, `?deleted_at=is.null`, etc.
- Prefer `Accept: application/json`.

### Resources (tables / view)

| Path | Typical use | Notes |
|------|-------------|--------|
| `/teams` | List/create teams | RLS: membership / global admin |
| `/team_ldap_maps` / `/team_oidc_maps` | Directory group → team role | Team admin+ |
| `/team_invites` | Invite metadata | Token hashes only |
| `/team_join_requests` | Join request workflow | status: pending/approved/rejected |
| `/projects` | Projects under teams | Optional `description` |
| `/groups` | Team-scoped groups | `source`: manual/ldap/oidc |
| `/group_members` | Group membership | |
| RBAC bindings UI/API | Role bindings | Scoped cluster/team/project/secret; not exposed as a public PostgREST table |
 |
| `/secrets` | Row metadata + `value_enc` | Soft-delete via `deleted_at`; `access_mode` |
| `/secret_meta` | Custom secret labels | Searchable in UI/API `q=` |
| `/secret_versions` | Prior ciphertexts | Filled on value change |
| `/secret_audit` | Secret actions | Append-only |
| `/secret_access_requests` | Reveal approval workflow | pending/approved/denied |
| `/org_audit` | Org / membership actions | |
| `/secret_pins` / `/secret_recent` | Per-user pins / recent | |
| `/machine_tokens` | Machine token **metadata** | Hashes only |
| `/user_directory` | User list view | Not a public directory via normal JWT policies |

### Examples

```bash
# List live secret metadata for a project
curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/secrets?project_id=eq.$SS_PROJECT&deleted_at=is.null&select=id,key,note,kind,expires_at,updated_at,last_accessed_at,access_mode"

# Custom metadata for a secret
curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/secret_meta?secret_id=eq.$SECRET_ID&select=key,value"

# List projects
curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/projects?select=id,name,team_id,created_at&order=name"
```

### OpenAPI from PostgREST

```bash
JWT=$(curl -s -H "Authorization: Bearer pat_…" \
  -H "Accept: application/json" \
  http://localhost:8080/api/token | jq -r .access_token)

curl -s -H "Authorization: Bearer $JWT" \
  -H 'Accept: application/openapi+json' \
  http://localhost:3000/ > docs/postgrest-openapi.json
```

See [postgrest-openapi.json](../postgrest-openapi.json) for a checked-in snapshot.

### HSM RPC security

HSM slot configuration is not a public PostgREST API. Anonymous callers cannot
invoke `api.list_hsm_slots()`; the former `api.hsm_slot_url(uuid)` RPC was removed.
Authenticated callers
may receive slot metadata, but `pkcs11_url` is null unless the caller is a global
admin. The URL resolver is reserved for internal application code, so HSM PINs
and module paths are not exposed through the API.

PostgREST also cannot select `machine_tokens.token_hash`; only token metadata is
available to authenticated users. Access-request and RBAC binding writes are
validated by database triggers in addition to the web UI checks.

### Important limitations

- **Creating secrets via PostgREST** requires a pre-encrypted `value_enc`.
  Prefer the UI or the machine **write** API.
- **Machine tokens** authenticate only `/eso/v1/…`, not PostgREST.
- **PATs** authenticate `/eso/v1/…` and `/api/token` → JWT for PostgREST.
  Never send `pat_…` to PostgREST directly.
- RLS is the access-control plane; a valid JWT without membership sees empty
  sets, not other teams' rows.

---

## Token cheatsheet

| Token | Example prefix | Endpoint family | Becomes |
|-------|----------------|-----------------|---------|
| Session | (cookie) | UI, `/api/token` | JWT optional |
| PAT | `pat_` | `/api/token`, **`/eso/v1/…`** | JWT → PostgREST; or plaintext secrets under RLS |
| JWT | `eyJ…` | PostgREST `:3000` | RLS as user |
| Machine | `ss_` | `/eso/v1/…` only | Project-scoped secret CRUD (plaintext) |

Full flows: [authentication.md](../admin/authentication.md).

---

## Related docs

- Authentication flows & token lifecycle: [authentication.md](../admin/authentication.md)
- Org RBAC, groups, Permissions/Metadata UI: [rbac.md](../admin/rbac.md)
- Deploy, env, OIDC, audit purge: [deploy.md](../admin/deploy.md)
- Machine accounts & ESO: [machine-tokens.md](../admin/machine-tokens.md)
- ESO manifests: [openshift-eso.yaml](../openshift-eso.yaml)
