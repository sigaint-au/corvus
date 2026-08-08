# API reference

Sigaint Secret Server exposes three machine-facing surfaces:

| Surface | Base | Auth | Plaintext secrets? |
|---------|------|------|--------------------|
| **App JSON** | `:8080` | Session or PAT (route-dependent) | No (except via UI HTML) |
| **ESO / machine / CLI** | `:8080/eso/v1/…` | `Authorization: Bearer ss_…` | **Yes** (decrypt with `MASTER_KEY`) |
| **PostgREST** | `:3000` (default) | `Authorization: Bearer <JWT>` | **No** — returns `value_enc` only |

> **Authentication flows, token lifecycle, and credential curl examples:**
> [authentication.md](./authentication.md).

---

## Which API should I use?

| Goal | Recommended API | Token |
|------|-----------------|-------|
| **CLI / CI: list, get, create, update, delete secrets (plaintext)** | ESO / machine API | Project machine token `ss_…` (**write** for mutate) |
| **OpenShift External Secrets Operator pull** | ESO `GET …/secrets/{key}` | Machine token `ss_…` (**read-only** is enough) |
| **Scripts: list teams/projects/metadata under user RLS** | PostgREST | PAT → JWT via `/api/token` |
| **Browser UI** | HTML session routes | Cookie session |

**Prefer the machine API** whenever a tool needs **plaintext** secret values or
to **create/update/delete** secrets without a browser. PostgREST cannot
decrypt values and cannot write plaintext `value` fields.

---

## Authentication (summary)

### 1. Browser session

Log in via the UI (`/login`, optional `/login/oidc`, optional `/login/2fa`).
Session cookie is used for HTML routes and for `GET /api/token` without a
Bearer header.

### 2. Personal access tokens (PAT)

Create under **My profile → Security**. Format: `pat_` + URL-safe secret
(shown once). Max 50 per user; optional expiry (1–3650 days).

- Act as that user under RLS after exchanging for a JWT.
- **Not** accepted on ESO routes (use machine tokens).

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

Errors: `401` `{"error":"unauthorized"}` if the PAT is invalid, revoked, or expired.

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

| Role | List / get | Create / update / delete |
|------|------------|---------------------------|
| `read-only` (default) | yes | **403** |
| `write` | yes | yes |

- Prefer **`read-only`** for ESO pull and read-only automation.
- Use **`write`** for CLI/CI that creates, rotates, or deletes secrets.

---

## App JSON endpoints (`:8080`)

### `GET /health`

Liveness / DB ping. No auth.

**200** `{"ok": true}`  
**503** `{"ok": false}`

---

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

---

### `GET /api/users/suggest?q=`

Email/name autocomplete for member fields. Requires **login** (session).

| Caller | Results |
|--------|---------|
| Global admin | Any active user matching `q` |
| Other users | Active users who share a team with the caller |

- `q` required (min length 1, max 80).
- Limit 15 rows.

**200**

```json
[
  {
    "email": "ada@example.com",
    "name": "Ada",
    "label": "Ada <ada@example.com>"
  }
]
```

On query failure returns `[]` (does not 500).

---

## Managing secrets via the machine API

**Base path:** `https://<host>/eso/v1/projects/<project_id>`

**Auth (all routes):**

```http
Authorization: Bearer ss_…
Content-Type: application/json   # for POST / PUT / PATCH bodies
```

Invalid token, expired token, or token for a different project →
**401** `{"error":"unauthorized"}`.

These routes are **CSRF-exempt** (Bearer token auth; no session cookie required).

### Setup for CLI / CI

1. Open the project in the UI → **Integrations** (or **Tokens**).
2. Create a machine token:
   - **read-only** — list/get only  
   - **write** — full secret management  
3. Copy the `ss_…` value (shown once) and the project UUID.
4. Optionally set a token expiry (1–3650 days).

```bash
export SS_URL="https://secrets.example.com"   # no trailing slash
export SS_TOKEN="ss_…"
export PID="<project-uuid>"
export AUTH="Authorization: Bearer $SS_TOKEN"
```

### Endpoint map

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| `GET` | `/secrets` | any | List bulk values **or** metadata |
| `GET` | `/secrets/{key}` | any | Get one secret (value + metadata) |
| `POST` | `/secrets` | **write** | Create or upsert (`key` in JSON body) |
| `PUT` | `/secrets/{key}` | **write** | Create or replace by path key |
| `PATCH` | `/secrets/{key}` | **write** | Partial update (secret must exist) |
| `DELETE` | `/secrets/{key}` | **write** | Soft-delete (moves to trash) |

`{key}` supports path-style keys (Flask `<path:key>`), e.g. `db/password`.

Full URLs look like:

```text
{SS_URL}/eso/v1/projects/{PID}/secrets
{SS_URL}/eso/v1/projects/{PID}/secrets/{key}
```

---

### Secret object fields

Returned by **get**, **create/upsert**, **put**, and **patch** (list metadata
omits `value`).

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID string | Secret row id |
| `key` | string | Name within the project (unique among live secrets) |
| `value` | string | Plaintext secret (only when decrypted for the caller) |
| `note` | string | Non-sensitive label / description |
| `kind` | string | `plain`, `database`, `certificate`, `ssh`, or `kv` |
| `expires_at` | ISO-8601 or `null` | Optional hard expiry |
| `created_at` | ISO-8601 or `null` | Row creation time |
| `updated_at` | ISO-8601 or `null` | Last update time |
| `ok` | boolean | Present on successful write responses |

---

### List secrets

#### Bulk values (ESO-compatible default)

Returns every live secret as a key → plaintext map. Suitable for bulk sync;
**not** ideal for interactive CLI listing (decrypts everything).

```bash
curl -s -H "$AUTH" \
  "$SS_URL/eso/v1/projects/$PID/secrets"
```

**200**

```json
{
  "secrets": {
    "DATABASE_URL": "postgres://…",
    "API_KEY": "…"
  }
}
```

#### Metadata only (recommended for CLI)

Does **not** decrypt values. Use for listing keys before a targeted get.

Query flags (any one enables metadata mode):

| Query | Effect |
|-------|--------|
| `meta=1` | Metadata list |
| `format=meta` | Same |
| `include_values=0` | Same |
| `q=<text>` | Optional filter: key or note substring (case-insensitive) |

```bash
# All keys in the project
curl -s -H "$AUTH" \
  "$SS_URL/eso/v1/projects/$PID/secrets?meta=1" | jq .

# Filter
curl -s -H "$AUTH" \
  "$SS_URL/eso/v1/projects/$PID/secrets?meta=1&q=api" | jq .
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
      "created_at": "2026-01-15T12:00:00+00:00",
      "updated_at": "2026-03-01T09:30:00+00:00"
    }
  ]
}
```

---

### Get a secret

```bash
curl -s -H "$AUTH" \
  "$SS_URL/eso/v1/projects/$PID/secrets/DATABASE_URL" | jq .
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
  "created_at": "2026-01-15T12:00:00+00:00",
  "updated_at": "2026-01-15T12:00:00+00:00"
}
```

**404** `{"error":"not found"}` — token valid, key missing  
**401** `{"error":"unauthorized"}`

**ESO:** keep using `jsonPath: $.value`. Extra fields are additive and safe for
existing webhooks.

---

### Create or update a secret (POST)

Creates a new secret or overwrites an existing live key. Requires role
**`write`**.

**Body** (`Content-Type: application/json`)

| Field | Required | Description |
|-------|----------|-------------|
| `key` | **yes** | Secret name |
| `value` | **yes** | Plaintext (may be `""`) |
| `note` | no | Non-sensitive label (default `""`) |
| `kind` | no | `plain` (default), `database`, `certificate`, `ssh`, `kv` |
| `expires_at` | no | ISO date/datetime; empty/`null` clears when this field is sent |
| `expires_days` | no | Integer days from now (alternative to `expires_at`) |
| `clear_expires` | no | Truthy (`true`, `1`, `yes`, …) → clear expiry |

```bash
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "key": "API_KEY",
    "value": "new-value",
    "note": "rotated by CI",
    "kind": "plain",
    "expires_days": 90
  }' \
  "$SS_URL/eso/v1/projects/$PID/secrets" | jq .
```

**200** — full secret object plus `"ok": true` (includes `value`).

Notes:

- Soft-deleted keys with the same name can be replaced (upsert semantics).
- Omitting all expiry fields leaves existing `expires_at` unchanged on update.
- Changing `value` archives the previous ciphertext in `secret_versions`.
- Audited as `machine_upsert` with actor email `machine`.

**400** validation errors (missing key/value, bad `kind`, bad expiry)  
**403** `{"error":"token is read-only"}` or `{"error":"forbidden"}`  
**401** unauthorized

---

### Replace a secret by key (PUT)

Same write semantics as POST, but **`key` is in the URL** (CLI-friendly).
Body must include `value`; optional `note`, `kind`, expiry fields as above.

```bash
curl -s -X PUT -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"value":"rotated-secret","note":"from cli"}' \
  "$SS_URL/eso/v1/projects/$PID/secrets/API_KEY" | jq .
```

**200** — same shape as POST upsert.

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

If `value` is omitted, the stored ciphertext is left unchanged (no spurious
version archive from re-encryption).

```bash
# Metadata only
curl -s -X PATCH -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"note":"rotated in CI","expires_days":90}' \
  "$SS_URL/eso/v1/projects/$PID/secrets/API_KEY" | jq .

# Rotate value only
curl -s -X PATCH -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"value":"brand-new-secret"}' \
  "$SS_URL/eso/v1/projects/$PID/secrets/API_KEY" | jq .
```

**200** — updated secret object (includes current `value`) + `"ok": true`  
**404** `{"error":"not found"}`  
**403** read-only token  
**400** validation errors

---

### Delete a secret (DELETE)

Soft-deletes the secret (moves it to the project/team **trash**). It can be
restored or permanently purged from the UI. Requires role **`write`**.

Audited as `deleted` with actor email `machine`.

```bash
curl -s -X DELETE -H "$AUTH" \
  "$SS_URL/eso/v1/projects/$PID/secrets/API_KEY" | jq .
```

**200**

```json
{"ok": true, "id": "a1b2c3d4-…", "key": "API_KEY"}
```

**404** `{"error":"not found"}`  
**403** `{"error":"token is read-only"}`  
**401** unauthorized

---

### CLI cookbook (copy-paste)

```bash
export SS_URL="https://secrets.example.com"
export SS_TOKEN="ss_…"
export PID="<project-uuid>"
AUTH=(-H "Authorization: Bearer $SS_TOKEN")

# 1) List keys (no values)
curl -s "${AUTH[@]}" "$SS_URL/eso/v1/projects/$PID/secrets?meta=1" | jq '.items[] | {key, note, kind, expires_at}'

# 2) Get one value
curl -s "${AUTH[@]}" "$SS_URL/eso/v1/projects/$PID/secrets/API_KEY" | jq -r .value

# 3) Create or replace
curl -s -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
  -d '{"value":"s3cret","note":"cli","kind":"plain"}' \
  "$SS_URL/eso/v1/projects/$PID/secrets/API_KEY" | jq .

# 4) Patch note / expiry without rotating value
curl -s -X PATCH "${AUTH[@]}" -H "Content-Type: application/json" \
  -d '{"note":"updated","expires_days":30}' \
  "$SS_URL/eso/v1/projects/$PID/secrets/API_KEY" | jq .

# 5) Soft-delete
curl -s -X DELETE "${AUTH[@]}" \
  "$SS_URL/eso/v1/projects/$PID/secrets/API_KEY" | jq .
```

### Error reference (machine API)

| HTTP | Body | Typical cause |
|------|------|----------------|
| **400** | `{"error":"key and value required"}` | Missing `key` or `value` on POST/PUT |
| **400** | `{"error":"kind must be one of: …"}` | Invalid `kind` |
| **400** | `{"error":"expires_days must be …"}` / ISO parse errors | Bad expiry input |
| **401** | `{"error":"unauthorized"}` | Missing/invalid/wrong-project/expired token |
| **403** | `{"error":"token is read-only"}` | Mutate with a read-only machine token |
| **403** | `{"error":"forbidden"}` | Write path denied by DB helper |
| **404** | `{"error":"not found"}` | Get/PATCH/DELETE on missing key |

### Audit actions written by the machine API

Every successful secret-touching machine/CLI call writes a row to
`api.secret_audit` via `private.audit_secret` (same table as the browser UI).

| HTTP operation | Audit `action` | Notes |
|----------------|----------------|-------|
| `GET …/secrets/{key}` (value returned) | `revealed` | Same action as UI reveal |
| `GET …/secrets` (bulk values) | `exported` | `secret_key` = `machine/values n=N` |
| `GET …/secrets?meta=1` | `exported` | `secret_key` = `machine/meta n=N` (+ optional `q=…`) |
| `POST` / `PUT` / `PATCH` | `machine_upsert` | Create or update |
| `DELETE …/secrets/{key}` | `deleted` | Soft-delete (trash) |

**Actor:** `user_id` is null (no JWT on machine connections). `actor_email` is
`machine:<token-name>:<token_prefix>` when the token can be resolved (e.g.
`machine:eso-pull:ss_abc12xyz`), otherwise `machine`.

Failed auth (401/403) and not-found (404) paths do **not** write audit rows.

---

### OpenShift ESO example

See [openshift-eso.yaml](./openshift-eso.yaml). Minimal shape:

```yaml
url: "https://secrets.example.com/eso/v1/projects/<PROJECT_ID>/secrets/{{ .remoteRef.key }}"
result:
  jsonPath: "$.value"
headers:
  Authorization: "Bearer {{ .auth.token }}"
```

Project **Integrations** can generate Secret + SecretStore YAML with the
configured Server URL and a machine token. Use a **read-only** token for ESO
pull unless the store also needs write access.

---

## PostgREST (`:3000`)

PostgREST exposes the Postgres **`api`** schema with **row-level security**.
Use the JWT from `/api/token`.

Default compose port: **3000**. Prefer the `postgrest` URL returned by
`/api/token` when configuring clients.

### What PostgREST is good for

- Listing teams, projects, and **secret metadata** as the authenticated user
- Membership and org automation under RLS
- Reading `secret_audit` / `org_audit` where permitted

### What PostgREST is **not** for

- Reading **plaintext** secret values (`value_enc` is Fernet ciphertext)
- Creating secrets with a plaintext `value` field (you would need to encrypt
  offline with `MASTER_KEY` — prefer the machine **write** API or UI)

### Conventions

- Prefer explicit `select=` columns.
- Filter: `?project_id=eq.<uuid>`, `?deleted_at=is.null`, etc.
  ([PostgREST filters](https://postgrest.org/en/stable/references/api/tables_views.html#horizontal-filtering)).
- Prefer `Accept: application/json`.

### Resources (tables / view)

| Path | Typical use | Notes |
|------|-------------|--------|
| `/teams` | List/create teams | RLS: membership / global admin |
| `/team_members` | Membership rows | `role`: owner, admin, member, viewer; `source`: manual, ldap, oidc |
| `/team_ldap_maps` | LDAP group → team role | Team admin+ |
| `/team_oidc_maps` | OIDC group → team role | Team admin+ |
| `/team_invites` | Invite metadata | Token hashes only |
| `/team_join_requests` | Join request workflow | status: pending, approved, rejected |
| `/projects` | Projects under teams | |
| `/project_members` | Project-scoped roles | `role`: admin, write, read |
| `/secrets` | Metadata + `value_enc` | Soft-delete via `deleted_at`; unique live `(project_id, key)` |
| `/secret_versions` | Prior ciphertexts | Filled on value change |
| `/secret_audit` | Secret actions | created, updated, revealed, deleted, restored, purged, machine_upsert, exported |
| `/org_audit` | Org / membership actions | |
| `/secret_pins` | Per-user pins | |
| `/secret_recent` | Per-user recent access | |
| `/machine_tokens` | Machine token **metadata** | Hashes only — raw `ss_…` never returned |
| `/user_directory` | User list view | Not a public directory via normal JWT policies |

### Example: list live secret metadata for a project

```bash
curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/secrets?project_id=eq.$PID&deleted_at=is.null&select=id,key,note,kind,expires_at,updated_at"
```

### Example: list projects

```bash
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

See [postgrest-openapi.json](./postgrest-openapi.json) for a checked-in snapshot.

### Important limitations

- **Creating secrets via PostgREST** requires a pre-encrypted `value_enc`. Prefer
  the UI or the machine **write** API for plaintext values.
- **Machine tokens** authenticate only `/eso/v1/…`, not PostgREST.
- **PATs** never go to PostgREST directly — always exchange at `/api/token` first.
- RLS is the access-control plane; a valid JWT without membership sees empty
  sets / permission errors, not other teams’ rows.

---

## Token cheatsheet

| Token | Example prefix | Endpoint family | Becomes |
|-------|----------------|-----------------|---------|
| Session | (cookie) | UI, `/api/token` | JWT optional |
| PAT | `pat_` | `/api/token` only | JWT → PostgREST |
| JWT | `eyJ…` | PostgREST `:3000` | RLS as user |
| Machine | `ss_` | `/eso/v1/…` only | Project-scoped secret CRUD (plaintext) |

Full flows: [authentication.md](./authentication.md).

---

## Related docs

- Authentication flows & token lifecycle: [authentication.md](./authentication.md)
- Deploy, env, OIDC, audit purge: [deploy.md](./deploy.md)
- ESO manifests: [openshift-eso.yaml](./openshift-eso.yaml)
