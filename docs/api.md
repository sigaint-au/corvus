# API reference

Sigaint Secret Server exposes three machine-facing surfaces:

| Surface | Base | Auth |
|---------|------|------|
| **App JSON** | `:8080` | Session, PAT, or machine token (route-dependent) |
| **ESO / machine** | `:8080/eso/v1/…` | `Authorization: Bearer ss_…` |
| **PostgREST** | `:3000` (default) | `Authorization: Bearer <JWT>` |

Secret **plaintext** is only returned by the ESO routes and the browser UI (after decrypt with `MASTER_KEY`). PostgREST returns **`value_enc`** (Fernet ciphertext), not plaintext.

> **Step-by-step authentication flows, token lifecycle, and `curl` examples for
> every credential type are in [authentication.md](./authentication.md).**

---

## Authentication

### 1. Browser session

Log in via the UI (`/login`, optional `/login/oidc`, optional `/login/2fa`). Session cookie is used for HTML routes and for `GET /api/token` without a Bearer header.

### 2. Personal access tokens (PAT)

Create under **My profile → Security**. Token format: `pat_` + URL-safe secret (shown once).

- Act as that user under RLS after exchanging for a JWT.
- Max 50 PATs per user; optional expiry (1–3650 days).
- **Not** accepted on ESO routes (use machine tokens).

Exchange:

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

Issued by `GET /api/token` (session or PAT). Signed with `JWT_SECRET`, role claim for PostgREST is typically `authenticated`. Lifetime: **24 hours**.

```bash
JWT=$(curl -s -H "Authorization: Bearer pat_…" \
  -H "Accept: application/json" \
  https://secrets.example.com/api/token | jq -r .access_token)

curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/projects?select=id,name,team_id"
```

Also available in the UI: **My profile → Security → API access → Show JWT**.

### 4. Machine tokens

Create on a project (**Integrations** / machine accounts). Format: `ss_…`.

| Role | List / get secret | Upsert secret |
|------|-------------------|---------------|
| `read-only` (default) | yes | 403 |
| `write` | yes | yes |

Scoped to **one project**. Prefer `read-only` for ESO.

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

## ESO / machine API (`:8080/eso/v1`)

All routes require:

```http
Authorization: Bearer ss_…
```

Invalid or wrong-project token → **401** `{"error":"unauthorized"}`.

### `GET /eso/v1/projects/{project_id}/secrets/{key}`

Single secret for ESO webhook. `jsonPath: $.value`.

**200**

```json
{"value": "plaintext-secret", "key": "DATABASE_URL"}
```

**404** `{"error":"not found"}` (token valid, key missing)  
**401** unauthorized

`key` is a path segment (supports nested path-style keys).

---

### `GET /eso/v1/projects/{project_id}/secrets`

Bulk map of all live secrets in the project.

```bash
curl -s -H "Authorization: Bearer ss_…" \
  "http://localhost:8080/eso/v1/projects/<PROJECT_ID>/secrets"
```

**200**

```json
{
  "secrets": {
    "DATABASE_URL": "…",
    "API_KEY": "…"
  }
}
```

---

### `POST /eso/v1/projects/{project_id}/secrets`

Create or update a secret. Requires machine role **`write`**.

**Request** (`Content-Type: application/json`)

```json
{
  "key": "API_KEY",
  "value": "new-value",
  "note": "optional label"
}
```

```bash
curl -s -X POST \
  -H "Authorization: Bearer ss_…" \
  -H "Content-Type: application/json" \
  -d '{"key":"API_KEY","value":"new-value","note":"optional label"}' \
  "http://localhost:8080/eso/v1/projects/<PROJECT_ID>/secrets"
```

- `key` and `value` required (`value` may be empty string).
- Soft-deleted keys with the same name are replaced (upsert semantics via SQL).

**200**

```json
{"ok": true, "id": "<uuid>", "key": "API_KEY"}
```

**400** `{"error":"key and value required"}`  
**403** `{"error":"token is read-only"}` or `{"error":"forbidden"}`  
**401** unauthorized

Writes an audit action `machine_upsert`.

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

Project **Integrations** tab can generate Secret + SecretStore YAML with the configured Server URL and a machine token.

---

## PostgREST (`:3000`)

PostgREST exposes the Postgres **`api`** schema with **row-level security**. Use the JWT from `/api/token`.

Default compose port: **3000**. Configure clients with the `postgrest` URL returned by `/api/token` when possible.

### Conventions

- Prefer explicit `select=` columns.
- Filter: `?project_id=eq.<uuid>`, `?deleted_at=is.null`, etc. ([PostgREST filters](https://postgrest.org/en/stable/references/api/tables_views.html#horizontal-filtering)).
- Prefer `Accept: application/json`.
- **Do not** treat `value_enc` as usable plaintext; decrypt only with the app’s `MASTER_KEY` (normally only the Flask app holds that).

### Resources (tables / view)

| Path | Typical use | Notes |
|------|-------------|--------|
| `/teams` | List/create teams | RLS: membership / global admin |
| `/team_members` | Membership rows | `role`: owner, admin, member, viewer; `source`: manual, ldap, oidc |
| `/team_ldap_maps` | LDAP group → team role | Team admin+ |
| `/team_oidc_maps` | OIDC group → team role | Team admin+ |
| `/team_invites` | Invite metadata | Token hashes only (not redeem URLs) |
| `/team_join_requests` | Join request workflow | status: pending, approved, rejected |
| `/projects` | Projects under teams | |
| `/project_members` | Project-scoped roles | `role`: admin, write, read |
| `/secrets` | Secret metadata + `value_enc` | Soft-delete via `deleted_at`; unique live `(project_id, key)` |
| `/secret_versions` | Prior ciphertexts | Filled on value change |
| `/secret_audit` | Secret actions | created, updated, revealed, deleted, restored, purged, machine_upsert, exported |
| `/org_audit` | Org / membership actions | |
| `/secret_pins` | Per-user pins | |
| `/secret_recent` | Per-user recent access | |
| `/machine_tokens` | Machine token metadata | **Hashes only** — raw `ss_…` never stored/returned |
| `/user_directory` | User list view | Granted to DB role `authenticator` for admin paths; not a public directory via normal JWT policies |

### Example: list live secrets for a project

```bash
curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/secrets?project_id=eq.$PID&deleted_at=is.null&select=id,key,note,expires_at,updated_at"
```

### Example: list projects

```bash
curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/projects?select=id,name,team_id,created_at&order=name"
```

### OpenAPI from PostgREST

PostgREST serves its schema at the root with:

```http
GET / HTTP/1.1
Host: localhost:3000
Accept: application/openapi+json
```

A snapshot of that document (paths/definitions for the `api` schema) can be regenerated
anytime PostgREST is up. Use an **authenticated** JWT so table paths are included (anonymous
OpenAPI only lists a few RPCs):

```bash
JWT=$(curl -s -H "Authorization: Bearer pat_…" \
  -H "Accept: application/json" \
  http://localhost:8080/api/token | jq -r .access_token)

curl -s -H "Authorization: Bearer $JWT" \
  -H 'Accept: application/openapi+json' \
  http://localhost:3000/ > docs/postgrest-openapi.json
```

See [postgrest-openapi.json](./postgrest-openapi.json) for a checked-in snapshot (regenerate after schema changes).

### Important limitations

- **Creating secrets via PostgREST** requires a pre-encrypted `value_enc`. Prefer the UI or the machine **write** upsert API for plaintext values.
- **Machine tokens** authenticate only the ESO routes, not PostgREST.
- **PATs** never go to PostgREST directly — always exchange at `/api/token` first.
- RLS is the access control plane; a valid JWT without membership sees empty sets / permission errors, not other teams’ rows.

---

## Token cheatsheet

| Token | Example prefix | Endpoint family | Becomes |
|-------|----------------|-----------------|---------|
| Session | (cookie) | UI, `/api/token` | JWT optional |
| PAT | `pat_` | `/api/token` only | JWT → PostgREST |
| JWT | `eyJ…` | PostgREST `:3000` | RLS as user |
| Machine | `ss_` | `/eso/v1/…` only | Project-scoped |

Full flows and curl examples: [authentication.md](./authentication.md).

---

## Related docs

- Authentication flows & token lifecycle with curl examples: [authentication.md](./authentication.md)
- Deploy, env, OIDC, audit purge: [deploy.md](./deploy.md)
- ESO manifests: [openshift-eso.yaml](./openshift-eso.yaml)
