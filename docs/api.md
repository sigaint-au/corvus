# API reference

Three machine-facing surfaces:

| Surface | Base | Auth |
|---------|------|------|
| **App JSON** | `:8080` | Session, PAT (route-dependent) |
| **ESO / machine** | `:8080/eso/v1/…` | `Bearer ss_…` |
| **PostgREST** | `:3000` | `Bearer <JWT>` |

**Plaintext** only from ESO routes and the UI. PostgREST returns **`value_enc`**.

## Auth

| Kind | Prefix | Use |
|------|--------|-----|
| Session cookie | — | UI; can call `GET /api/token` |
| Personal access token | `pat_…` | Scripts → exchange for JWT |
| JWT (24h) | `eyJ…` | PostgREST (`JWT_SECRET`) |
| Machine token | `ss_…` | ESO only; one project; `read-only` or `write` |

### `GET /api/token`

Mint PostgREST JWT (session or `Authorization: Bearer pat_…`).

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "expires_in": 86400,
  "postgrest": "http://localhost:3000"
}
```

```bash
JWT=$(curl -s -H "Authorization: Bearer pat_…" \
  -H "Accept: application/json" \
  https://secrets.example.com/api/token | jq -r .access_token)
```

### `GET /health`

No auth. **200** `{"ok":true}` / **503** `{"ok":false}`.

## ESO / machine (`/eso/v1`)

```http
Authorization: Bearer ss_…
```

| Method | Path | Role | Response |
|--------|------|------|----------|
| `GET` | `/projects/{id}/secrets/{key}` | read | `{"value":"…","key":"…"}` |
| `GET` | `/projects/{id}/secrets` | read | `{"secrets":{"KEY":"…"}}` |
| `POST` | `/projects/{id}/secrets` | **write** | upsert body `{"key","value","note?"}` → `{"ok":true,"id","key"}` |

**401** bad token · **403** read-only on POST · **404** missing key.

ESO webhook shape: [openshift-eso.yaml](./openshift-eso.yaml)

```yaml
url: "https://secrets.example.com/eso/v1/projects/<PROJECT_ID>/secrets/{{ .remoteRef.key }}"
result:
  jsonPath: "$.value"
headers:
  Authorization: "Bearer {{ .auth.token }}"
```

## PostgREST (`:3000`)

JWT from `/api/token`. RLS applies. Prefer `select=` and `deleted_at=is.null`.

| Path | Notes |
|------|--------|
| `/teams`, `/team_members` | membership / roles |
| `/projects`, `/project_members` | project roles: admin, write, read |
| `/secrets` | metadata + `value_enc`; soft-delete `deleted_at` |
| `/secret_versions`, `/secret_audit` | history / audit |
| `/machine_tokens` | **hashes only** — never raw `ss_…` |

```bash
curl -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/secrets?project_id=eq.$PID&deleted_at=is.null&select=id,key,note"
```

OpenAPI snapshot: [postgrest-openapi.json](./postgrest-openapi.json) (regenerate after schema changes with a JWT + `Accept: application/openapi+json`).

**Limits:** don’t create secrets via PostgREST without pre-encrypted `value_enc` — use UI or machine write API. PATs are not accepted by PostgREST; exchange first. Machine tokens are not PostgREST credentials.

## Token cheatsheet

| Token | Talks to | Becomes |
|-------|----------|---------|
| Session | UI, `/api/token` | optional JWT |
| `pat_…` | `/api/token` only | JWT → PostgREST |
| JWT | PostgREST | user under RLS |
| `ss_…` | `/eso/v1` only | project scope |

Deploy / OIDC / purge: [deploy.md](./deploy.md).
