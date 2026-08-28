# Authentication and token flows

Every way a caller can authenticate, the exact flow for each, and concrete
`curl` examples.

There are four credential types. Everything maps to one of two enforcement
planes:

| Credential | Prefix / form | Where used | Enforced by |
|------------|---------------|------------|-------------|
| Browser session | cookie (`session`) | UI (HTML), `GET /api/token` | Flask session + server-side session registry |
| Personal Access Token (PAT) | `pat_…` | `/api/token` → JWT; **and** `/eso/v1/…` plaintext | Flask PAT table; user RLS on secrets |
| CLI session token | `sso_…` | `/eso/v1/…`, `/api/v1/manage`, `/api/token` | Flask CLI-session table; user RLS on secrets |
| Short-lived JWT | `eyJ…` (HS256) | PostgREST `:3000` | Postgres RLS (`request.jwt.claims`) |
| Machine token | `ss_…` | `/eso/v1/…` only | Postgres SECURITY DEFINER functions |

> **Plaintext** secret values are only returned by the browser UI and the
> `/eso/v1` routes (after decryption with `MASTER_KEY`), for **machine tokens**
> or **PATs**. PostgREST returns `value_enc` (Fernet ciphertext), never
> plaintext.

---

## 1. Browser session flow

The browser flow is the only one that uses a cookie. It is **two-step** when
2FA is enabled, and can be forced through TOTP enrollment for global admins.

### 1a-0. Email verification (local signups)

When SMTP is configured, self-registered accounts start **unverified** and
receive a single-use link (`/verify-email/<token>`, valid 3 days) before they
can sign in. The link is stored hashed. Signing in with an unverified
account shows a verify-your-email page with a resend button; resends answer
generically and send at most one email per address per minute.
LDAP/OIDC-provisioned accounts skip this: the directory already proves the
mailbox. Without SMTP, new accounts are active immediately (fail-open).
### 1a. Password (local) or LDAP login

```
POST /login
  form: email, password
```

1. Check the login lockout counter (`private.login_failures`). 5 failed
   attempts → 5 minute lockout.
2. Try local password verification (`private.verify_user`).
3. If that fails and LDAP is enabled, try LDAP bind + group sync.
4. On success check whether the account needs a 2FA step:
   - `verify` → redirect to `/login/2fa` (step 1b)
   - `enroll` (global admin + enforcement on) → redirect to `/totp/setup`
   - otherwise → full session established.

A full session sets `user_id`, `email`, `name`, `is_global_admin`, a `jwt`
(for PostgREST), and a server-side session id `sid`. The cookie is `HttpOnly`,
`SameSite=Lax`, and `Secure` unless `FLASK_ENV=development` (set `COOKIE_SECURE=0` to disable).

### 1b. Two-factor (TOTP) challenge

```
POST /login/2fa
  form: code
```

- `code` is a 6-digit TOTP, or a recovery code (8 or 32 hex chars).
- Recovery codes are single-use and HMAC-hashed at rest.
- On success the pending-2FA session keys are replaced with a full session.

### 1c. Forced TOTP enrollment (global admins)

```
GET  /profile/2fa        → shows QR + secret
POST /profile/2fa/confirm  form: code
GET  /profile/2fa/recovery-codes  → shows 10 recovery codes once
```

Until enrollment completes, `validate_registered_session` blocks all other
routes.

### 1d. Using the session

The session cookie is sufficient for all HTML routes and for `GET /api/token`
**without** an `Authorization` header:

```bash
curl -s -b cookies.txt -H "Accept: application/json" \
  http://localhost:8080/api/token
```

### 1e. Logout

`POST /logout` revokes the server-side session and clears the cookie. Sessions
are also revocable individually or "all others" from **My profile → Security**.

---

## 2. Personal Access Token (PAT) flow

PATs are for scripts that talk to PostgREST without a browser.

### Create

**My profile → Security → Personal access tokens**. Format: `pat_` + URL-safe
secret. Shown **once**. Max 50 per user, optional expiry (1–3650 days).

### Exchange for a JWT

PATs are **never** sent to PostgREST directly. Exchange them at `GET /api/token`:

```bash
JWT=$(curl -s \
  -H "Authorization: Bearer pat_XXXX..." \
  -H "Accept: application/json" \
  http://localhost:8080/api/token | jq -r .access_token)
```

Response:

```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 3600,
  "postgrest": "http://localhost:3000"
}
```

The JWT acts as **that user** under RLS for at most 1 hour. Invalid / revoked /
expired PATs return `401 {"error":"unauthorized"}`.

### Use the JWT against PostgREST

```bash
curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/projects?select=id,name,team_id"
```

---

## 2b. CLI session token flow (copy login command)

A CLI session token (`sso_…`) is a short-lived, user-scoped opaque token that
lets a signed-in user hand a ready-made `corvus login` command to a shell
without minting a long-lived PAT.

Click **Copy login command** in the sidebar footer. A dialog mints the token
and shows the command:

```bash
corvus login --url https://secrets.example.com --token sso_…
```

- Opaque, stored as a SHA-256 hash in `private.cli_session_tokens`.
- Multi-use within its TTL; `last_used_at` bumps on each use.
- Lifetime is the server setting `cli_session_ttl_seconds` (default **3600**,
  i.e. 1 hour; clamped to at least 60).
- User-wide: acts as that user under RLS (same as a PAT), so `/eso/v1` accepts
  a project UUID or unique name.

The raw token is shown once and is not retrievable after the dialog closes.

---

## 3. Machine token flow (ESO / CI / CLI)

Machine tokens (`ss_…`) are **project-scoped** and authenticate `/eso/v1`.
**PATs** (`pat_…`) also authenticate `/eso/v1` under user RLS (project UUID or
unique name).

Create a token on a project under **Integrations** (or **Tokens**). Project
or team admins only. Name the keys on the allow-list (`*` skips restricted
secrets). Roles:

| Role | Metadata | Reveal values | Write |
|------|----------|---------------|-------|
| `service-read` | yes | no | no |
| `service-reveal` | yes | yes | no |
| `service-write` | yes | yes | yes |

Raw `ss_…` tokens are stored only as SHA-256 hashes; the raw value is shown
once at creation.

```bash
export SS_URL="http://localhost:8080"
export SS_TOKEN="ss_XXXX..."
export SS_PROJECT="<PROJECT_ID>"
AUTH=(-H "Authorization: Bearer $SS_TOKEN")
```

### Fetch a single secret

```bash
curl -s "${AUTH[@]}" \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets/DATABASE_URL"
```

```json
{
  "id": "<uuid>",
  "key": "DATABASE_URL",
  "value": "postgres://...",
  "note": "",
  "kind": "plain",
  "expires_at": null,
  "access_mode": "inherit",
  "created_at": "…",
  "updated_at": "…",
  "last_accessed_at": "…",
  "last_accessed_by": "alice@example.com",
  "metadata": { "owner": "platform-team", "env": "prod" }
}
```

ESO continues to use `jsonPath: $.value` (extra fields are additive). A
successful **PAT** get updates `last_accessed_*`.

**403 on get (PAT):** `{"error":"approval_required",…}` if reveal approval is
required; `{"error":"forbidden"}` if per-secret access mode denies reveal. Machine
tokens (`ss_…`) skip human access mode and approval.

### Fetch all secrets (bulk value map)

```bash
curl -s "${AUTH[@]}" \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets"
```

```json
{"secrets": {"DATABASE_URL": "...", "API_KEY": "..."}}
```

PAT bulk list with values only includes secrets the caller may reveal (access
mode + approval). Machine tokens return all live keys in the project.

### List metadata only (CLI never returns plaintext)

```bash
curl -s "${AUTH[@]}" \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets?meta=1"
# filter key, note, or custom metadata key/value:
#   &q=api
#   &q=platform-team
```

### Create or replace (write role)

```bash
# POST upsert
curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
  -d '{"key":"API_KEY","value":"new-value","note":"optional label","expires_days":90}' \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets"

# PUT replace / create by path
curl -s -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
  -d '{"value":"rotated","note":"from cli"}' \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets/API_KEY"
```

Optional body fields: `note`, `kind` (`plain`|`database`|`certificate`|`ssh`|`kv`),
`expires_at`, `expires_days`, `clear_expires`.

### Partial update (write role)

Secret must already exist. Omitted fields keep current values; omit `value` to
change only note/kind/expiry without rotating ciphertext.

```bash
curl -s -X PATCH "${AUTH[@]}" -H "Content-Type: application/json" \
  -d '{"note":"rotated in CI","expires_days":90}' \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets/API_KEY"
```

### Soft-delete (write role)

```bash
curl -s -X DELETE "${AUTH[@]}" \
  "$SS_URL/eso/v1/projects/$SS_PROJECT/secrets/API_KEY"
```

```json
{"ok": true, "id": "<uuid>", "key": "API_KEY"}
```

### Errors

| Code | Meaning |
|------|---------|
| `400` | Missing key/value, bad `kind`, bad expiry |
| `401` | Missing/invalid/wrong-project/expired token |
| `403` | Read-only token used for a write |
| `404` | Key not found (get / patch / delete) |

---

## 4. JWT / PostgREST flow

The JWT is the bridge between the app and PostgREST. Minted by `GET /api/token`
from a session or PAT, signed with `JWT_SECRET` (HS256), carrying `sub`
(user id), `role: authenticated`, and a 1h `exp`.

PostgREST maps the JWT `role` to the DB role `authenticated` and reads the `sub`
claim from `request.jwt.claims` for RLS. **RLS is the access-control plane**: a valid JWT with no membership sees empty sets, not other teams' rows.

```bash
JWT=$(curl -s -H "Authorization: Bearer pat_XXXX..." \
  -H "Accept: application/json" \
  http://localhost:8080/api/token | jq -r .access_token)

curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/secrets?project_id=eq.<PID>&deleted_at=is.null&select=id,key,note,kind,expires_at"
```

The UI can also show a ready JWT under **My profile → Security → API access →
Show JWT**.

---

## 5. OIDC / SSO flow

OIDC is an **authorization-code** flow. Configure under **Administration →
Server settings → OIDC / SSO**.

```
1. User clicks "Sign in with SSO"  →  GET /login/oidc
2. App generates state + nonce, stores them in the session, redirects to IdP:
     GET {issuer}/protocol/openid-connect/auth
        ?response_type=code&client_id=...&redirect_uri={server_url}/login/oidc/callback
        &scope=openid email profile&state=...&nonce=...
3. IdP redirects back:  GET /login/oidc/callback?code=...&state=...
4. App validates state, exchanges code for tokens, verifies the ID token
   (asymmetric RS/ES/PS only, checks nonce, issuer, audience, exp).
5. If email_verified is required (default), the claim must be true.
6. User is upserted by email (auth_source=oidc); group→role maps apply.
7. Then the normal 2FA / session logic runs.
```

Key security properties:

- `state` prevents CSRF on the callback; `nonce` binds the ID token to the
  login attempt.
- ID token signature algorithms restricted to asymmetric (RS/ES/PS).
- Discovery documents cached 1 hour and cleared when settings are saved.
- Local password login still works for break-glass accounts.

### OIDC group → role mapping

- **Server settings → OIDC / SSO → OIDC group → roles** maps a group to
  `global_admin`.
- **Team → Settings → OIDC group membership** maps a directory group to a
  directory-managed `rbac.bindings` row. Manual memberships are never overwritten.
- **Team → Groups** can create a first-class group with `source=oidc` and an
  `external_key` matching the claim value; on login, matching users are synced
  into `group_members`. That group can hold a **team role**, a **project role**,
  or a **secret ACL** grant.

Groups come from the configured groups claim (default `groups`) plus
`realm_access.roles` when present. Maps apply on each SSO login; manual
memberships are not removed.

---

## 6. LDAP flow

LDAP is a **bind login** plus optional group → role sync.

```
POST /login  (email, password)
  → local verify fails
  → LDAP bind with the supplied credentials
  → on success: sync/upsert user (auth_source=ldap), read groups
  → apply LDAP group → team role / global-admin maps
  → sync first-class group memberships (external_key)
  → normal 2FA / session logic
```

- LDAP over cleartext is rejected unless StartTLS is enabled.
- **Team → Settings → LDAP group membership** maps a group to a direct
  team-scope RBAC role binding.
- **Team → Groups** with `source=ldap` + `external_key` syncs membership into
  `group_members`.
- **Server settings → LDAP → LDAP group → roles** maps a group to
  `global_admin`.

For team / project / secret RBAC with groups end-to-end, see [rbac.md](rbac.md).

---

## 7. Password reset flow

For **local** accounts only (LDAP/OIDC accounts have no local password).

```
POST /forgot-password  form: email
  → if a local account exists, create a single-use token (1h expiry)
  → email the reset link if SMTP is configured
  → identical response regardless of whether the account exists (no enumeration)

GET  /reset-password/<token>
POST /reset-password/<token>  form: password, password_confirm
  → validate token (single-use, not expired)
  → set new password (min 8 chars)
  → revoke ALL sessions for that user
```

Reset tokens are stored as SHA-256 hashes. Global admins can also issue a reset
for any local user from **Administration → Users**.

---

## 8. Token comparison & lifecycle

| Token | Lifetime | Shown once? | Revocation | Storage at rest |
|-------|----------|-------------|------------|-----------------|
| Session | 14 days idle / sliding | n/a | Per-session revoke, "sign out all", password change, admin disable | Server-side `private.user_sessions` + signed cookie |
| PAT | Optional 1–3650 days | yes | Revoke in UI | SHA-256 hash |
| JWT | 1 hour | n/a | Not revocable (short-lived) | Not stored |
| Machine (`ss_`) | Optional 1–3650 days | yes | Delete in UI | SHA-256 hash |
| Invite link | 1–90 days | yes | Revoke in UI | SHA-256 hash |
| Password reset | 1 hour | yes | n/a | SHA-256 hash |

### Security notes

- PATs and machine tokens are stored as **unsalted SHA-256** hashes. That is
  acceptable for high-entropy random tokens, which resist brute force even
  from a DB leak.
- TOTP recovery codes are **HMAC-SHA256** with `SECRET_KEY`.
- Secret values are **Fernet-encrypted** with `MASTER_KEY` at rest; only the
  app and ESO routes decrypt them.
- PostgREST never sees plaintext, only `value_enc`.

---

## Related docs

- Full HTTP / ESO / PostgREST reference: [api.md](../dev/api.md)
- Deploy, env vars, bootstrap, OIDC/LDAP config: [deploy.md](deploy.md)
- Machine accounts: [machine-tokens.md](machine-tokens.md)
- ESO pull and push: [external-secrets.md](external-secrets.md)
