# Authentication & Token Flows

This document explains **every way a caller can authenticate** to Sigaint Secret
Server, the exact step-by-step flow for each, and concrete `curl` examples.

There are four credential types. Everything ultimately maps to one of two
enforcement planes:

| Credential | Prefix / form | Where it is used | Enforced by |
|------------|---------------|------------------|-------------|
| Browser session | cookie (`session`) | UI (HTML), `GET /api/token` | Flask session + server-side session registry |
| Personal Access Token (PAT) | `pat_…` | `GET /api/token` only | Flask (`private.personal_access_tokens`) |
| Short-lived JWT | `eyJ…` (HS256) | PostgREST `:3000` | Postgres RLS (`request.jwt.claims`) |
| Machine token | `ss_…` | `/eso/v1/…` only | Postgres SECURITY DEFINER functions |

> **Plaintext** secret values are only returned by the browser UI and the
> `/eso/v1` machine routes (after decryption with `MASTER_KEY`). PostgREST
> returns `value_enc` (Fernet ciphertext), never plaintext.

---

## 1. Browser session flow

The browser flow is the only one that uses a cookie. It is a **two-step**
process when 2FA is enabled, and can be forced through TOTP enrollment for
global admins.

### 1a. Password (local) or LDAP login

```
POST /login
  form: email, password
```

1. The app checks the login lockout counter (`private.login_failures`).
   5 failed attempts → 5 minute lockout.
2. It tries local password verification (`private.verify_user`).
3. If that fails and LDAP is enabled, it tries LDAP bind + group sync.
4. On success it checks whether the account needs a 2FA step:
   - `verify` → redirect to `/login/2fa` (step 1b)
   - `enroll` (global admin + enforcement on) → redirect to `/totp/setup`
   - otherwise → full session is established.

A full session sets `user_id`, `email`, `name`, `is_global_admin`, a `jwt`
(for PostgREST), and a server-side session id `sid`. The cookie is
`HttpOnly`, `SameSite=Lax`, and `Secure` when `COOKIE_SECURE=1`.

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
routes (`_TOTP_SETUP_OK` allow-list).

### 1d. Using the session

Once logged in, the session cookie is sufficient for:

- All HTML routes.
- `GET /api/token` **without** an `Authorization` header → returns a JWT for
  the logged-in user.

```bash
# With a browser session cookie:
curl -s -b cookies.txt -H "Accept: application/json" \
  http://localhost:8080/api/token
```

### 1e. Logout

`POST /logout` revokes the server-side session (`private.user_sessions`) and
clears the cookie. Sessions are also revocable individually or "all others"
from **My profile → Security**.

---

## 2. Personal Access Token (PAT) flow

PATs are for **scripts** that need to talk to PostgREST without a browser.

### Create

Created in the UI: **My profile → Security → Personal access tokens**.
Format: `pat_` + URL-safe secret. Shown **once**. Max 50 per user, optional
expiry (1–3650 days).

### Exchange for a JWT

PATs are **never** sent to PostgREST directly. You exchange them at
`GET /api/token`:

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
  "expires_in": 86400,
  "postgrest": "http://localhost:3000"
}
```

The JWT acts as **that user** under RLS for 24 hours. Invalid / revoked /
expired PATs return `401 {"error":"unauthorized"}`.

### Use the JWT against PostgREST

```bash
curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/projects?select=id,name,team_id"
```

---

## 3. Machine token flow (ESO / CI)

Machine tokens (`ss_…`) are **project-scoped** and only authenticate the
`/eso/v1` routes. They are created on a project under **Integrations** (or
**Tokens**). Roles:

| Role | `GET` / list secrets | `POST` upsert |
|------|----------------------|---------------|
| `read-only` (default) | yes | **403** |
| `write` | yes | yes |

Raw `ss_…` tokens are stored only as SHA-256 hashes; the raw value is shown
once at creation.

### Fetch a single secret (ESO webhook)

```bash
curl -s -H "Authorization: Bearer ss_XXXX..." \
  "http://localhost:8080/eso/v1/projects/<PROJECT_ID>/secrets/DATABASE_URL"
```

```json
{"value": "postgres://...", "key": "DATABASE_URL"}
```

### Fetch all secrets (bulk sync)

```bash
curl -s -H "Authorization: Bearer ss_XXXX..." \
  "http://localhost:8080/eso/v1/projects/<PROJECT_ID>/secrets"
```

```json
{"secrets": {"DATABASE_URL": "...", "API_KEY": "..."}}
```

### Upsert a secret (write role)

```bash
curl -s -X POST \
  -H "Authorization: Bearer ss_XXXX..." \
  -H "Content-Type: application/json" \
  -d '{"key":"API_KEY","value":"new-value","note":"optional label"}' \
  "http://localhost:8080/eso/v1/projects/<PROJECT_ID>/secrets"
```

```json
{"ok": true, "id": "<uuid>", "key": "API_KEY"}
```

Errors: `400` missing key/value, `403` read-only token, `401` unauthorized.

---

## 4. JWT / PostgREST flow

The JWT is the bridge between the app and PostgREST. It is minted by
`GET /api/token` from either a session or a PAT, signed with `JWT_SECRET`
(HS256), and carries `sub` (user id), `role: authenticated`, and a 24h `exp`.

PostgREST maps the JWT `role` to the DB role `authenticated` and reads the
`sub` claim from `request.jwt.claims` for RLS. **RLS is the access-control
plane** — a valid JWT with no membership sees empty sets, not other teams'
rows.

```bash
JWT=$(curl -s -H "Authorization: Bearer pat_XXXX..." \
  -H "Accept: application/json" \
  http://localhost:8080/api/token | jq -r .access_token)

# List live secrets in a project
curl -s -H "Authorization: Bearer $JWT" \
  "http://localhost:3000/secrets?project_id=eq.<PID>&deleted_at=is.null&select=id,key,note,kind,expires_at"
```

> The UI can also show a ready JWT under **My profile → Security → API access
> → Show JWT**.

---

## 5. OIDC / SSO flow

OIDC is an **authorization-code** flow. Configure it under
**Administration → Server settings → OIDC / SSO**.

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
7. Then the normal 2FA / session logic runs (_post_password_login).
```

Key security properties:

- `state` prevents CSRF on the callback; `nonce` binds the ID token to the
  login attempt.
- ID token signature algorithms are restricted to asymmetric (RS/ES/PS).
- Discovery documents are cached 1 hour and cleared when settings are saved.
- Local password login still works for break-glass accounts.

### OIDC group → role mapping

- **Server settings → OIDC / SSO → OIDC group → roles** maps a group to
  `global_admin`.
- **Team → Settings → OIDC group membership** maps a group to a team role.
- Groups come from the configured groups claim (default `groups`) plus
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
  → normal 2FA / session logic
```

- LDAP over cleartext is rejected unless StartTLS is enabled
  (`ldap_tls_required_ok`).
- **Team → Settings → LDAP group membership** maps a group to a team role.
- **Server settings → LDAP → LDAP group → roles** maps a group to
  `global_admin`.

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

Reset tokens are stored as SHA-256 hashes. Global admins can also issue a
reset for any local user from **Administration → Users**.

---

## 8. Token comparison & lifecycle

| Token | Lifetime | Shown once? | Revocation | Storage at rest |
|-------|----------|-------------|------------|-----------------|
| Session | 14 days idle / sliding | n/a | Per-session revoke, "sign out all", password change, admin disable | Server-side `private.user_sessions` + signed cookie |
| PAT | Optional 1–3650 days | yes | Revoke in UI | SHA-256 hash |
| JWT | 24 hours | n/a | Not revocable (short-lived) | Not stored |
| Machine (`ss_`) | Optional 1–3650 days | yes | Delete in UI | SHA-256 hash |
| Invite link | 1–90 days | yes | Revoke in UI | SHA-256 hash |
| Password reset | 1 hour | yes | n/a | SHA-256 hash |

### Security notes

- PATs and machine tokens are stored as **unsalted SHA-256** hashes. This is
  acceptable for high-entropy random tokens (they are not brute-forceable from
  a DB leak), but see the recommendations in the review if you want HMAC.
- TOTP recovery codes are **HMAC-SHA256** with `SECRET_KEY` (not plain SHA).
- Secret values are **Fernet-encrypted** with `MASTER_KEY` at rest; only the
  app and ESO routes decrypt them.
- PostgREST never sees plaintext — only `value_enc`.

---

## Related docs

- Full HTTP / ESO / PostgREST reference: [api.md](./api.md)
- Deploy, env vars, bootstrap, OIDC/LDAP config: [deploy.md](./deploy.md)
- ESO manifests: [openshift-eso.yaml](./openshift-eso.yaml)
