# Configuration Reference

All environment variables and server settings for Sigaint Secret Server.

---

## Environment variables

### Required

| Variable | Purpose | Example |
|----------|---------|---------|
| `JWT_SECRET` | Flask ↔ PostgREST JWT signing (HS256) | 64 hex chars |
| `MASTER_KEY` | Fernet key for secret values | 64 hex chars |
| `SECRET_KEY` | Flask session cookie (+ TOTP recovery HMAC) | 64 hex chars |
| `DATABASE_URL` | App role (`authenticator`); RLS applies | `postgres://authenticator:…@db:5432/secretstore` |
| `DATABASE_ADMIN_URL` | Superuser DSN for schema upgrades (**required**) | `postgres://postgres:…@db:5432/secretstore` |

### Optional

| Variable | Default | Purpose |
|----------|---------|---------|
| `POSTGREST_URL` | `http://localhost:3000` | PostgREST base URL |
| `REDIS_URL` | unset | Shared project-key cache; Compose uses `redis://redis:6379/0` |
| `REDIS_DEK_CACHE_TTL` | `300` | Project-key cache lifetime in seconds |
| `GLOBAL_ADMIN_EMAIL` | — | Promote this email to global admin on first login |
| `BOOTSTRAP_ADMIN_EMAIL` | — | Same as `GLOBAL_ADMIN_EMAIL` if unset |
| `ALLOW_INSECURE_DEFAULTS` | `0` | `1` only for local dev defaults |
| `COOKIE_SECURE` | on in production | `0` disables; off when `FLASK_ENV=development` or `ALLOW_INSECURE_DEFAULTS` |
| `CLIPBOARD_CLEAR_SECONDS` | `30` | UI clipboard auto-clear; `0` disables |
| `REVEAL_AUTO_HIDE_SECONDS` | `30` | Auto-hide revealed values; `0` disables |
| `REVEAL_ACCESS_GRANT_MINUTES` | `15` | Default approved-reveal grant duration (minutes) |
| `MAX_CONTENT_LENGTH` | `1 MiB` | Request/import size cap (memory DoS guard) |

> `DATABASE_ADMIN_URL` is **required** — the app uses it for idempotent schema
> upgrades (`app/core/schema.py`). Compose sets it for you.

---

## Server settings (UI)

Configured under **Administration → Server settings**. Stored in
`private.server_settings`.

### General

| Setting | Default | Purpose |
|---------|---------|---------|
| Server URL | `""` | Public base URL (no trailing slash); OIDC redirect + ESO YAML default |
| Brand name | `Sigaint` | Sidebar / page titles / mail / TOTP issuer |
| Brand tagline | `Secret Server` | Sidebar subtitle |
| Classification | `false` | Show a classification banner (text/color) |
| Registration | `true` | Allow self-registration |
| User team creation | `true` | Allow users to create teams |

### Security

| Setting | Default | Purpose |
|---------|---------|---------|
| TOTP enforce global admins | `false` | Force global admins to enroll 2FA |

### Email (SMTP)

| Setting | Default | Purpose |
|---------|---------|---------|
| SMTP enabled | `false` | Send password-reset / login-alert emails |
| Host / Port | `""` / `587` | SMTP server |
| Encryption | `starttls` | `none` \| `starttls` \| `ssl` |
| Username / Password | — | SMTP auth |
| From email / name | — | Sender |
| Login alerts | `false` | Email on new login |

### LDAP

| Setting | Default | Purpose |
|---------|---------|---------|
| LDAP enabled | `false` | Bind login + group sync |
| URL | `""` | e.g. `ldaps://…` |
| StartTLS | `false` | Reject cleartext unless enabled |
| Bind DN / password | — | Service account |
| User base / filter | — | User lookup (`{login}` placeholder) |
| Email / name attrs | `mail` / `displayName` | Attribute mapping |
| Group base / filter | — | Group membership |
| Use memberOf | `true` | Use `memberOf` attribute |

### OIDC / SSO

| Setting | Default | Purpose |
|---------|---------|---------|
| OIDC enabled | `false` | Authorization-code SSO |
| Issuer | `""` | e.g. `https://idp.example/realms/myrealm` |
| Client ID / secret | — | Confidential client |
| Scopes | `openid email profile` | OpenID scopes |
| Button label | `Sign in with SSO` | Login button text |
| Username claim | `preferred_username` | Display name on upsert |
| Groups claim | `groups` | Group list claim |
| Require verified email | `true` | Require `email_verified` claim |

### Auditing

| Setting | Default | Purpose |
|---------|---------|---------|
| Audit retention (days) | `365` | `0` = keep forever; applied by purge-audit |

---

## Key constants (code)

| Constant | Value | Purpose |
|----------|-------|---------|
| `RBAC_TEAM_ROLE_DROPDOWN` | `team-owner, team-admin, team-member, team-viewer` | Team role dropdown |
| `RBAC_PROJECT_ROLE_DROPDOWN` | `project-admin, project-write, project-reveal, project-read` | Project role dropdown |
| `RBAC_SECRET_ROLE_DROPDOWN` | `secret-write, secret-reveal, secret-read` | Secret role dropdown |
| `RBAC_SERVICE_ROLE_DROPDOWN` | `service-write, service-reveal, service-read` | Machine token role dropdown |
| `MACHINE_TOKEN_ROLES` | `service-read, service-reveal, service-write` | Machine account roles |
| `INVITE_ROLES` | `team-admin, team-member, team-viewer` | Roles allowed for invites (not `team-owner`) |
| `ACCESS_MODES` | `inherit, restricted` | Secret access modes |
| `ACCESS_MODE_LABELS` | `inherit → "Inherit project access"`, `restricted → "Restricted (role bindings only)"` | Access mode labels |
| `RBAC_VERBS` | `get, list, create, update, delete, reveal, admin, *` | RBAC verbs |
| `RBAC_RESOURCES` | `teams, projects, secrets, bindings, roles, audit` | RBAC resources |
| `RBAC_SCOPE_KINDS` | `cluster, team, project, secret` | RBAC scope kinds |
| `RBAC_SUBJECT_KINDS` | `User, Group, ServiceAccount` | RBAC subject kinds |
| `RBAC_BUILTIN_ROLES` | (see `core/config.py`) | All built-in role names |
| `REVEAL_ACCESS_GRANT_CHOICES` | `15, 60, 240, 1440` | Allowed grant durations (minutes) |
| `SECRET_KINDS` | `plain, database, certificate, ssh, kv` | Structured secret kinds |
| `MAX_EXPIRY_DAYS` | `3650` | Max optional expiry |
| `SIDEBAR_PINS_LIMIT` | `8` | Sidebar pinned secrets |
| `SIDEBAR_RECENT_LIMIT` | `8` | Sidebar recent secrets |

---

## Related docs

- [deploy.md](deploy.md) — deployment guide
- [rbac.md](rbac.md) — RBAC access model
- [authentication.md](authentication.md) — auth flows
