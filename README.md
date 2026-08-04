# Sigaint Secret Server

Minimal Bitwarden-style secrets manager: **teams → projects → secrets**, membership, machine tokens for **OpenShift External Secrets Operator**.

Stack: **Flask + HTMX + oat.ink** UI · **Postgres RLS** · **PostgREST** · **Podman Compose**.

App layout (`app/`): thin `app.py` entrypoint; modules `config`, `db`, `crypto`, `authz`, `settings_svc`, `ldap_auth`, `schema`, `nav`; HTTP handlers under `routes/`.

**Roles:** team `owner` / `admin` / `member`, plus **global admin** (server-wide). The first registered user becomes global admin; only global admins can open **Server settings** (registration toggle, classification banner, LDAP, promote admins).

**LDAP (optional):** enable under **Server settings**. Local accounts still work. On each LDAP login the app reads directory groups and applies:

- **LDAP group → roles** (global admin maps)
- **Team LDAP maps** (team owners/admins map a group → team role; membership `source=ldap` is re-synced on login; manual members are left alone)

## Quick start

```bash
cd secretstore
podman-compose up -d --build
# UI:  http://localhost:8080
# API: http://localhost:3000  (PostgREST; JWT from /api/token after login)
```

1. Register at `/register`
2. Create a team → project → secrets
3. Create a machine token on the project (copy once)
4. Point OpenShift ESO webhook at `/eso/v1/projects/<PROJECT_ID>/secrets/<KEY>`

See `examples/openshift-eso.yaml`.

## Model

| Concept | Notes |
|--------|--------|
| Team | Org unit; members have `owner` / `admin` / `member` |
| Project | Secret collection (primary access surface) |
| Secret | Key/value; value Fernet-encrypted at rest (`MASTER_KEY`) |
| Machine token | Project-scoped bearer for ESO / CI |
| LDAP role map | Directory group → `global_admin` |
| Team LDAP map | Directory group → team role (auto membership) |

## ESO webhook

```
GET /eso/v1/projects/{id}/secrets/{key}
Authorization: Bearer ss_…
→ {"value":"…"}   # jsonPath: $.value
```

## Env

| Variable | Default |
|----------|---------|
| `JWT_SECRET` | shared Flask ↔ PostgREST |
| `MASTER_KEY` | secret encryption |
| `SECRET_KEY` | Flask session |
| `GLOBAL_ADMIN_EMAIL` | optional; promotes that user on startup |
| `DATABASE_ADMIN_URL` | superuser DSN for schema upgrades (compose default: postgres) |

Change the secrets in production.

## PostgREST

After login, `GET /api/token` returns a JWT. Use:

```bash
curl -H "Authorization: Bearer $JWT" http://localhost:3000/projects
```

RLS enforces team/project membership.
