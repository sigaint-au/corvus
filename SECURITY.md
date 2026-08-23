# Security Policy

## Supported versions

Security fixes land on `main` and are cut to `release` as calendar-version
tags (for example `2026.8.23.1`, matching `pyproject.toml`). If you deploy
from a tag or fork, pull the latest tag or rebase onto `main` regularly.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately so we can assess impact and ship a fix before disclosure:

1. **Email:** [security@sigaint.au](mailto:security@sigaint.au)  
   Use a clear subject (e.g. `corvus: …`). Include:
   - Affected component (UI, `/eso/v1`, PostgREST, CLI, schema/RLS, deploy)
   - Version or commit hash if known
   - Steps to reproduce and expected vs actual behaviour
   - Impact (auth bypass, secret disclosure, privilege escalation, DoS, etc.)
   - Any proof-of-concept (keep it minimal; no mass scanning of third parties)

2. **Gitea private channel:** if you have access to the Sigaint org, open a
   **private** security report / confidential issue against
   [Sigaint/corvus](https://git.sigaint.au/Sigaint/corvus).

We aim to acknowledge reports within **5 business days** and to provide a
status update within **14 days**. Coordinated disclosure is preferred; please
allow a reasonable window for a patch before public discussion.

## Scope

In scope:

- Authentication and session handling (local, LDAP, OIDC, TOTP, lockout)
- Authorization and Postgres RLS / `api.can_*` helpers
- Secret encryption at rest (`MASTER_KEY`), export paths, machine tokens, PATs
- CSRF, open redirects, injection in the Flask UI and APIs
- Multi-tenant isolation (teams, projects, per-secret access mode)

Out of scope (unless they enable a product vulnerability):

- Issues only in third-party images (Postgres, PostgREST) with no corvus config
- Social engineering or physical access
- Denial of service that requires overwhelming infrastructure resources

## Safe harbour

Good-faith research that follows this policy and avoids privacy harm, data
destruction, and service disruption is welcome. Do not access data that is not
yours, and do not degrade production systems.

## Hardening tips for operators

See [docs/admin/deploy.md](docs/admin/deploy.md): strong `JWT_SECRET` / `MASTER_KEY` /
`SECRET_KEY`, disable `ALLOW_INSECURE_DEFAULTS` in production, TLS termination,
audit retention, and bootstrap admin controls.
