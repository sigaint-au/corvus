# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Engineering teams at security-conscious organizations who self-host a central
secrets store. Primary users: platform and DevOps engineers managing
credentials, certificates, and configuration across teams and projects.
Secondary: developers consuming secrets via CI/CD and Kubernetes, and
administrators enforcing access policy.

> Inferred from README and docs; no user answer received.

## Product Purpose

Corvus is a self-hosted secrets management system that centralizes
credentials, certificates, and configuration with role-based access control
enforced at the database level (PostgreSQL Row-Level Security), full audit
logging, and machine/PAT APIs for CI/CD and Kubernetes integration. Success
means teams can store, share, and automate secrets without trusting a third
party with plaintext.

> Inferred from README, architecture.md, and pyproject.toml description.

## Positioning

Authorization enforced by PostgreSQL RLS — the database itself rejects
unauthorized rows, not just application code. Self-hosted, AGPL-3.0, with
optional per-project bring-your-own-key encryption and External Secrets
Operator integration. This combination (RLS at the DB + self-hosted + BYOK)
is the differentiator vs. SaaS secrets managers.

> Inferred from README "Security model" and architecture.md; no user answer received.

## Operating Context

- Teams organize access in a `team → project → secret` hierarchy.
- Three interfaces: browser UI (Flask + HTMX), unified secret API (`/eso/v1`
  for machine tokens and PATs), and PostgREST API (SQL-style queries, JWT).
- Deploy via Docker/Podman Compose or Kubernetes (kustomize).
- Migrations ship as ordered SQL files, applied at startup.
- Audit retention purge runs as a cron/CronJob.
- Webhook delivery requires a background worker process.
- Local dev uses `ALLOW_INSECURE_DEFAULTS=1`; production refuses weak secrets.

## Capabilities and Constraints

- RBAC at team, project, and secret scope, backed by directory groups (LDAP/OIDC).
- Per-secret access modes: inherit project permissions or restrict to explicit bindings.
- Reveal approval workflow with time-limited grants.
- Machine tokens (`service-read`/`service-reveal`/`service-write`) with key allow-lists.
- Personal access tokens (PATs) acting as the user under RLS.
- TOTP 2FA with single-use recovery codes (stdlib implementation — no pyotp).
- Fernet encryption at rest via `MASTER_KEY`; optional per-project DEKs (BYOK).
- PKCS#11 HSM support (SoftHSM2) for external key management.
- Secret expiry, soft-delete trash, version history, structured kinds.
- Bulk import/export (.env, JSON, CSV).
- Audit logs with access review, export, and retention purge.
- Optional classification banners.
- LDAP and OIDC SSO with group mapping; SMTP notifications.
- External Secrets Operator: pull (`ExternalSecret`) and push (`PushSecret`).
- Postgres RLS is the enforcement plane; `SECURITY DEFINER` functions implement
  access checks; no separate app-only ACL.
- Per-project crypto keys are not an RBAC resource — gated by app-side admin
  predicates, kept out of `RBAC_RESOURCES` so wildcard grants never cover key
  management.
- Python 3.10+ required; Flask 3.1, psycopg 3, gunicorn; tests mock the DB.

## Brand Commitments

- Name: **Corvus** (logo at `app/static/logo.svg`).
- UI framework: oat.ink + HTMX, server-rendered templates.
- License: AGPL-3.0.
- Voice: plain user-facing copy; RBAC role names in UI.

## Evidence on Hand

- Live demo at `https://secretserver-dev.sigaint.au` with seeded mock accounts.
- Full docs set under `docs/` (user guide, admin deploy/config, RBAC,
  authentication, machine tokens, external secrets, audit, backup, dev
  architecture/database/API/testing/contributing).
- `scripts/seed_mock.py` for dev tooling.
- Kubernetes kustomize overlays in `deploy/`.
- `THIRD_PARTY.md` lists bundled third-party works.

## Product Principles

1. **RLS is the enforcement plane.** The database rejects unauthorized access;
   the app and APIs call the same SQL helpers. Never build a parallel app-only ACL.
2. **Self-hosted by default.** Teams control their own secrets infrastructure;
   production refuses insecure defaults.
3. **Migrations are the sole source of truth for DDL.** Schema changes ship as
   ordered, idempotent SQL migrations; never edit released baselines.
4. **Boring, minimal dependencies.** stdlib TOTP, Fernet crypto, oat.ink UI —
   no pyotp, no bespoke crypto, no SPA framework.
5. **Audit everything.** Every reveal, access change, and admin action is
   append-only audited; retention is configurable but never silent.

## Accessibility & Inclusion

No product-specific accessibility requirement was established.
