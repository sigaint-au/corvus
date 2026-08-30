# app/

- `app.py` Flask factory
- `routes/` HTTP — one concern per package
- `secret_svc/` secret domain
- `crypto/` `MASTER_KEY` + per-project DEKs (`project_keys.py`)
- `auth/` sessions, PAT, OIDC, LDAP, TOTP
- `core/` migration runner, settings, db pool (`as_user` stays direct for `SET ROLE`)
- `audit/` audit log
- `integrations/` mailer, ESO-adjacent, LDAP/OIDC clients
- `templates/` oat.ink + HTMX. Edit the template the route renders
- `ui/` shared UI helpers
- `static/` do not dump into context

Templates: resource pages use vertical rail (`page-side` / `page-subnav`, `?tab=`).
`nav.tabs` only for in-widget tablists. Wrap tables in `<div class="table">`.
Reuse `partials/access_bindings_panel.html` for binding forms.

Health: `/healthz` liveness (always 200), `/readyz` readiness (DB). No auth.