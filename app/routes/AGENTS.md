# routes

Pick the package that owns the URL. Do not list sibling packages.

- `auth/` login, register, session, password reset
- `secrets/` `teams/` `projects/` HTML + HTMX
- `eso/` `/eso/v1` machine API
- `admin/` `rbac/` identity admin
- `mgmt_api/` management JSON
- `import_export.py` `project_tokens.py` `webhooks_ui.py` one-off surfaces

Grep the handler, then `@` that module + `tests/test_<area>.py`.