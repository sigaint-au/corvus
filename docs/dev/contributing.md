# Contributing

Guidelines for contributing to Sigaint Secret Server.

---

## Getting started

```bash
# Clone
git clone <repo-url> secretserver
cd secretserver

# Install deps
pip install -r app/requirements.txt -r requirements-dev.txt

# Run tests
pytest

# Run lint
tox -e lint
```

---

## Repo layout

```
app/            # Flask app (flat modules + routes/)
db/init.sql     # Tables + ENABLE/FORCE RLS (first DB init, applied as 01-init.sql)
db/rbac.sql     # RBAC schema + auth functions + RLS policies (applied as 02-rbac.sql)
app/rbac.sql    # Same as db/rbac.sql (without legacy migration) — applied by schema.py
docs/           # Documentation (user/, admin/, dev/)
tests/          # pytest suite
scripts/        # dev seed (seed_mock.py)
compose.yml     # Postgres + PostgREST + app
Dockerfile      # App image
```

---

## Making changes

1. **Write a failing test first** where possible. Tests live in `tests/` and
   mock the DB — no live Postgres needed.
2. **Keep `db/init.sql`, `db/rbac.sql`, `app/rbac.sql`, and `app/schema.py` in
   sync.** `init.sql` creates tables; `rbac.sql` creates RBAC functions + RLS
   policies; `schema.py` (`ensure_schema()`) upgrades existing databases. Any
   schema/RLS change must be applied in all relevant files, idempotently.
   `db/rbac.sql` and `app/rbac.sql` should be identical except for the legacy
   data migration block (only in `db/rbac.sql`).
3. **Run the full suite and lint** before submitting:
   ```bash
   pytest
   tox -e lint
   ```
4. **Update documentation** if you change behaviour. Docs are organised by
   audience under `docs/user/`, `docs/admin/`, `docs/dev/`.

---

## Security-sensitive areas

- **RLS / access control** — changes must preserve the invariant that the UI
  and APIs use the same SQL helpers; there is no separate app-only ACL.
- **SECURITY DEFINER functions** — grant them narrowly (never `authenticated`
  for machine helpers), set an explicit `search_path`, and use
  `row_security = off` only where needed to avoid recursion.
- **Audit** — audit rows are append-only; the actor is derived from JWT claims,
  never caller input.
- **Secrets at rest** — values are Fernet-encrypted with `MASTER_KEY`. Never
  store plaintext in `api.secrets` or log secret values.

---

## Reporting security issues

Do **not** open a public issue for a security vulnerability. Report it
privately to the maintainers (see the project's `SECURITY` policy if present,
or the repository owner). Include a description, affected version, and a
reproduction if possible.

---

## Related docs

- [architecture.md](architecture.md) — how it fits together
- [database.md](database.md) — schema & RLS
- [testing.md](testing.md) — tests & lint
