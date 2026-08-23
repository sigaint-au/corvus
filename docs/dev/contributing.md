# Contributing

Guidelines for contributing to Corvus.

---

## Getting started

```bash
# Clone
git clone <repo-url> corvus
cd corvus

# Install deps
pip install -e ".[dev]"

# Run tests
pytest

# Run lint
tox -e lint
```

---

## Repo layout

```
app/            # Flask app (flat modules + routes/ + lib/)
db/migrations/  # Squashed fresh-install SQL baseline (0001_init.sql + marker)
docs/           # Documentation (user/, admin/, dev/)
tests/          # pytest suite
scripts/        # dev seed (seed_mock.py)
compose.yml     # Postgres + PostgREST + app
Dockerfile      # App image
```

---

## Making changes

1. **Write a failing test first** where possible. Tests live in `tests/` and
   mock the DB, so no live Postgres is needed.
2. **Schema changes are a migration story.** The fresh-install baseline lives
   in `db/migrations/0001_init.sql`. Do not edit it after release. For
   existing databases, add a new idempotent `db/migrations/NNNN_slug.sql` —
   `app/core/migrations.py` applies it at startup.
3. **Run the full suite and lint** before submitting:
   ```bash
   pytest
   tox -e lint
   ```
4. **Update documentation** if you change behaviour. Docs are organised by
   audience under `docs/user/`, `docs/admin/`, `docs/dev/`.

---

## Security-sensitive areas

- **RLS / access control**: changes must preserve the invariant that the UI
  and APIs use the same SQL helpers; there is no separate app-only ACL.
- **SECURITY DEFINER functions**: grant them narrowly (never `authenticated`
  for machine helpers), set an explicit `search_path`, and use
  `row_security = off` only where needed to avoid recursion.
- **Audit**: audit rows are append-only; the actor is derived from JWT claims,
  never caller input.
- **Secrets at rest**: values are Fernet-encrypted with `MASTER_KEY`. Never
  store plaintext in `api.secrets` or log secret values.

---

## Reporting security issues

Do **not** open a public issue for a security vulnerability. Report it
privately to the maintainers (see the project's `SECURITY` policy if present,
or the repository owner). Include a description, affected version, and a
reproduction if possible.

---

## Related docs

- [architecture.md](architecture.md): how it fits together
- [database.md](database.md): schema & RLS
- [testing.md](testing.md): tests & lint
