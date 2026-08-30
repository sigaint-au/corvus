# db

`0001_init.sql` is the squashed baseline. Do not open it to "understand RBAC".
Grep a function name, or `@docs/dev/database.md` if the task is schema.

New DDL:
- add `db/migrations/NNNN_slug.sql` (zero-padded next number)
- idempotent (`IF NOT EXISTS`) where possible
- no `BEGIN`/`COMMIT` — runner wraps one transaction per file
- never edit a released migration (checksum is recorded)
- comments starting `--` are stripped before checksum
- append the filename in `tests/test_migrations.py:test_migrations_ship_in_order`
- assert in `tests/test_meta.py` or `tests/test_schema.py`

RBAC definitions live in the baseline. Do not start a second baseline.