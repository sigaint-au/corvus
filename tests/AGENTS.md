# tests

Mocked DB (`helpers.mock_conn`). `TESTING=True` skips `ensure_schema()`.
`pythonpath` is `.` and `app` via `pyproject.toml`.

Map:
- `test_auth.py` ↔ `app/auth`, `app/routes/auth`
- `test_secrets.py` / `test_secret_lifecycle.py` ↔ `secret_svc`, `routes/secrets`
- `test_eso.py` ↔ `routes/eso`
- `test_crypto.py` / `test_project_keys.py` ↔ `app/crypto`
- `test_mailer.py` ↔ mailer
- `test_migrations.py` / `test_schema.py` / `test_meta.py` ↔ `db/migrations`
- `test_live_*.py` and `test_e2e.py` are opt-in (`-m live`). Do not run them.

Default: `pytest tests/test_<area>.py -q --tb=short`