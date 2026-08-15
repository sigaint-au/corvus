# Contributing

Thanks for helping improve Sigaint Secret Server.

## Development setup

```bash
# Clone
git clone https://git.sigaint.au/Sigaint/secretserver.git
cd secretserver

# Optional local stack (Postgres + app)
export GLOBAL_ADMIN_EMAIL=you@example.com
ALLOW_INSECURE_DEFAULTS=1 podman-compose up -d --build
# UI: http://localhost:8080
```

Python deps for unit tests and lint:

```bash
pip install -e ".[dev]"
```

## Tests and lint

Unit tests mock the database (no Postgres required):

```bash
pytest
# or the full CI matrix:
tox -e py
tox -e lint
```

Layout:

| Path | Purpose |
|------|---------|
| `app/` | Flask application (container image contents) |
| `tests/` | Pytest suite (not shipped in the image) |
| `db/migrations/` | Versioned SQL migrations (baseline + additive) |
| `docs/` | Deploy, API, RBAC, auth |

## Pull requests

1. Branch from an up-to-date `main`.
2. Keep changes focused; match existing style and security assumptions (RLS,
   mock DB in unit tests, no real secrets in fixtures).
3. Run `tox -e py` and `tox -e lint` before opening a PR.
4. Update docs when behaviour or APIs change (`docs/`, README examples).
5. Prefer small commits with clear messages.

Open a pull request against `main` on
[git.sigaint.au/Sigaint/secretserver](https://git.sigaint.au/Sigaint/secretserver).

## Security

Do **not** file public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
same terms as the project ([AGPL-3.0](LICENSE)).
