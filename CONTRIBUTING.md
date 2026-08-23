# Contributing

Thanks for helping improve Corvus.

## Development setup

```bash
# Clone
git clone https://git.sigaint.au/Sigaint/corvus.git
cd corvus

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
[git.sigaint.au/Sigaint/corvus](https://git.sigaint.au/Sigaint/corvus).

## Releases

Cut from `release` when it matches `main`. Version is calendar
`YYYY.M.D.build` in `pyproject.toml` (changelog form `YYYY-MM-DD.build`).
Tag the same string after changelog and tests, for example:

```bash
git tag 2026.8.23.1
git push origin 2026.8.23.1
scripts/build.sh    # quay.io/sigaint/corvus:2026.8.23.1 and :latest
```

Do not rewrite already-tagged migration files. Overlay image tags in
`deploy/overlays/` should match the git tag you push.

## Security

Do **not** file public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
same terms as the project ([AGPL-3.0](LICENSE)).
