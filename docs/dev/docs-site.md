# Documentation site

The documentation site is generated with [MkDocs](https://www.mkdocs.org/) and
[Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) from the
Markdown files under `docs/`.

## Prerequisites

```bash
pip install -e ".[docs]"
```

This installs the pinned toolchain (`mkdocs-material` pins MkDocs itself).
Do not upgrade past the pin: the Material team has announced breaking changes
for MkDocs 2.0 with no migration path — bump deliberately and rebuild.

## Working on the docs

```bash
scripts/docs-serve.sh   # live-reload preview at http://localhost:8000
scripts/docs-build.sh   # CI-style check; any warning fails the build
```

(`make docs-serve` / `make docs-build` run the same scripts.)
`--strict` is the default expectation: broken internal links, files missing
from `nav`, and bad anchors abort the build. Run it before committing.

## Sigaint theme

Brand tokens (fonts, ink/paper colors) and the Corvus logo are snapshotted
from the main site into the repo, so builds work offline:

| Path | Role |
|------|------|
| `docs/stylesheets/sigaint-tokens.css` | Generated `:root` tokens — do not edit |
| `docs/stylesheets/material-brand.css` | Hand-written Material bridge — edit this |
| `docs/images/sigaint-corvus-logo.svg` | Header logo snapshot |

```bash
scripts/docs-fetch-theme.sh              # refresh snapshots from the main site
scripts/docs-build.sh --refresh-theme    # refresh, then build
SIGAINT_MAIN_URL=https://… scripts/docs-fetch-theme.sh  # override the source
```

`mkdocs.yml` pins the snapshots via `theme.logo`, `primary: black`, and
`extra_css`. Commit refreshed snapshots like any other change.

## Conventions

- **Every page must appear in `nav`** (`mkdocs.yml`) or the strict build
  fails. Nav order is the reading order; sections map to audiences
  (Users / Administrators / Developers).
- Internal links are relative Markdown links between files under `docs/`
  (e.g. `[Upgrades](upgrades.md)`). Links to repo files outside `docs/`
  (e.g. `deploy/README.md`) must use absolute URLs to the Forgejo repository,
  because MkDocs cannot resolve targets outside its docs directory.
- Anchors cannot be used as `nav` entries. If a workflow deserves its own nav
  item (see `admin/upgrades.md`), give it its own page.
- User-facing copy stays plain; use RBAC role names everywhere.

## Adding a page

1. Create `docs/<audience>/<topic>.md`.
2. Add it to the matching section in `nav` in `mkdocs.yml`.
3. If it belongs in an audience index, add a row to the tables in the repo
   `README.md` and `docs/index.md`.
4. Verify with `mkdocs build --strict`.

## Deployment

`mkdocs build` emits a fully static `site/` (gitignored). Ship it anywhere
that serves static files:

- Forgejo Pages, or
- a static nginx sidecar/container added to the existing compose/Kubernetes
  overlays

No server-side runtime is required; the site is read-only content.

## Repository layout

| Path | Role |
|------|------|
| `mkdocs.yml` | Site config: theme, extensions, nav |
| `docs/index.md` | Site landing page |
| `docs/{user,admin,dev}/` | Source Markdown by audience |
| `site/` | Build output (gitignored) |
