#!/usr/bin/env bash
# Build the docs site with a CI-style strict check.
#
# Usage:
#   scripts/docs-build.sh                # build with cached Sigaint theme
#   scripts/docs-build.sh --refresh-theme  # re-snapshot theme, then build
#
# Any warning (broken link, page missing from nav, bad anchor) fails the build.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--refresh-theme" ]]; then
  scripts/docs-fetch-theme.sh
elif [[ ! -f docs/stylesheets/sigaint-tokens.css || ! -f docs/images/sigaint-corvus-logo.svg ]]; then
  echo "==> Theme snapshot missing; fetching once (re-run with --refresh-theme to update)"
  scripts/docs-fetch-theme.sh
fi

command -v mkdocs >/dev/null 2>&1 || {
  echo "error: 'mkdocs' not found; run: pip install -e \".[docs]\"" >&2
  exit 1
}

echo "==> mkdocs build --strict"
mkdocs build --strict
