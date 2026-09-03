#!/usr/bin/env bash
# Serve the docs site locally with live reload.
#
# Usage:
#   scripts/docs-serve.sh                # serve with cached Sigaint theme
#   scripts/docs-serve.sh --refresh-theme  # re-snapshot theme, then serve
#
#   Preview: http://localhost:8000
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--refresh-theme" ]]; then
  scripts/docs-fetch-theme.sh
  shift
elif [[ ! -f docs/stylesheets/sigaint-tokens.css || ! -f docs/images/sigaint-corvus-logo.svg ]]; then
  echo "==> Theme snapshot missing; fetching once (re-run with --refresh-theme to update)"
  scripts/docs-fetch-theme.sh
fi

command -v mkdocs >/dev/null 2>&1 || {
  echo "error: 'mkdocs' not found; run: pip install -e \".[docs]\"" >&2
  exit 1
}

echo "==> mkdocs serve (http://localhost:8000)"
exec mkdocs serve "$@"
