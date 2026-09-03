#!/usr/bin/env bash
# Snapshot the docs-site theme from the main Sigaint website.
#
# Downloads the main-site stylesheet and Corvus logo, then extracts the
# `:root` brand tokens into docs/stylesheets/sigaint-tokens.css (generated —
# do not edit) and copies the logo to docs/images/sigaint-corvus-logo.svg.
# Both snapshots are tracked in git so `mkdocs build --strict` works offline;
# re-run this script to pick up brand changes from the main site.
#
# Usage:
#   scripts/docs-fetch-theme.sh
#   SIGAINT_MAIN_URL=https://staging.example.com scripts/docs-fetch-theme.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE_URL="${SIGAINT_MAIN_URL:-https://sigaint.au}"
CSS_URL="$BASE_URL/css/site.css"
LOGO_URL="$BASE_URL/assets/corvus-logo-white.svg"

TOKENS_FILE="docs/stylesheets/sigaint-tokens.css"
LOGO_FILE="docs/images/sigaint-corvus-logo.svg"

command -v curl >/dev/null 2>&1 || {
  echo "error: 'curl' is required to fetch the theme" >&2
  exit 1
}

tmp_css="$(mktemp)"
tmp_logo="$(mktemp)"
trap 'rm -f "$tmp_css" "$tmp_logo"' EXIT

echo "==> Fetching theme from $BASE_URL"
curl -fsSL --max-time 30 "$CSS_URL" -o "$tmp_css"
curl -fsSL --max-time 30 "$LOGO_URL" -o "$tmp_logo"

# Sanity-check the downloads before touching the snapshots.
grep -q ':root' "$tmp_css" || {
  echo "error: $CSS_URL did not contain a ':root' block; refusing to update" >&2
  exit 1
}
grep -q '<svg' "$tmp_logo" || {
  echo "error: $LOGO_URL did not look like an SVG; refusing to update" >&2
  exit 1
}

# Extract the :root { ... } block (brand tokens only, not page rules).
tokens="$(sed -n '/:root[[:space:]]*{/,/}/p' "$tmp_css")"
echo "$tokens" | grep -q -- '--ink' || {
  echo "error: no '--ink' token in upstream :root block; refusing to update" >&2
  exit 1
}

mkdir -p docs/stylesheets docs/images
{
  echo "/* Generated from $CSS_URL by scripts/docs-fetch-theme.sh — do not edit. */"
  echo "$tokens"
} >"$TOKENS_FILE"
cp "$tmp_logo" "$LOGO_FILE"

echo "==> Wrote $TOKENS_FILE and $LOGO_FILE"
