#!/usr/bin/env bash
# Drop the local database volume, rebuild the stack, and reseed mock data.
#
# Usage:
#   scripts/reset.sh          # prompt before deleting local database data
#   scripts/reset.sh --yes    # non-interactive reset
#
# This deletes only the named `pgdata` volume. The `hsmdata` volume remains.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

load_env
dev_defaults

if [[ "${1:-}" == "--yes" ]]; then
  shift
elif [[ $# -gt 0 ]]; then
  echo "usage: $0 [--yes]" >&2
  exit 2
else
  echo "This permanently deletes local PostgreSQL data and reseeds mock data."
  read -r -p "Continue? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }
fi

if [[ $# -gt 0 ]]; then
  echo "usage: $0 [--yes]" >&2
  exit 2
fi

PG_VOLUME="corvus_pgdata"

echo "==> Stopping stack with $(compose_name)"
compose down

echo "==> Removing PostgreSQL volume: $PG_VOLUME"
if [[ "$(compose_name)" == "podman-compose" ]]; then
  podman volume rm -f "$PG_VOLUME"
else
  docker volume rm -f "$PG_VOLUME"
fi

echo "==> Rebuilding and starting stack"
compose up -d --build --force-recreate

echo "==> Reseeding mock data"
compose exec -T app python - < "$ROOT/scripts/seed_mock.py"

echo
echo "==> Reset complete"
compose ps
