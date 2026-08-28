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
# podman-compose waits forever for depends_on: service_healthy if Postgres
# init fails. Cap the wait so a bad 0001_init.sql surfaces as an error.
up_ok=0
if command -v timeout >/dev/null 2>&1; then
  if timeout 300 "$(compose_name)" up -d --build --force-recreate; then
    up_ok=1
  fi
elif compose up -d --build --force-recreate; then
  up_ok=1
fi
if [[ "$up_ok" -ne 1 ]]; then
  echo "error: compose up failed or timed out; postgres logs:" >&2
  compose logs --tail=80 db || true
  exit 1
fi

echo "==> Waiting for the app to become ready"
ready=0
for _ in $(seq 1 45); do
  if compose exec -T app python -c \
    'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/healthz")' \
    >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" -ne 1 ]]; then
  echo "error: app did not become ready; logs:" >&2
  compose logs --tail=80 app db || true
  exit 1
fi

echo "==> Reseeding mock data"
compose exec -T app python - < "$ROOT/scripts/seed_mock.py"

echo
echo "==> Reset complete"
compose ps
