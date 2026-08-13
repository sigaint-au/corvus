#!/usr/bin/env bash
# Shared helpers for the developer container scripts. Source from other scripts;
# do not execute directly.
#
# Resolves a compose runner (podman-compose or docker compose), keeps all
# commands rooted at the repo directory, and loads `.env` for the stack.
set -euo pipefail

# Repo root (parent of scripts/).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Resolve the compose runner that is actually installed.
if command -v podman-compose >/dev/null 2>&1; then
  _compose_cmd="podman-compose"
elif command -v docker >/dev/null 2>&1; then
  _compose_cmd="docker compose"
else
  echo "error: neither 'podman-compose' nor 'docker compose' is installed" >&2
  exit 1
fi

# Print the resolved runner name (for friendly messages).
compose_name() {
  printf '%s' "$_compose_cmd"
}

# Run a compose subcommand via the resolved runner.
compose() {
  # shellcheck disable=SC2086
  $_compose_cmd "$@"
}

# Load repo `.env` (gitignored) if present, without clobbering the caller's
# already-exported variables. Accepts the local dev secrets + GLOBAL_ADMIN_EMAIL.
load_env() {
  if [[ -f "$ROOT/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$ROOT/.env"
    set +a
  fi
}

# Allow the stack to boot with the baked-in dev secrets for local development
# (the production default refuses insecure defaults). Respect an explicit value.
dev_defaults() {
  export ALLOW_INSECURE_DEFAULTS="${ALLOW_INSECURE_DEFAULTS:-1}"
}