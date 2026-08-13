#!/usr/bin/env bash
# Build and start the full stack in the background (the "run" command).
#
# Usage:
#   scripts/up.sh            # build + start all containers
#   scripts/up.sh db         # build + start only the db service
#
# For local development this allows the insecure default dev secrets (same as
# `ALLOW_INSECURE_DEFAULTS=1 podman-compose up -d --build` in the README). Set
# ALLOW_INSECURE_DEFAULTS=0 to force the production guard.
#
#   UI:          http://localhost:8080
#   PostgREST:   http://localhost:3000
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
load_env
dev_defaults

echo "==> Starting stack with $(compose_name) (build + up -d)"
compose up -d --build "$@"
echo
compose ps