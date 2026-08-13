#!/usr/bin/env bash
# Build the application container image(s).
#
# Usage:
#   scripts/build.sh
#
# Rebuilds from the Dockerfile with the resolved runner (podman-compose or
# docker compose) but does not start the stack — see scripts/up.sh.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

echo "==> Building images with $(compose_name)"
compose build