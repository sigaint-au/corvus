#!/usr/bin/env bash
# Restart the running containers without rebuilding.
#
# Usage:
#   scripts/restart.sh        # restart the whole stack
#   scripts/restart.sh app    # restart only the app service
#
# Use scripts/rebuild.sh when you need a fresh image too.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
load_env

echo "==> Restarting with $(compose_name)"
compose restart "$@"