#!/usr/bin/env bash
# Stop and remove the stack's containers.
#
# Usage:
#   scripts/down.sh            # stop + remove containers, keep data
#   scripts/down.sh --volumes  # also delete the pgdata volume (DESTRUCTIVE)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

echo "==> Taking stack down with $(compose_name)"
compose down "$@"