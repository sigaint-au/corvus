#!/usr/bin/env bash
# Stream the container logs.
#
# Usage:
#   scripts/logs.sh            # follow all services
#   scripts/logs.sh app        # follow only the app service
#   scripts/logs.sh --tail=100 # last 100 lines without following
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

echo "==> logs: $(compose_name) logs -f $*"
compose logs -f "$@"