#!/usr/bin/env bash
# Show the running containers and their status.
#
# Usage:
#   scripts/status.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

compose ps