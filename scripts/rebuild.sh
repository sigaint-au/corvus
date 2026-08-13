#!/usr/bin/env bash
# Full rebuild + restart: tear down the stack, rebuild images, and bring it back
# up. Data persists in the named `pgdata` volume.
#
# Usage:
#   scripts/rebuild.sh
#
# For a truly clean slate you can additionally run `scripts/down.sh --volumes`,
# but that deletes the database volume — only do it if you want a fresh DB.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
load_env
dev_defaults

echo "==> Stopping stack with $(compose_name)"
compose down "$@"

echo "==> Rebuilding and starting stack"
compose up -d --build

echo
compose ps