#!/usr/bin/env bash
# Build the application image and push it to Quay.
#
# Usage:
#   scripts/build.sh            # build, tag, and push
#   scripts/build.sh --no-push  # build and tag only
#
# Images (override with IMAGE_REPO=… TAG=…):
#   quay.io/sigaint/corvus:<pyproject version>
#   quay.io/sigaint/corvus:latest
# Also tags localhost/corvus_app:latest for the local Compose stack.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

PUSH=1
for arg in "$@"; do
  case "$arg" in
    --push) PUSH=1 ;;
    --no-push) PUSH=0 ;;
    -h|--help)
      sed -n '2,11p' "$0"
      exit 0
      ;;
    *)
      echo "error: unknown argument: $arg (try --push or --no-push)" >&2
      exit 1
      ;;
  esac
done

IMAGE_REPO="${IMAGE_REPO:-quay.io/sigaint/corvus}"
TAG="${TAG:-$(app_version)}"
if [[ -z "$TAG" ]]; then
  echo "error: could not read version from pyproject.toml" >&2
  exit 1
fi

echo "==> Building with $(container_name)"
echo "    ${IMAGE_REPO}:${TAG}"
echo "    ${IMAGE_REPO}:latest"
container build \
  -t "${IMAGE_REPO}:${TAG}" \
  -t "${IMAGE_REPO}:latest" \
  -t "localhost/corvus_app:latest" \
  "$ROOT"

if [[ "$PUSH" -eq 1 ]]; then
  echo "==> Pushing ${IMAGE_REPO}:${TAG} and ${IMAGE_REPO}:latest"
  container push "${IMAGE_REPO}:${TAG}"
  container push "${IMAGE_REPO}:latest"
fi
