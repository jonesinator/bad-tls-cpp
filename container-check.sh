#!/usr/bin/env bash
#
# Build and run the full check inside a Debian sid container.
# Uses podman by default; set CONTAINER_CMD=docker to use docker.
#
# Usage: ./container-check.sh

set -euo pipefail

CMD="${CONTAINER_CMD:-podman}"

echo "Using: $CMD"
exec "$CMD" build -f Containerfile --target check -t asn1-check .
