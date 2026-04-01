#!/usr/bin/env bash
#
# Build and run the full check inside a Debian sid container.
# Uses podman by default; set CONTAINER_CMD=docker to use docker.
#
# Usage: ./container-check.sh
#
# Packet captures and SSLKEYLOGFILE outputs are saved to build/captures/
# inside the container. To extract them:
#   podman cp <container>:/src/build/captures ./captures

set -euo pipefail

CMD="${CONTAINER_CMD:-podman}"

echo "Using: $CMD"
"$CMD" build -f Containerfile --target check -t asn1-check .
"$CMD" run --cap-add=NET_RAW --rm asn1-check
