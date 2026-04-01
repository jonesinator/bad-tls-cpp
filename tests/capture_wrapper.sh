#!/usr/bin/env bash
#
# Runs a test script while capturing packets and TLS master secrets.
#
# Usage: ./tests/capture_wrapper.sh <output_dir> <test_script> [args...]
#
# Produces:
#   <output_dir>/<test_name>.pcap    — packet capture (if tcpdump is available)
#   <output_dir>/<test_name>.keys    — SSLKEYLOGFILE for Wireshark decryption
#
# tcpdump requires CAP_NET_RAW or root; if unavailable, only .keys are produced.

set -euo pipefail

OUTPUT_DIR="$1"
shift
TEST_SCRIPT="$1"
shift

TEST_NAME=$(basename "$TEST_SCRIPT" .sh)
mkdir -p "$OUTPUT_DIR"

KEYLOG="$OUTPUT_DIR/$TEST_NAME.keys"
PCAP="$OUTPUT_DIR/$TEST_NAME.pcap"

export SSLKEYLOGFILE="$KEYLOG"

# Start packet capture if possible (needs CAP_NET_RAW)
TCPDUMP_PID=""
if tcpdump -i any -U -w "$PCAP" -s 0 'tcp or udp' 2>/dev/null &
then
    TCPDUMP_PID=$!
    sleep 0.5
    # Verify it actually started
    if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        TCPDUMP_PID=""
    fi
fi

cleanup() {
    if [ -n "$TCPDUMP_PID" ]; then
        kill "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
    # Remove empty pcap if tcpdump couldn't run
    [ ! -s "$PCAP" ] && rm -f "$PCAP" || true
}
trap cleanup EXIT

# Run the actual test
"$TEST_SCRIPT" "$@"
