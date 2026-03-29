#!/usr/bin/env bash
#
# TLS 1.2 integration test — verifies the tls_connect_tool can connect to
# real public websites with full certificate and hostname verification,
# and correctly rejects connections with bad certificates.
#
# Usage: ./tests/test_tls_integration.sh [path/to/tls_connect_tool]
#
# Requires network access. Exit code 0 = all tests passed.

set -euo pipefail

TOOL="${1:-./build/tls_connect_tool}"

if [ ! -x "$TOOL" ]; then
    echo "ERROR: $TOOL not found or not executable"
    echo "Build with: cmake -B build -G Ninja && cmake --build build"
    exit 1
fi

PASS=0
FAIL=0
TOTAL=0

# Test a connection that should succeed
expect_pass() {
    local host="$1"
    TOTAL=$((TOTAL + 1))
    printf "  %-35s " "$host"
    if output=$("$TOOL" "$host" 443 2>&1); then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        echo "    Output: $(echo "$output" | head -5)"
        FAIL=$((FAIL + 1))
    fi
}

# Test a connection that should fail (bad cert, wrong host, etc.)
expect_fail() {
    local host="$1"
    local reason="$2"
    TOTAL=$((TOTAL + 1))
    printf "  %-35s " "$host ($reason)"
    if output=$("$TOOL" "$host" 443 2>&1); then
        echo "FAIL (should have been rejected)"
        FAIL=$((FAIL + 1))
    else
        echo "PASS (correctly rejected)"
        PASS=$((PASS + 1))
    fi
}

echo "=== TLS 1.2 Integration Tests ==="
echo ""
echo "--- Valid certificates (should connect) ---"
expect_pass google.com
expect_pass github.com
expect_pass cloudflare.com
expect_pass amazon.com
expect_pass microsoft.com
expect_pass wikipedia.org
expect_pass mozilla.org
expect_pass letsencrypt.org
expect_pass sha256.badssl.com
expect_pass httpbin.org
expect_pass yahoo.com
expect_pass reddit.com
expect_pass netflix.com
expect_pass duckduckgo.com

echo ""
echo "--- Bad certificates (should reject) ---"
expect_fail wrong.host.badssl.com "hostname mismatch"
expect_fail untrusted-root.badssl.com "untrusted root CA"

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
