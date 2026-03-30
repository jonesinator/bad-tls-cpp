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
    printf "  %-40s " "$host"
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
    printf "  %-40s " "$host ($reason)"
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
# Major tech / search engines
expect_pass google.com
expect_pass github.com
expect_pass cloudflare.com
expect_pass amazon.com
expect_pass microsoft.com
expect_pass apple.com
expect_pass meta.com
expect_pass x.com
expect_pass yahoo.com
expect_pass bing.com

# Social / media / entertainment
expect_pass reddit.com
expect_pass netflix.com
expect_pass linkedin.com
expect_pass instagram.com
expect_pass pinterest.com
expect_pass tumblr.com
expect_pass twitch.tv
expect_pass spotify.com
expect_pass discord.com
expect_pass tiktok.com

# News / media
expect_pass nytimes.com
expect_pass bbc.com
expect_pass cnn.com
expect_pass theguardian.com
expect_pass washingtonpost.com
expect_pass reuters.com
expect_pass bloomberg.com
expect_pass forbes.com
expect_pass wsj.com
expect_pass nbcnews.com

# Reference / education
expect_pass wikipedia.org
expect_pass stackoverflow.com
expect_pass medium.com
expect_pass quora.com
expect_pass arxiv.org
expect_pass archive.org
expect_pass wikimedia.org
expect_pass britannica.com
expect_pass nature.com
expect_pass mit.edu

# Technology / developer
expect_pass mozilla.org
expect_pass letsencrypt.org
expect_pass gitlab.com
expect_pass npmjs.com
expect_pass pypi.org
expect_pass crates.io
expect_pass docker.com
expect_pass kubernetes.io
expect_pass rust-lang.org
expect_pass go.dev

# Cloud / infrastructure
expect_pass aws.amazon.com
expect_pass cloud.google.com
expect_pass azure.microsoft.com
expect_pass digitalocean.com
expect_pass heroku.com
expect_pass netlify.com
expect_pass vercel.com
expect_pass fly.io
expect_pass render.com
expect_pass cloudflare-dns.com

# E-commerce / business
expect_pass ebay.com
expect_pass etsy.com
expect_pass shopify.com
expect_pass stripe.com
expect_pass paypal.com
expect_pass square.com
expect_pass zillow.com
expect_pass booking.com
expect_pass airbnb.com
expect_pass uber.com

# Communication / productivity
expect_pass zoom.us
expect_pass slack.com
expect_pass notion.so
expect_pass dropbox.com
expect_pass box.com
expect_pass trello.com
expect_pass figma.com
expect_pass canva.com
expect_pass airtable.com
expect_pass asana.com

# Security / privacy / infra
expect_pass sha256.badssl.com
expect_pass httpbin.org
expect_pass duckduckgo.com
expect_pass signal.org
expect_pass proton.me
expect_pass cloudflare.net
expect_pass fastly.com
expect_pass akamai.com
expect_pass imperva.com
expect_pass okta.com

# International / other popular
expect_pass samsung.com
expect_pass sony.com
expect_pass ibm.com
expect_pass oracle.com
expect_pass intel.com
expect_pass nvidia.com
expect_pass adobe.com
expect_pass salesforce.com
expect_pass cisco.com
expect_pass hp.com

echo ""
echo "--- Bad certificates (should reject) ---"
expect_fail wrong.host.badssl.com "hostname mismatch"
expect_fail untrusted-root.badssl.com "untrusted root CA"
expect_fail expired.badssl.com "expired certificate"

echo ""
echo "--- mTLS with client certificate (client.badssl.com) ---"
TMPDIR=$(mktemp -d)
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

# Download and decrypt the badssl.com client cert (RSA, encrypted PKCS#8)
curl -sf https://badssl.com/certs/badssl.com-client.pem -o "$TMPDIR/badssl-client.pem"
openssl pkey -in "$TMPDIR/badssl-client.pem" -passin pass:badssl.com \
    -out "$TMPDIR/badssl-client-key.pem" -traditional 2>/dev/null
openssl x509 -in "$TMPDIR/badssl-client.pem" -out "$TMPDIR/badssl-client-cert.pem" 2>/dev/null

TOTAL=$((TOTAL + 1))
printf "  %-40s " "client.badssl.com (mTLS)"
if output=$("$TOOL" --cert "$TMPDIR/badssl-client-cert.pem" \
    --key "$TMPDIR/badssl-client-key.pem" client.badssl.com 443 2>&1); then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL"
    echo "    Output: $(echo "$output" | tail -5)"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
