#!/usr/bin/env bash
#
# TLS 1.2 third-party server test — verifies tls_connect_tool can connect
# to an OpenSSL s_server instance with full certificate verification,
# including mutual TLS (mTLS).
#
# Usage: ./tests/test_tls_openssl_server.sh [build_dir]
#
# Requires: openssl. Exit code 0 = all tests passed.

set -euo pipefail

BUILD="${1:-./build}"
CLIENT_TOOL="$BUILD/tls_connect_tool"

if [ ! -x "$CLIENT_TOOL" ]; then
    echo "ERROR: $CLIENT_TOOL not found or not executable"
    echo "Build with: cmake -B build -G Ninja && cmake --build build"
    exit 1
fi

TMPDIR=$(mktemp -d)
SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill -9 $SERVER_PID 2>/dev/null; rm -rf "$TMPDIR"; }
trap cleanup EXIT

# Generate test PKI
echo "=== Generating test PKI ==="

# Server CA key and self-signed cert
openssl ecparam -name prime256v1 -genkey -noout -out "$TMPDIR/ca_key.pem" 2>/dev/null
openssl req -x509 -new -key "$TMPDIR/ca_key.pem" -out "$TMPDIR/ca.pem" \
    -days 1 -subj "/CN=Test CA" -sha256 2>/dev/null

# Server key and CA-signed cert with SAN
openssl ecparam -name prime256v1 -genkey -noout -out "$TMPDIR/server_key.pem" 2>/dev/null
openssl req -new -key "$TMPDIR/server_key.pem" -out "$TMPDIR/server.csr" \
    -subj "/CN=localhost" -sha256 2>/dev/null

cat > "$TMPDIR/ext.cnf" <<EOF
[v3_req]
subjectAltName = DNS:localhost, IP:127.0.0.1
EOF

openssl x509 -req -in "$TMPDIR/server.csr" -CA "$TMPDIR/ca.pem" -CAkey "$TMPDIR/ca_key.pem" \
    -CAcreateserial -out "$TMPDIR/server.pem" -days 1 -sha256 \
    -extfile "$TMPDIR/ext.cnf" -extensions v3_req 2>/dev/null

cat "$TMPDIR/server.pem" "$TMPDIR/ca.pem" > "$TMPDIR/chain.pem"

# Client CA and client certificate (for mTLS)
openssl ecparam -name prime256v1 -genkey -noout -out "$TMPDIR/client_ca_key.pem" 2>/dev/null
openssl req -x509 -new -key "$TMPDIR/client_ca_key.pem" -out "$TMPDIR/client_ca.pem" \
    -days 1 -subj "/CN=Client CA" -sha256 2>/dev/null

openssl ecparam -name prime256v1 -genkey -noout -out "$TMPDIR/client_key.pem" 2>/dev/null
openssl req -new -key "$TMPDIR/client_key.pem" -out "$TMPDIR/client.csr" \
    -subj "/CN=Test Client" -sha256 2>/dev/null
openssl x509 -req -in "$TMPDIR/client.csr" -CA "$TMPDIR/client_ca.pem" \
    -CAkey "$TMPDIR/client_ca_key.pem" -CAcreateserial -out "$TMPDIR/client.pem" \
    -days 1 -sha256 2>/dev/null

cat "$TMPDIR/client.pem" "$TMPDIR/client_ca.pem" > "$TMPDIR/client_chain.pem"

get_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null || echo "$1"
}

PASS=0
FAIL=0
TOTAL=0

run_test() {
    local name="$1"
    local expected="$2"
    shift 2
    TOTAL=$((TOTAL + 1))
    printf "  %-55s " "$name"
    if output=$("$@" 2>&1); then
        if echo "$output" | grep -q "$expected"; then
            echo "PASS"
            PASS=$((PASS + 1))
        else
            echo "FAIL (missing expected output)"
            echo "    Output:"
            echo "$output" | tail -10 | sed 's/^/    /'
            FAIL=$((FAIL + 1))
        fi
    else
        echo "FAIL (exit code $?)"
        echo "    Output:"
        echo "$output" | tail -10 | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi
}

start_openssl_server() {
    local port="$1"
    shift
    openssl s_server \
        -cert "$TMPDIR/chain.pem" -key "$TMPDIR/server_key.pem" \
        -port "$port" -tls1_2 -www \
        "$@" \
        > "$TMPDIR/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 1
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "ERROR: openssl s_server failed to start"
        cat "$TMPDIR/server.log"
        exit 1
    fi
}

stop_server() {
    kill -9 $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null || true
    SERVER_PID=""
}

# ========== Test 1: Basic TLS per cipher suite ==========
for SUITE in ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384; do
    echo ""
    echo "=== Test: Basic TLS ($SUITE) ==="
    PORT=$(get_port 14444)
    start_openssl_server "$PORT" -cipher "$SUITE"

    run_test "TLS $SUITE" "HTTP" \
        "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" localhost "$PORT"

    stop_server
done

# ========== Test 2: mTLS per cipher suite ==========
for SUITE in ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384; do
    echo ""
    echo "=== Test: mTLS ($SUITE) ==="
    PORT=$(get_port 14445)
    start_openssl_server "$PORT" -Verify 1 -CAfile "$TMPDIR/client_ca.pem" -cipher "$SUITE"

    run_test "mTLS $SUITE" "HTTP" \
        "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" \
        --cert "$TMPDIR/client_chain.pem" --key "$TMPDIR/client_key.pem" \
        localhost "$PORT"

    stop_server
done

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
