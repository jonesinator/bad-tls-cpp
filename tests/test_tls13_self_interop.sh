#!/usr/bin/env bash
#
# TLS 1.3 self-interop test — verifies our tls13_connect_tool can connect
# to our tls13_server_tool with various certificate types.
#
# Usage: ./tests/test_tls13_self_interop.sh [build_dir]
#
# Requires: openssl (for PKI generation). Exit code 0 = all tests passed.

set -euo pipefail

BUILD="${1:-./build}"
SERVER_TOOL="$BUILD/tls13_server_tool"
CLIENT_TOOL="$BUILD/tls13_connect_tool"

for tool in "$SERVER_TOOL" "$CLIENT_TOOL"; do
    if [ ! -x "$tool" ]; then
        echo "ERROR: $tool not found or not executable"
        echo "Build with: cmake -B build -G Ninja && cmake --build build"
        exit 1
    fi
done

TMPDIR=$(mktemp -d)
SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill -9 $SERVER_PID 2>/dev/null; rm -rf "$TMPDIR"; }
trap cleanup EXIT

# === Generate test PKI ===
echo "=== Generating test PKI ==="

# EC CA + server cert with SAN
openssl ecparam -name prime256v1 -genkey -noout -out "$TMPDIR/ca_key.pem" 2>/dev/null
openssl req -x509 -new -key "$TMPDIR/ca_key.pem" -out "$TMPDIR/ca.pem" \
    -days 1 -subj "/CN=TLS13 Self-Interop CA" -sha256 2>/dev/null

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

# RSA CA + server cert
echo "=== Generating RSA test PKI ==="
openssl genrsa -traditional -out "$TMPDIR/rsa_ca_key.pem" 2048 2>/dev/null
openssl req -x509 -new -key "$TMPDIR/rsa_ca_key.pem" -out "$TMPDIR/rsa_ca.pem" \
    -days 1 -subj "/CN=TLS13 RSA Self-Interop CA" -sha256 2>/dev/null

openssl genrsa -traditional -out "$TMPDIR/rsa_server_key.pem" 2048 2>/dev/null
openssl req -new -key "$TMPDIR/rsa_server_key.pem" -out "$TMPDIR/rsa_server.csr" \
    -subj "/CN=localhost" -sha256 2>/dev/null
openssl x509 -req -in "$TMPDIR/rsa_server.csr" -CA "$TMPDIR/rsa_ca.pem" \
    -CAkey "$TMPDIR/rsa_ca_key.pem" -CAcreateserial -out "$TMPDIR/rsa_server.pem" \
    -days 1 -sha256 -extfile "$TMPDIR/ext.cnf" -extensions v3_req 2>/dev/null

cat "$TMPDIR/rsa_server.pem" "$TMPDIR/rsa_ca.pem" > "$TMPDIR/rsa_chain.pem"

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

start_server() {
    local cert="$1"
    local key="$2"
    local port="$3"
    "$SERVER_TOOL" "$cert" "$key" "" "$port" > "$TMPDIR/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 1
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "ERROR: tls13_server_tool failed to start"
        cat "$TMPDIR/server.log"
        exit 1
    fi
}

stop_server() {
    kill -9 $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null || true
    SERVER_PID=""
}

# ========== Test 1: ECDSA server cert ==========
echo ""
echo "=== Test: Self-interop ECDSA cert ==="
PORT=$(get_port 14700)
start_server "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem" "$PORT"

run_test "Self-interop ECDSA cert" "Hello, TLS 1.3" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" localhost "$PORT"

stop_server

# ========== Test 2: RSA server cert ==========
echo ""
echo "=== Test: Self-interop RSA cert ==="
PORT=$(get_port 14701)
start_server "$TMPDIR/rsa_chain.pem" "$TMPDIR/rsa_server_key.pem" "$PORT"

run_test "Self-interop RSA cert" "Hello, TLS 1.3" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/rsa_ca.pem" localhost "$PORT"

stop_server

# ========== Results ==========
echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
