#!/usr/bin/env bash
#
# TLS 1.2 server integration test — verifies the tls_server_tool works
# with both curl and the project's own tls_connect_tool.
#
# Usage: ./tests/test_tls_server.sh [build_dir]
#
# Requires: openssl, curl. Exit code 0 = all tests passed.

set -euo pipefail

BUILD="${1:-./build}"
SERVER_TOOL="$BUILD/tls_server_tool"
CLIENT_TOOL="$BUILD/tls_connect_tool"

for tool in "$SERVER_TOOL" "$CLIENT_TOOL"; do
    if [ ! -x "$tool" ]; then
        echo "ERROR: $tool not found or not executable"
        echo "Build with: cmake -B build -G Ninja && cmake --build build"
        exit 1
    fi
done

TMPDIR=$(mktemp -d)
trap 'kill $SERVER_PID 2>/dev/null; rm -rf "$TMPDIR"' EXIT

# Generate test PKI
echo "=== Generating test PKI ==="

# CA key and self-signed cert
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

# Combine server cert + CA cert into chain file
cat "$TMPDIR/server.pem" "$TMPDIR/ca.pem" > "$TMPDIR/chain.pem"

echo "  CA cert:     $TMPDIR/ca.pem"
echo "  Server cert: $TMPDIR/server.pem"
echo "  Server key:  $TMPDIR/server_key.pem"

# Find a free port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null || echo 14433)

echo ""
echo "=== Starting TLS server on port $PORT ==="
"$SERVER_TOOL" "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem" "" "$PORT" &
SERVER_PID=$!

# Wait for server to be ready
sleep 1
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    exit 1
fi

PASS=0
FAIL=0
TOTAL=0

run_test() {
    local name="$1"
    local expected="$2"
    shift 2
    TOTAL=$((TOTAL + 1))
    printf "  %-40s " "$name"
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

echo ""
echo "=== Running tests ==="

# Test 1: curl with custom CA (force TLS 1.2 with ECDHE-ECDSA cipher)
run_test "curl --cacert (TLS 1.2)" "Hello, world!" \
    curl -s --cacert "$TMPDIR/ca.pem" --tlsv1.2 --tls-max 1.2 \
    --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 "https://localhost:$PORT/"

# Test 2: our own TLS client with custom CA
run_test "tls_connect_tool --cafile" "Hello, world!" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" localhost "$PORT"

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
