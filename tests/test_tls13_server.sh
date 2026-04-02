#!/usr/bin/env bash
#
# TLS 1.3 server integration test — verifies the tls13_server_tool works
# with OpenSSL s_client using various cipher suites, key exchange groups,
# and certificate types.
#
# Usage: ./tests/test_tls13_server.sh [build_dir]
#
# Requires: openssl. Exit code 0 = all tests passed.

set -euo pipefail

BUILD="${1:-./build}"
SERVER_TOOL="$BUILD/tls13_server_tool"

if [ ! -x "$SERVER_TOOL" ]; then
    echo "ERROR: $SERVER_TOOL not found or not executable"
    echo "Build with: cmake -B build -G Ninja && cmake --build build"
    exit 1
fi

TMPDIR=$(mktemp -d)
SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill -9 $SERVER_PID 2>/dev/null; rm -rf "$TMPDIR"; }
trap cleanup EXIT

# === Generate test PKI ===
echo "=== Generating test PKI ==="

# EC CA + server cert with SAN
openssl ecparam -name prime256v1 -genkey -noout -out "$TMPDIR/ca_key.pem" 2>/dev/null
openssl req -x509 -new -key "$TMPDIR/ca_key.pem" -out "$TMPDIR/ca.pem" \
    -days 1 -subj "/CN=TLS13 Server Test CA" -sha256 2>/dev/null

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
    -days 1 -subj "/CN=TLS13 RSA Server Test CA" -sha256 2>/dev/null

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
    local port="$3"
    shift 3
    TOTAL=$((TOTAL + 1))
    printf "  %-55s " "$name"
    # Connect with openssl s_client, send HTTP request, capture response
    if output=$(echo -e "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | \
        timeout 5 openssl s_client -connect "localhost:$port" -tls1_3 \
        -CAfile "$TMPDIR/ca.pem" -ign_eof "$@" 2>/dev/null); then
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

# ========== Test 1: Per cipher suite (ECDSA server cert) ==========
for SUITE in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
    echo ""
    echo "=== Test: TLS 1.3 server $SUITE (ECDSA) ==="
    PORT=$(get_port 14600)
    start_server "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem" "$PORT"

    run_test "TLS 1.3 server $SUITE ECDSA" "Hello, TLS 1.3" "$PORT" \
        -ciphersuites "$SUITE"

    stop_server
done

# ========== Test 2: Per key exchange group ==========
for GROUP in X25519 P-256 P-384; do
    echo ""
    echo "=== Test: TLS 1.3 server key exchange group $GROUP ==="
    PORT=$(get_port 14603)
    start_server "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem" "$PORT"

    run_test "TLS 1.3 server group $GROUP" "Hello, TLS 1.3" "$PORT" \
        -groups "$GROUP"

    stop_server
done

# ========== Test 3: RSA server cert (RSA-PSS CertificateVerify) ==========
echo ""
echo "=== Test: TLS 1.3 server RSA cert ==="
PORT=$(get_port 14606)
start_server "$TMPDIR/rsa_chain.pem" "$TMPDIR/rsa_server_key.pem" "$PORT"

run_test "TLS 1.3 server RSA cert AES-128-GCM" "Hello, TLS 1.3" "$PORT" \
    -CAfile "$TMPDIR/rsa_ca.pem" -ciphersuites TLS_AES_128_GCM_SHA256

stop_server

echo ""
echo "=== Test: TLS 1.3 server RSA cert AES-256-GCM ==="
PORT=$(get_port 14607)
start_server "$TMPDIR/rsa_chain.pem" "$TMPDIR/rsa_server_key.pem" "$PORT"

run_test "TLS 1.3 server RSA cert AES-256-GCM" "Hello, TLS 1.3" "$PORT" \
    -CAfile "$TMPDIR/rsa_ca.pem" -ciphersuites TLS_AES_256_GCM_SHA384

stop_server

# ========== Results ==========
echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
