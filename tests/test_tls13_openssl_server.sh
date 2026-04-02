#!/usr/bin/env bash
#
# TLS 1.3 OpenSSL interop test — verifies tls13_connect_tool can connect
# to an OpenSSL s_server instance with various cipher suites, key exchange
# groups, and certificate types.
#
# Usage: ./tests/test_tls13_openssl_server.sh [build_dir]
#
# Requires: openssl. Exit code 0 = all tests passed.

set -euo pipefail

BUILD="${1:-./build}"
CLIENT_TOOL="$BUILD/tls13_connect_tool"

if [ ! -x "$CLIENT_TOOL" ]; then
    echo "ERROR: $CLIENT_TOOL not found or not executable"
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
    -days 1 -subj "/CN=TLS13 Test CA" -sha256 2>/dev/null

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

# RSA CA + server cert (for RSA-PSS CertificateVerify in TLS 1.3)
echo "=== Generating RSA test PKI ==="
openssl genrsa -traditional -out "$TMPDIR/rsa_ca_key.pem" 2048 2>/dev/null
openssl req -x509 -new -key "$TMPDIR/rsa_ca_key.pem" -out "$TMPDIR/rsa_ca.pem" \
    -days 1 -subj "/CN=TLS13 RSA Test CA" -sha256 2>/dev/null

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

start_openssl_server() {
    local port="$1"
    shift
    openssl s_server \
        -cert "$TMPDIR/chain.pem" -key "$TMPDIR/server_key.pem" \
        -port "$port" -tls1_3 -www \
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

start_openssl_rsa_server() {
    local port="$1"
    shift
    openssl s_server \
        -cert "$TMPDIR/rsa_chain.pem" -key "$TMPDIR/rsa_server_key.pem" \
        -port "$port" -tls1_3 -www \
        "$@" \
        > "$TMPDIR/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 1
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "ERROR: openssl s_server (RSA) failed to start"
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
    echo "=== Test: TLS 1.3 $SUITE (ECDSA) ==="
    PORT=$(get_port 14500)
    start_openssl_server "$PORT" -ciphersuites "$SUITE"

    run_test "TLS 1.3 $SUITE ECDSA" "HTTP" \
        "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" localhost "$PORT"

    stop_server
done

# ========== Test 2: Per key exchange group ==========
for GROUP in X25519 P-256 P-384; do
    echo ""
    echo "=== Test: TLS 1.3 key exchange group $GROUP ==="
    PORT=$(get_port 14503)
    start_openssl_server "$PORT" -groups "$GROUP"

    run_test "TLS 1.3 group $GROUP" "HTTP" \
        "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" localhost "$PORT"

    stop_server
done

# ========== Test 3: RSA server cert (RSA-PSS CertificateVerify) ==========
echo ""
echo "=== Test: TLS 1.3 RSA cert (RSA-PSS CertificateVerify) ==="
PORT=$(get_port 14506)
start_openssl_rsa_server "$PORT" -ciphersuites TLS_AES_128_GCM_SHA256

run_test "TLS 1.3 RSA cert AES-128-GCM" "HTTP" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/rsa_ca.pem" localhost "$PORT"

stop_server

echo ""
echo "=== Test: TLS 1.3 RSA cert AES-256-GCM ==="
PORT=$(get_port 14507)
start_openssl_rsa_server "$PORT" -ciphersuites TLS_AES_256_GCM_SHA384

run_test "TLS 1.3 RSA cert AES-256-GCM" "HTTP" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/rsa_ca.pem" localhost "$PORT"

stop_server

# ========== Results ==========
echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
