#!/usr/bin/env bash
#
# DTLS 1.2 integration test — verifies dtls_server_tool and dtls_connect_tool
# interoperate correctly, including mTLS and RSA keys.
#
# Tests our client against our server (self-interop) since OpenSSL's
# s_server/s_client DTLS support requires special setup (BIO_s_datagram,
# -listen flag with root) that varies by platform.
#
# Usage: ./tests/test_dtls_server.sh [build_dir]

set -euo pipefail

BUILD="${1:-./build}"
SERVER_TOOL="$BUILD/dtls_server_tool"
CLIENT_TOOL="$BUILD/dtls_connect_tool"

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

# Generate test PKI
echo "=== Generating test PKI ==="

# EC CA + server cert
openssl ecparam -name prime256v1 -genkey -noout -out "$TMPDIR/ca_key.pem" 2>/dev/null
openssl req -x509 -new -key "$TMPDIR/ca_key.pem" -out "$TMPDIR/ca.pem" \
    -days 1 -subj "/CN=Test CA" -sha256 2>/dev/null

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
openssl genrsa -out "$TMPDIR/rsa_ca_key.pem" 2048 2>/dev/null
openssl req -x509 -new -key "$TMPDIR/rsa_ca_key.pem" -out "$TMPDIR/rsa_ca.pem" \
    -days 1 -subj "/CN=RSA Test CA" -sha256 2>/dev/null

openssl genrsa -out "$TMPDIR/rsa_server_key.pem" 2048 2>/dev/null
openssl req -new -key "$TMPDIR/rsa_server_key.pem" -out "$TMPDIR/rsa_server.csr" \
    -subj "/CN=localhost" -sha256 2>/dev/null

openssl x509 -req -in "$TMPDIR/rsa_server.csr" -CA "$TMPDIR/rsa_ca.pem" \
    -CAkey "$TMPDIR/rsa_ca_key.pem" -CAcreateserial -out "$TMPDIR/rsa_server.pem" \
    -days 1 -sha256 -extfile "$TMPDIR/ext.cnf" -extensions v3_req 2>/dev/null

cat "$TMPDIR/rsa_server.pem" "$TMPDIR/rsa_ca.pem" > "$TMPDIR/rsa_chain.pem"

# Client cert for mTLS (EC)
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

# RSA client cert for mTLS
openssl genrsa -out "$TMPDIR/rsa_client_key.pem" 2048 2>/dev/null
openssl req -new -key "$TMPDIR/rsa_client_key.pem" -out "$TMPDIR/rsa_client.csr" \
    -subj "/CN=RSA Test Client" -sha256 2>/dev/null
openssl x509 -req -in "$TMPDIR/rsa_client.csr" -CA "$TMPDIR/client_ca.pem" \
    -CAkey "$TMPDIR/client_ca_key.pem" -CAcreateserial -out "$TMPDIR/rsa_client.pem" \
    -days 1 -sha256 2>/dev/null

cat "$TMPDIR/rsa_client.pem" "$TMPDIR/client_ca.pem" > "$TMPDIR/rsa_client_chain.pem"

get_port() {
    python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null || echo "$1"
}

PASS=0
FAIL=0
TOTAL=0

run_test() {
    local name="$1"
    local expected="$2"
    shift 2
    TOTAL=$((TOTAL + 1))
    echo -n "  $name: "
    if output=$("$@" 2>&1); then
        if [ "$expected" = "pass" ]; then
            echo "PASS"
            PASS=$((PASS + 1))
        else
            echo "FAIL (expected failure, got success)"
            FAIL=$((FAIL + 1))
        fi
    else
        if [ "$expected" = "fail" ]; then
            echo "PASS (expected failure)"
            PASS=$((PASS + 1))
        else
            echo "FAIL"
            echo "    output: $(echo "$output" | head -5)"
            FAIL=$((FAIL + 1))
        fi
    fi
}

wait_for_server() {
    for i in $(seq 1 20); do
        if kill -0 "$1" 2>/dev/null; then
            sleep 0.1
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# ============================================================
echo ""
echo "=== Test: DTLS ECDHE-ECDSA (EC server key) ==="

PORT=$(get_port 14433)
$SERVER_TOOL "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem" "" "$PORT" &
SERVER_PID=$!
wait_for_server $SERVER_PID

run_test "dtls_ecdhe_ecdsa" "pass" \
    timeout 10 $CLIENT_TOOL --cafile "$TMPDIR/ca.pem" localhost "$PORT"

kill -9 $SERVER_PID 2>/dev/null; SERVER_PID=""
sleep 0.5

# ============================================================
echo ""
echo "=== Test: DTLS ECDHE-RSA (RSA server key) ==="

PORT=$(get_port 14434)
$SERVER_TOOL "$TMPDIR/rsa_chain.pem" "$TMPDIR/rsa_server_key.pem" "" "$PORT" &
SERVER_PID=$!
wait_for_server $SERVER_PID

run_test "dtls_ecdhe_rsa" "pass" \
    timeout 10 $CLIENT_TOOL --cafile "$TMPDIR/rsa_ca.pem" localhost "$PORT"

kill -9 $SERVER_PID 2>/dev/null; SERVER_PID=""
sleep 0.5

# ============================================================
echo ""
echo "=== Test: DTLS mTLS with EC client cert ==="

PORT=$(get_port 14435)
$SERVER_TOOL --client-ca "$TMPDIR/client_ca.pem" --require-client-cert \
    "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem" "" "$PORT" &
SERVER_PID=$!
wait_for_server $SERVER_PID

run_test "dtls_mtls_ec_client" "pass" \
    timeout 10 $CLIENT_TOOL --cafile "$TMPDIR/ca.pem" \
        --cert "$TMPDIR/client_chain.pem" --key "$TMPDIR/client_key.pem" \
        localhost "$PORT"

kill -9 $SERVER_PID 2>/dev/null; SERVER_PID=""
sleep 0.5

# ============================================================
echo ""
echo "=== Test: DTLS mTLS with RSA client cert on EC server ==="

PORT=$(get_port 14436)
$SERVER_TOOL --client-ca "$TMPDIR/client_ca.pem" --require-client-cert \
    "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem" "" "$PORT" &
SERVER_PID=$!
wait_for_server $SERVER_PID

run_test "dtls_mtls_rsa_client_ec_server" "pass" \
    timeout 10 $CLIENT_TOOL --cafile "$TMPDIR/ca.pem" \
        --cert "$TMPDIR/rsa_client_chain.pem" --key "$TMPDIR/rsa_client_key.pem" \
        localhost "$PORT"

kill -9 $SERVER_PID 2>/dev/null; SERVER_PID=""
sleep 0.5

# ============================================================
echo ""
echo "=== Test: DTLS mTLS with EC client cert on RSA server ==="

PORT=$(get_port 14437)
$SERVER_TOOL --client-ca "$TMPDIR/client_ca.pem" --require-client-cert \
    "$TMPDIR/rsa_chain.pem" "$TMPDIR/rsa_server_key.pem" "" "$PORT" &
SERVER_PID=$!
wait_for_server $SERVER_PID

run_test "dtls_mtls_ec_client_rsa_server" "pass" \
    timeout 10 $CLIENT_TOOL --cafile "$TMPDIR/rsa_ca.pem" \
        --cert "$TMPDIR/client_chain.pem" --key "$TMPDIR/client_key.pem" \
        localhost "$PORT"

kill -9 $SERVER_PID 2>/dev/null; SERVER_PID=""
sleep 0.5

# ============================================================
echo ""
echo "=== Test: Optional mTLS (client sends cert) ==="

PORT=$(get_port 14438)
$SERVER_TOOL --client-ca "$TMPDIR/client_ca.pem" \
    "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem" "" "$PORT" &
SERVER_PID=$!
wait_for_server $SERVER_PID

run_test "dtls_optional_mtls_with_cert" "pass" \
    bash -c "timeout 10 $CLIENT_TOOL --cafile '$TMPDIR/ca.pem' \
        --cert '$TMPDIR/client_chain.pem' --key '$TMPDIR/client_key.pem' \
        localhost $PORT 2>&1 | grep -q 'Hello, secure!'"

kill -9 $SERVER_PID 2>/dev/null; SERVER_PID=""
sleep 0.5

# ============================================================
echo ""
echo "=== Test: Optional mTLS (client sends no cert) ==="

PORT=$(get_port 14439)
$SERVER_TOOL --client-ca "$TMPDIR/client_ca.pem" \
    "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem" "" "$PORT" &
SERVER_PID=$!
wait_for_server $SERVER_PID

run_test "dtls_optional_mtls_no_cert" "pass" \
    bash -c "timeout 10 $CLIENT_TOOL --cafile '$TMPDIR/ca.pem' \
        localhost $PORT 2>&1 | grep -q 'Hello, insecure!'"

kill -9 $SERVER_PID 2>/dev/null; SERVER_PID=""
sleep 0.5

# ============================================================
echo ""
echo "=== Test: Required mTLS without cert (should reject) ==="

PORT=$(get_port 14440)
$SERVER_TOOL --client-ca "$TMPDIR/client_ca.pem" --require-client-cert \
    "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem" "" "$PORT" &
SERVER_PID=$!
wait_for_server $SERVER_PID

run_test "dtls_required_mtls_no_cert" "fail" \
    timeout 10 $CLIENT_TOOL --cafile "$TMPDIR/ca.pem" localhost "$PORT"

kill -9 $SERVER_PID 2>/dev/null; SERVER_PID=""

# ============================================================
# OpenSSL interop tests
# ============================================================

echo ""
echo "=== Test: OpenSSL s_client vs our server (EC) ==="

PORT=$(get_port 14440)
$SERVER_TOOL "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem" "" "$PORT" &
SERVER_PID=$!
wait_for_server $SERVER_PID

run_test "dtls_openssl_client_ec" "pass" \
    bash -c "echo 'hello' | timeout 12 openssl s_client -dtls1_2 \
        -connect 127.0.0.1:$PORT -CAfile '$TMPDIR/ca.pem' 2>&1 \
        | grep -q 'Verify return code: 0'"

kill -9 $SERVER_PID 2>/dev/null; SERVER_PID=""
sleep 0.5

echo ""
echo "=== Test: Our client vs OpenSSL s_server (EC) ==="

PORT=$(get_port 14440)
sleep 30 | openssl s_server -dtls1_2 -4 -accept "$PORT" \
    -cert "$TMPDIR/chain.pem" -key "$TMPDIR/server_key.pem" 2>/dev/null &
SERVER_PID=$!
sleep 2

run_test "dtls_openssl_server_ec" "pass" \
    bash -c "timeout 15 $CLIENT_TOOL --cafile '$TMPDIR/ca.pem' \
        localhost $PORT 2>&1 | grep -q 'DTLS handshake complete'"

kill -9 $SERVER_PID 2>/dev/null; SERVER_PID=""
sleep 0.5

echo ""
echo "=== Test: OpenSSL s_client vs our server (RSA) ==="

PORT=$(get_port 14440)
$SERVER_TOOL "$TMPDIR/rsa_chain.pem" "$TMPDIR/rsa_server_key.pem" "" "$PORT" &
SERVER_PID=$!
wait_for_server $SERVER_PID

run_test "dtls_openssl_client_rsa" "pass" \
    bash -c "echo 'hello' | timeout 12 openssl s_client -dtls1_2 \
        -connect 127.0.0.1:$PORT -CAfile '$TMPDIR/rsa_ca.pem' 2>&1 \
        | grep -q 'Verify return code: 0'"

kill -9 $SERVER_PID 2>/dev/null; SERVER_PID=""

# ============================================================
echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
