#!/usr/bin/env bash
#
# TLS 1.2 server integration test — verifies the tls_server_tool works
# with both curl and the project's own tls_connect_tool, including mTLS.
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

# Find a free port
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

# Expect the command to fail
run_test_fail() {
    local name="$1"
    shift
    TOTAL=$((TOTAL + 1))
    printf "  %-55s " "$name"
    if output=$("$@" 2>&1); then
        echo "FAIL (should have been rejected)"
        echo "    Output:"
        echo "$output" | tail -5 | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    else
        echo "PASS (correctly rejected)"
        PASS=$((PASS + 1))
    fi
}

start_server() {
    local port="$1"
    shift
    "$SERVER_TOOL" "$@" "" "$port" > "$TMPDIR/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 1
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "ERROR: Server failed to start"
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
    PORT=$(get_port 14433)
    start_server "$PORT" "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem"

    run_test "curl $SUITE -> Hello, world!" "Hello, world!" \
        curl -s --cacert "$TMPDIR/ca.pem" --tlsv1.2 --tls-max 1.2 \
        --ciphers "$SUITE" "https://localhost:$PORT/"

    run_test "tls_connect_tool -> Hello, world!" "Hello, world!" \
        "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" localhost "$PORT"

    stop_server
done

# ========== Test 2: Optional mTLS (client with cert) ==========
echo ""
echo "=== Test: Optional mTLS ==="
PORT=$(get_port 14434)
start_server "$PORT" --client-ca "$TMPDIR/client_ca.pem" \
    "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem"

run_test "client with cert -> Hello, secure!" "Hello, secure!" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" \
    --cert "$TMPDIR/client_chain.pem" --key "$TMPDIR/client_key.pem" \
    localhost "$PORT"

run_test "client without cert -> Hello, insecure!" "Hello, insecure!" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" localhost "$PORT"

run_test "curl with cert -> Hello, secure!" "Hello, secure!" \
    curl -s --cacert "$TMPDIR/ca.pem" --tlsv1.2 --tls-max 1.2 \
    --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
    --cert "$TMPDIR/client.pem" --key "$TMPDIR/client_key.pem" \
    "https://localhost:$PORT/"

stop_server

# ========== Test 3: Required mTLS ==========
echo ""
echo "=== Test: Required mTLS ==="
PORT=$(get_port 14435)
start_server "$PORT" --client-ca "$TMPDIR/client_ca.pem" --require-client-cert \
    "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem"

run_test "client with cert -> Hello, secure!" "Hello, secure!" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" \
    --cert "$TMPDIR/client_chain.pem" --key "$TMPDIR/client_key.pem" \
    localhost "$PORT"

run_test_fail "client without cert -> rejected" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" localhost "$PORT"

stop_server

# ========== Test 4: RSA server certificate ==========
echo ""
echo "=== Generating RSA test PKI ==="

# RSA server key and CA-signed cert
openssl genrsa -traditional -out "$TMPDIR/rsa_ca_key.pem" 2048 2>/dev/null
openssl req -x509 -new -key "$TMPDIR/rsa_ca_key.pem" -out "$TMPDIR/rsa_ca.pem" \
    -days 1 -subj "/CN=RSA Test CA" -sha256 2>/dev/null

openssl genrsa -traditional -out "$TMPDIR/rsa_server_key.pem" 2048 2>/dev/null
openssl req -new -key "$TMPDIR/rsa_server_key.pem" -out "$TMPDIR/rsa_server.csr" \
    -subj "/CN=localhost" -sha256 2>/dev/null

openssl x509 -req -in "$TMPDIR/rsa_server.csr" -CA "$TMPDIR/rsa_ca.pem" \
    -CAkey "$TMPDIR/rsa_ca_key.pem" -CAcreateserial -out "$TMPDIR/rsa_server.pem" \
    -days 1 -sha256 -extfile "$TMPDIR/ext.cnf" -extensions v3_req 2>/dev/null

cat "$TMPDIR/rsa_server.pem" "$TMPDIR/rsa_ca.pem" > "$TMPDIR/rsa_chain.pem"

for SUITE in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384; do
    echo ""
    echo "=== Test: RSA TLS ($SUITE) ==="
    PORT=$(get_port 14436)
    start_server "$PORT" "$TMPDIR/rsa_chain.pem" "$TMPDIR/rsa_server_key.pem"

    run_test "curl $SUITE -> Hello, world!" "Hello, world!" \
        curl -s --cacert "$TMPDIR/rsa_ca.pem" --tlsv1.2 --tls-max 1.2 \
        --ciphers "$SUITE" "https://localhost:$PORT/"

    run_test "tls_connect_tool -> Hello, world!" "Hello, world!" \
        "$CLIENT_TOOL" --cafile "$TMPDIR/rsa_ca.pem" localhost "$PORT"

    stop_server
done

# ========== Test 5: RSA server with EC client mTLS ==========
echo ""
echo "=== Test: RSA server + EC client mTLS ==="
PORT=$(get_port 14437)
start_server "$PORT" --client-ca "$TMPDIR/client_ca.pem" \
    "$TMPDIR/rsa_chain.pem" "$TMPDIR/rsa_server_key.pem"

run_test "EC client cert with RSA server -> Hello, secure!" "Hello, secure!" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/rsa_ca.pem" \
    --cert "$TMPDIR/client_chain.pem" --key "$TMPDIR/client_key.pem" \
    localhost "$PORT"

run_test "curl EC client with RSA server -> Hello, secure!" "Hello, secure!" \
    curl -s --cacert "$TMPDIR/rsa_ca.pem" --tlsv1.2 --tls-max 1.2 \
    --ciphers ECDHE-RSA-AES128-GCM-SHA256 \
    --cert "$TMPDIR/client.pem" --key "$TMPDIR/client_key.pem" \
    "https://localhost:$PORT/"

stop_server

# ========== Test 6: RSA client cert with ECDSA server (cross-key mTLS) ==========
echo ""
echo "=== Test: ECDSA server + RSA client mTLS ==="

# Generate RSA client cert
openssl genrsa -traditional -out "$TMPDIR/rsa_client_key.pem" 2048 2>/dev/null
openssl req -new -key "$TMPDIR/rsa_client_key.pem" -out "$TMPDIR/rsa_client.csr" \
    -subj "/CN=RSA Test Client" -sha256 2>/dev/null
openssl x509 -req -in "$TMPDIR/rsa_client.csr" -CA "$TMPDIR/client_ca.pem" \
    -CAkey "$TMPDIR/client_ca_key.pem" -CAcreateserial -out "$TMPDIR/rsa_client.pem" \
    -days 1 -sha256 2>/dev/null
cat "$TMPDIR/rsa_client.pem" "$TMPDIR/client_ca.pem" > "$TMPDIR/rsa_client_chain.pem"

PORT=$(get_port 14438)
start_server "$PORT" --client-ca "$TMPDIR/client_ca.pem" \
    "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem"

run_test "RSA client cert with ECDSA server -> Hello, secure!" "Hello, secure!" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" \
    --cert "$TMPDIR/rsa_client_chain.pem" --key "$TMPDIR/rsa_client_key.pem" \
    localhost "$PORT"

run_test "curl RSA client with ECDSA server -> Hello, secure!" "Hello, secure!" \
    curl -s --cacert "$TMPDIR/ca.pem" --tlsv1.2 --tls-max 1.2 \
    --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
    --cert "$TMPDIR/rsa_client.pem" --key "$TMPDIR/rsa_client_key.pem" \
    "https://localhost:$PORT/"

stop_server

# ========== Test 7: Session Tickets ==========
echo ""
echo "=== Test: Session Tickets (RFC 5077) ==="
PORT=$(get_port 14439)
start_server "$PORT" --ticket-key "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem"

TICKET_FILE="$TMPDIR/session_ticket.bin"

# First connection: full handshake, should receive a ticket
run_test "first connect (full handshake) -> Hello, world!" "Hello, world!" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" --ticket-file "$TICKET_FILE" localhost "$PORT"

# Verify ticket file was created
TOTAL=$((TOTAL + 1))
printf "  %-55s " "ticket file saved"
if [ -f "$TICKET_FILE" ] && [ -s "$TICKET_FILE" ]; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (ticket file not created)"
    FAIL=$((FAIL + 1))
fi

# Second connection: should resume via ticket
run_test "second connect (ticket resumption) -> Hello, world!" "Hello, world!" \
    "$CLIENT_TOOL" --cafile "$TMPDIR/ca.pem" --ticket-file "$TICKET_FILE" localhost "$PORT"

stop_server

# ========== Test 8: Session ticket resumption (openssl s_client → our server) ==========
echo ""
echo "=== Test: Session Ticket Resumption with openssl s_client ==="
PORT=$(get_port 14440)
start_server "$PORT" --ticket-key "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem"

# First connection: full handshake, save session
TOTAL=$((TOTAL + 1))
printf "  %-55s " "openssl s_client full handshake (save session)"
output=$(printf 'GET / HTTP/1.0\r\n\r\n' | \
    openssl s_client -connect "localhost:$PORT" -CAfile "$TMPDIR/ca.pem" \
    -tls1_2 -sess_out "$TMPDIR/openssl_sess.pem" 2>&1)
if echo "$output" | grep -q "New,.*TLSv1.2"; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected New session)"
    echo "$output" | grep -E "New,|Reused," | sed 's/^/    /'
    FAIL=$((FAIL + 1))
fi

# Second connection: resume via session ticket
TOTAL=$((TOTAL + 1))
printf "  %-55s " "openssl s_client ticket resumption"
output=$(printf 'GET / HTTP/1.0\r\n\r\n' | \
    openssl s_client -connect "localhost:$PORT" -CAfile "$TMPDIR/ca.pem" \
    -tls1_2 -sess_in "$TMPDIR/openssl_sess.pem" 2>&1)
if echo "$output" | grep -q "Reused,.*TLSv1.2"; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected Reused session)"
    echo "$output" | grep -E "New,|Reused," | sed 's/^/    /'
    FAIL=$((FAIL + 1))
fi

stop_server

# ========== Test 9: Session ID resumption (openssl s_client → our server) ==========
echo ""
echo "=== Test: Session ID Resumption with openssl s_client ==="
PORT=$(get_port 14441)
start_server "$PORT" --session-cache "$TMPDIR/chain.pem" "$TMPDIR/server_key.pem"

# First connection: full handshake, save session (no tickets)
TOTAL=$((TOTAL + 1))
printf "  %-55s " "openssl s_client full handshake (session ID, save)"
output=$(printf 'GET / HTTP/1.0\r\n\r\n' | \
    openssl s_client -connect "localhost:$PORT" -CAfile "$TMPDIR/ca.pem" \
    -tls1_2 -no_ticket -sess_out "$TMPDIR/openssl_sess_id.pem" 2>&1)
if echo "$output" | grep -q "New,.*TLSv1.2"; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected New session)"
    echo "$output" | grep -E "New,|Reused," | sed 's/^/    /'
    FAIL=$((FAIL + 1))
fi

# Second connection: resume via session ID
TOTAL=$((TOTAL + 1))
printf "  %-55s " "openssl s_client session ID resumption"
output=$(printf 'GET / HTTP/1.0\r\n\r\n' | \
    openssl s_client -connect "localhost:$PORT" -CAfile "$TMPDIR/ca.pem" \
    -tls1_2 -no_ticket -sess_in "$TMPDIR/openssl_sess_id.pem" 2>&1)
if echo "$output" | grep -q "Reused,.*TLSv1.2"; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected Reused session)"
    echo "$output" | grep -E "New,|Reused," | sed 's/^/    /'
    FAIL=$((FAIL + 1))
fi

stop_server

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
