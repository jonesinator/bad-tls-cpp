#!/usr/bin/env bash
#
# ECDSA/ECDH/RSA-PSS interop tests between this library and OpenSSL.
#
# Proves bidirectional compatibility:
#   1. OpenSSL signs, this library verifies
#   2. This library signs, OpenSSL verifies
#
# Also tests with multiple messages and freshly generated keys.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
TOOL="$BUILD_DIR/ecdsa_tool"
RSA_TOOL="$BUILD_DIR/rsa_tool"
X509_TOOL="$BUILD_DIR/x509_tool"
WORK="$(mktemp -d)"

trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0

check() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        printf "  PASS  %s\n" "$desc"
        pass=$((pass + 1))
    else
        printf "  FAIL  %s\n" "$desc"
        fail=$((fail + 1))
    fi
}

check_fail() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        printf "  FAIL  %s (expected failure)\n" "$desc"
        fail=$((fail + 1))
    else
        printf "  PASS  %s (correctly rejected)\n" "$desc"
        pass=$((pass + 1))
    fi
}

# --- Build ---

printf "Building tools...\n"
cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug >/dev/null 2>&1
cmake --build "$BUILD_DIR" --target ecdsa_tool --target rsa_tool --target x509_tool >/dev/null 2>&1
printf "Build OK.\n\n"

# --- Key 1: the hardcoded test key ---

cat > "$WORK/key1.pem" << 'EOF'
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILqCeQe9YS7mdX3IseutWyDcygJWrKtkpQul8wWxsKNMoAoGCCqGSM49
AwEHoUQDQgAE2wIVduUCSe5a9JoCg7cE5lmkK1GAlNnYpqTz5ZB9339rsLkmHZIi
jMWwbEFkrrjsCG4+H2avHOsSky5iNHfRvA==
-----END EC PRIVATE KEY-----
EOF
openssl ec -in "$WORK/key1.pem" -pubout -out "$WORK/pub1.pem" 2>/dev/null

# --- Key 2: freshly generated P-256 ---

openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/key2.pem" 2>/dev/null
openssl ec -in "$WORK/key2.pem" -pubout -out "$WORK/pub2.pem" 2>/dev/null

# --- Key 3: freshly generated P-384 ---

openssl ecparam -name secp384r1 -genkey -noout -out "$WORK/key3.pem" 2>/dev/null
openssl ec -in "$WORK/key3.pem" -pubout -out "$WORK/pub3.pem" 2>/dev/null

# --- Test messages ---

printf "hello world"           > "$WORK/msg1.bin"
printf ""                      > "$WORK/msg2.bin"  # empty
printf "The quick brown fox jumps over the lazy dog" > "$WORK/msg3.bin"
dd if=/dev/urandom bs=4096 count=1 of="$WORK/msg4.bin" 2>/dev/null  # 4 KB random

# =========================================================================
printf "=== Test suite: hardcoded key ===\n"
# =========================================================================

for i in 1 2 3 4; do
    msg="$WORK/msg${i}.bin"
    tag="key1/msg${i}"

    # OpenSSL signs -> library verifies
    openssl dgst -sha256 -sign "$WORK/key1.pem" -out "$WORK/sig_ossl.der" "$msg"
    check "$tag: openssl signs, library verifies" \
        "$TOOL" verify "$WORK/key1.pem" "$msg" "$WORK/sig_ossl.der"

    # Library signs -> OpenSSL verifies
    "$TOOL" sign "$WORK/key1.pem" "$msg" "$WORK/sig_lib.der" >/dev/null
    check "$tag: library signs, openssl verifies" \
        openssl dgst -sha256 -verify "$WORK/pub1.pem" -signature "$WORK/sig_lib.der" "$msg"

    # Library signs -> library verifies
    check "$tag: library signs, library verifies" \
        "$TOOL" verify "$WORK/key1.pem" "$msg" "$WORK/sig_lib.der"

    # OpenSSL signs -> OpenSSL verifies
    check "$tag: openssl signs, openssl verifies" \
        openssl dgst -sha256 -verify "$WORK/pub1.pem" -signature "$WORK/sig_ossl.der" "$msg"
done

# =========================================================================
printf "\n=== Test suite: fresh key ===\n"
# =========================================================================

for i in 1 2 3 4; do
    msg="$WORK/msg${i}.bin"
    tag="key2/msg${i}"

    openssl dgst -sha256 -sign "$WORK/key2.pem" -out "$WORK/sig_ossl.der" "$msg"
    check "$tag: openssl signs, library verifies" \
        "$TOOL" verify "$WORK/key2.pem" "$msg" "$WORK/sig_ossl.der"

    "$TOOL" sign "$WORK/key2.pem" "$msg" "$WORK/sig_lib.der" >/dev/null
    check "$tag: library signs, openssl verifies" \
        openssl dgst -sha256 -verify "$WORK/pub2.pem" -signature "$WORK/sig_lib.der" "$msg"

    check "$tag: library signs, library verifies" \
        "$TOOL" verify "$WORK/key2.pem" "$msg" "$WORK/sig_lib.der"

    check "$tag: openssl signs, openssl verifies" \
        openssl dgst -sha256 -verify "$WORK/pub2.pem" -signature "$WORK/sig_ossl.der" "$msg"
done

# =========================================================================
printf "\n=== Test suite: P-384 fresh key ===\n"
# =========================================================================

for i in 1 2 3 4; do
    msg="$WORK/msg${i}.bin"
    tag="key3/msg${i}"

    # OpenSSL signs -> library verifies
    openssl dgst -sha384 -sign "$WORK/key3.pem" -out "$WORK/sig_ossl.der" "$msg"
    check "$tag: openssl signs, library verifies" \
        "$TOOL" verify "$WORK/key3.pem" "$msg" "$WORK/sig_ossl.der"

    # Library signs -> OpenSSL verifies
    "$TOOL" sign "$WORK/key3.pem" "$msg" "$WORK/sig_lib.der" >/dev/null
    check "$tag: library signs, openssl verifies" \
        openssl dgst -sha384 -verify "$WORK/pub3.pem" -signature "$WORK/sig_lib.der" "$msg"

    # Library signs -> library verifies
    check "$tag: library signs, library verifies" \
        "$TOOL" verify "$WORK/key3.pem" "$msg" "$WORK/sig_lib.der"

    # OpenSSL signs -> OpenSSL verifies
    check "$tag: openssl signs, openssl verifies" \
        openssl dgst -sha384 -verify "$WORK/pub3.pem" -signature "$WORK/sig_ossl.der" "$msg"
done

# =========================================================================
printf "\n=== Test suite: negative cases ===\n"
# =========================================================================

# Sign msg1 with key1 (P-256), try to verify against msg3 (wrong message)
"$TOOL" sign "$WORK/key1.pem" "$WORK/msg1.bin" "$WORK/sig_neg.der" >/dev/null
check_fail "wrong message rejected by library" \
    "$TOOL" verify "$WORK/key1.pem" "$WORK/msg3.bin" "$WORK/sig_neg.der"

check_fail "wrong message rejected by openssl" \
    openssl dgst -sha256 -verify "$WORK/pub1.pem" -signature "$WORK/sig_neg.der" "$WORK/msg3.bin"

# Sign with key1 (P-256), verify with key2 (P-256, wrong key)
check_fail "wrong key rejected by library" \
    "$TOOL" verify "$WORK/key2.pem" "$WORK/msg1.bin" "$WORK/sig_neg.der"

check_fail "wrong key rejected by openssl" \
    openssl dgst -sha256 -verify "$WORK/pub2.pem" -signature "$WORK/sig_neg.der" "$WORK/msg1.bin"

# Sign msg1 with key3 (P-384), wrong message
"$TOOL" sign "$WORK/key3.pem" "$WORK/msg1.bin" "$WORK/sig_neg384.der" >/dev/null
check_fail "P-384 wrong message rejected by library" \
    "$TOOL" verify "$WORK/key3.pem" "$WORK/msg3.bin" "$WORK/sig_neg384.der"

check_fail "P-384 wrong message rejected by openssl" \
    openssl dgst -sha384 -verify "$WORK/pub3.pem" -signature "$WORK/sig_neg384.der" "$WORK/msg3.bin"

# =========================================================================
printf "\n=== Test suite: ECDH P-256 ===\n"
# =========================================================================

# Generate two P-256 keypairs for ECDH
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ecdh_a.pem" 2>/dev/null
openssl ec -in "$WORK/ecdh_a.pem" -pubout -out "$WORK/ecdh_a_pub.pem" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ecdh_b.pem" 2>/dev/null
openssl ec -in "$WORK/ecdh_b.pem" -pubout -out "$WORK/ecdh_b_pub.pem" 2>/dev/null

# OpenSSL derives shared secrets from both sides
openssl pkeyutl -derive -inkey "$WORK/ecdh_a.pem" -peerkey "$WORK/ecdh_b_pub.pem" -out "$WORK/ecdh_ossl_ab.bin" 2>/dev/null
openssl pkeyutl -derive -inkey "$WORK/ecdh_b.pem" -peerkey "$WORK/ecdh_a_pub.pem" -out "$WORK/ecdh_ossl_ba.bin" 2>/dev/null

check "P-256 openssl A*B == openssl B*A" cmp "$WORK/ecdh_ossl_ab.bin" "$WORK/ecdh_ossl_ba.bin"

# Library derives shared secrets from both sides
"$TOOL" derive "$WORK/ecdh_a.pem" "$WORK/ecdh_b_pub.pem" "$WORK/ecdh_lib_ab.bin" >/dev/null
"$TOOL" derive "$WORK/ecdh_b.pem" "$WORK/ecdh_a_pub.pem" "$WORK/ecdh_lib_ba.bin" >/dev/null

check "P-256 library A*B == library B*A" cmp "$WORK/ecdh_lib_ab.bin" "$WORK/ecdh_lib_ba.bin"

# Cross-compare: library matches OpenSSL
check "P-256 library A*B == openssl A*B" cmp "$WORK/ecdh_lib_ab.bin" "$WORK/ecdh_ossl_ab.bin"
check "P-256 library B*A == openssl B*A" cmp "$WORK/ecdh_lib_ba.bin" "$WORK/ecdh_ossl_ba.bin"

# =========================================================================
printf "\n=== Test suite: ECDH P-384 ===\n"
# =========================================================================

# Generate two P-384 keypairs for ECDH
openssl ecparam -name secp384r1 -genkey -noout -out "$WORK/ecdh384_a.pem" 2>/dev/null
openssl ec -in "$WORK/ecdh384_a.pem" -pubout -out "$WORK/ecdh384_a_pub.pem" 2>/dev/null
openssl ecparam -name secp384r1 -genkey -noout -out "$WORK/ecdh384_b.pem" 2>/dev/null
openssl ec -in "$WORK/ecdh384_b.pem" -pubout -out "$WORK/ecdh384_b_pub.pem" 2>/dev/null

# OpenSSL derives shared secrets from both sides
openssl pkeyutl -derive -inkey "$WORK/ecdh384_a.pem" -peerkey "$WORK/ecdh384_b_pub.pem" -out "$WORK/ecdh384_ossl_ab.bin" 2>/dev/null
openssl pkeyutl -derive -inkey "$WORK/ecdh384_b.pem" -peerkey "$WORK/ecdh384_a_pub.pem" -out "$WORK/ecdh384_ossl_ba.bin" 2>/dev/null

check "P-384 openssl A*B == openssl B*A" cmp "$WORK/ecdh384_ossl_ab.bin" "$WORK/ecdh384_ossl_ba.bin"

# Library derives shared secrets from both sides
"$TOOL" derive "$WORK/ecdh384_a.pem" "$WORK/ecdh384_b_pub.pem" "$WORK/ecdh384_lib_ab.bin" >/dev/null
"$TOOL" derive "$WORK/ecdh384_b.pem" "$WORK/ecdh384_a_pub.pem" "$WORK/ecdh384_lib_ba.bin" >/dev/null

check "P-384 library A*B == library B*A" cmp "$WORK/ecdh384_lib_ab.bin" "$WORK/ecdh384_lib_ba.bin"

# Cross-compare: library matches OpenSSL
check "P-384 library A*B == openssl A*B" cmp "$WORK/ecdh384_lib_ab.bin" "$WORK/ecdh384_ossl_ab.bin"
check "P-384 library B*A == openssl B*A" cmp "$WORK/ecdh384_lib_ba.bin" "$WORK/ecdh384_ossl_ba.bin"

# =========================================================================
printf "\n=== Test suite: RSA-PSS 2048 ===\n"
# =========================================================================

openssl genrsa -out "$WORK/rsa_key.pem" 2048 2>/dev/null
openssl rsa -in "$WORK/rsa_key.pem" -pubout -out "$WORK/rsa_pub.pem" 2>/dev/null

for i in 1 2 3 4; do
    msg="$WORK/msg${i}.bin"
    tag="rsa2048/msg${i}"

    # OpenSSL signs PSS -> library verifies
    openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
        -sign "$WORK/rsa_key.pem" -out "$WORK/rsa_sig_ossl.bin" "$msg"
    check "$tag: openssl PSS signs, library verifies" \
        "$RSA_TOOL" verify-pss "$WORK/rsa_key.pem" "$msg" "$WORK/rsa_sig_ossl.bin"

    # Library signs PSS -> OpenSSL verifies
    "$RSA_TOOL" sign-pss "$WORK/rsa_key.pem" "$msg" "$WORK/rsa_sig_lib.bin" >/dev/null
    check "$tag: library PSS signs, openssl verifies" \
        openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
            -verify "$WORK/rsa_pub.pem" -signature "$WORK/rsa_sig_lib.bin" "$msg"

    # Library signs -> library verifies
    check "$tag: library PSS signs, library verifies" \
        "$RSA_TOOL" verify-pss "$WORK/rsa_key.pem" "$msg" "$WORK/rsa_sig_lib.bin"
done

# =========================================================================
printf "\n=== Test suite: RSA-PSS negative cases ===\n"
# =========================================================================

# Sign msg1 with RSA key, try to verify against msg3 (wrong message)
"$RSA_TOOL" sign-pss "$WORK/rsa_key.pem" "$WORK/msg1.bin" "$WORK/rsa_sig_neg.bin" >/dev/null
check_fail "RSA-PSS wrong message rejected by library" \
    "$RSA_TOOL" verify-pss "$WORK/rsa_key.pem" "$WORK/msg3.bin" "$WORK/rsa_sig_neg.bin"

check_fail "RSA-PSS wrong message rejected by openssl" \
    openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
        -verify "$WORK/rsa_pub.pem" -signature "$WORK/rsa_sig_neg.bin" "$WORK/msg3.bin"

# =========================================================================
printf "\n=== Test suite: RSA PKCS#1 v1.5 ===\n"
# =========================================================================

for i in 1 2 3 4; do
    msg="$WORK/msg${i}.bin"
    tag="rsa-pkcs1/msg${i}"

    # OpenSSL signs PKCS#1 v1.5 -> library verifies
    openssl dgst -sha256 -sign "$WORK/rsa_key.pem" -out "$WORK/rsa_pkcs1_ossl.bin" "$msg"
    check "$tag: openssl PKCS1v15 signs, library verifies" \
        "$RSA_TOOL" verify-pkcs1 "$WORK/rsa_key.pem" "$msg" "$WORK/rsa_pkcs1_ossl.bin"

    # Library signs PKCS#1 v1.5 -> OpenSSL verifies
    "$RSA_TOOL" sign "$WORK/rsa_key.pem" "$msg" "$WORK/rsa_pkcs1_lib.bin" >/dev/null
    check "$tag: library PKCS1v15 signs, openssl verifies" \
        openssl dgst -sha256 -verify "$WORK/rsa_pub.pem" -signature "$WORK/rsa_pkcs1_lib.bin" "$msg"

    # Library signs -> library verifies
    check "$tag: library PKCS1v15 signs, library verifies" \
        "$RSA_TOOL" verify-pkcs1 "$WORK/rsa_key.pem" "$msg" "$WORK/rsa_pkcs1_lib.bin"
done

# =========================================================================
printf "\n=== Test suite: RSA PKCS#1 v1.5 negative cases ===\n"
# =========================================================================

"$RSA_TOOL" sign "$WORK/rsa_key.pem" "$WORK/msg1.bin" "$WORK/rsa_pkcs1_neg.bin" >/dev/null
check_fail "RSA PKCS1v15 wrong message rejected by library" \
    "$RSA_TOOL" verify-pkcs1 "$WORK/rsa_key.pem" "$WORK/msg3.bin" "$WORK/rsa_pkcs1_neg.bin"

check_fail "RSA PKCS1v15 wrong message rejected by openssl" \
    openssl dgst -sha256 -verify "$WORK/rsa_pub.pem" -signature "$WORK/rsa_pkcs1_neg.bin" "$WORK/msg3.bin"

# =========================================================================
printf "\n=== Test suite: X.509 certificate chain verification ===\n"
# =========================================================================

# --- RSA chain: root -> intermediate -> leaf (depth 2) ---

openssl genrsa -out "$WORK/chain_root_key.pem" 2048 2>/dev/null
openssl req -x509 -new -key "$WORK/chain_root_key.pem" -out "$WORK/chain_root.pem" \
    -days 365 -subj "/CN=Chain Root CA/O=Test" \
    -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null

openssl genrsa -out "$WORK/chain_int_key.pem" 2048 2>/dev/null
openssl req -new -key "$WORK/chain_int_key.pem" -out "$WORK/chain_int.csr" \
    -subj "/CN=Chain Intermediate/O=Test" 2>/dev/null
openssl x509 -req -in "$WORK/chain_int.csr" -CA "$WORK/chain_root.pem" \
    -CAkey "$WORK/chain_root_key.pem" -CAcreateserial \
    -out "$WORK/chain_int.pem" -days 365 \
    -extfile <(printf "basicConstraints=critical,CA:TRUE") 2>/dev/null

openssl genrsa -out "$WORK/chain_leaf_key.pem" 2048 2>/dev/null
openssl req -new -key "$WORK/chain_leaf_key.pem" -out "$WORK/chain_leaf.csr" \
    -subj "/CN=leaf.chain.test/O=Test" 2>/dev/null
openssl x509 -req -in "$WORK/chain_leaf.csr" -CA "$WORK/chain_int.pem" \
    -CAkey "$WORK/chain_int_key.pem" -CAcreateserial \
    -out "$WORK/chain_leaf.pem" -days 365 2>/dev/null

# Verify: OpenSSL verifies the chain
check "RSA depth-2 chain: openssl verifies" \
    openssl verify -CAfile "$WORK/chain_root.pem" -untrusted "$WORK/chain_int.pem" "$WORK/chain_leaf.pem"

# Verify: library verifies the chain (leaf, intermediate, root)
check "RSA depth-2 chain: library verifies" \
    "$X509_TOOL" verify-chain "$WORK/chain_root.pem" "$WORK/chain_leaf.pem" "$WORK/chain_int.pem" "$WORK/chain_root.pem"

# Verify: library rejects chain with wrong root
openssl genrsa -out "$WORK/wrong_root_key.pem" 2048 2>/dev/null
openssl req -x509 -new -key "$WORK/wrong_root_key.pem" -out "$WORK/wrong_root.pem" \
    -days 365 -subj "/CN=Wrong Root/O=Other" 2>/dev/null

check_fail "RSA depth-2 chain: wrong root rejected by library" \
    "$X509_TOOL" verify-chain "$WORK/wrong_root.pem" "$WORK/chain_leaf.pem" "$WORK/chain_int.pem" "$WORK/chain_root.pem"

# --- RSA chain: depth 1 (root directly signs leaf) ---

openssl genrsa -out "$WORK/d1_leaf_key.pem" 2048 2>/dev/null
openssl req -new -key "$WORK/d1_leaf_key.pem" -out "$WORK/d1_leaf.csr" \
    -subj "/CN=direct.leaf.test/O=Test" 2>/dev/null
openssl x509 -req -in "$WORK/d1_leaf.csr" -CA "$WORK/chain_root.pem" \
    -CAkey "$WORK/chain_root_key.pem" -CAcreateserial \
    -out "$WORK/d1_leaf.pem" -days 365 2>/dev/null

check "RSA depth-1 chain: library verifies" \
    "$X509_TOOL" verify-chain "$WORK/chain_root.pem" "$WORK/d1_leaf.pem" "$WORK/chain_root.pem"

# --- EC chain: P-256 root -> P-256 leaf (depth 1) ---

openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ec_root_key.pem" 2>/dev/null
openssl req -x509 -new -key "$WORK/ec_root_key.pem" -out "$WORK/ec_root.pem" \
    -days 365 -subj "/CN=EC Root CA/O=Test" \
    -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null

openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ec_leaf_key.pem" 2>/dev/null
openssl req -new -key "$WORK/ec_leaf_key.pem" -out "$WORK/ec_leaf.csr" \
    -subj "/CN=ec.leaf.test/O=Test" 2>/dev/null
openssl x509 -req -in "$WORK/ec_leaf.csr" -CA "$WORK/ec_root.pem" \
    -CAkey "$WORK/ec_root_key.pem" -CAcreateserial \
    -out "$WORK/ec_leaf.pem" -days 365 2>/dev/null

check "EC P-256 depth-1 chain: openssl verifies" \
    openssl verify -CAfile "$WORK/ec_root.pem" "$WORK/ec_leaf.pem"

check "EC P-256 depth-1 chain: library verifies" \
    "$X509_TOOL" verify-chain "$WORK/ec_root.pem" "$WORK/ec_leaf.pem" "$WORK/ec_root.pem"

# --- Deep chain: root -> int1 -> int2 -> int3 -> leaf (depth 4) ---

prev_cert="$WORK/chain_root.pem"
prev_key="$WORK/chain_root_key.pem"

for depth in 1 2 3; do
    openssl genrsa -out "$WORK/deep_int${depth}_key.pem" 2048 2>/dev/null
    openssl req -new -key "$WORK/deep_int${depth}_key.pem" -out "$WORK/deep_int${depth}.csr" \
        -subj "/CN=Deep Intermediate ${depth}/O=Test" 2>/dev/null
    openssl x509 -req -in "$WORK/deep_int${depth}.csr" \
        -CA "$prev_cert" -CAkey "$prev_key" -CAcreateserial \
        -out "$WORK/deep_int${depth}.pem" -days 365 \
        -extfile <(printf "basicConstraints=critical,CA:TRUE") 2>/dev/null
    prev_cert="$WORK/deep_int${depth}.pem"
    prev_key="$WORK/deep_int${depth}_key.pem"
done

openssl genrsa -out "$WORK/deep_leaf_key.pem" 2048 2>/dev/null
openssl req -new -key "$WORK/deep_leaf_key.pem" -out "$WORK/deep_leaf.csr" \
    -subj "/CN=deep.leaf.test/O=Test" 2>/dev/null
openssl x509 -req -in "$WORK/deep_leaf.csr" \
    -CA "$prev_cert" -CAkey "$prev_key" -CAcreateserial \
    -out "$WORK/deep_leaf.pem" -days 365 2>/dev/null

# Build the full chain file for OpenSSL verify
cat "$WORK/deep_int1.pem" "$WORK/deep_int2.pem" "$WORK/deep_int3.pem" > "$WORK/deep_chain.pem"

check "RSA depth-4 chain: openssl verifies" \
    openssl verify -CAfile "$WORK/chain_root.pem" -untrusted "$WORK/deep_chain.pem" "$WORK/deep_leaf.pem"

check "RSA depth-4 chain: library verifies" \
    "$X509_TOOL" verify-chain "$WORK/chain_root.pem" \
        "$WORK/deep_leaf.pem" "$WORK/deep_int3.pem" "$WORK/deep_int2.pem" "$WORK/deep_int1.pem" "$WORK/chain_root.pem"

# --- Negative: missing intermediate ---

check_fail "RSA depth-4 chain: missing intermediate rejected by library" \
    "$X509_TOOL" verify-chain "$WORK/chain_root.pem" \
        "$WORK/deep_leaf.pem" "$WORK/deep_int3.pem" "$WORK/chain_root.pem"

# =========================================================================
printf "\n=== Results ===\n"
# =========================================================================

total=$((pass + fail))
printf "%d / %d passed\n" "$pass" "$total"
if [ "$fail" -ne 0 ]; then
    printf "FAILED\n"
    exit 1
fi
printf "ALL PASSED\n"
