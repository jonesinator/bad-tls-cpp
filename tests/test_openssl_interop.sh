#!/usr/bin/env bash
#
# ECDSA P-256/SHA-256 and P-384/SHA-384 interop tests between this library and OpenSSL.
#
# Proves bidirectional compatibility:
#   1. OpenSSL signs, this library verifies
#   2. This library signs, OpenSSL verifies
#
# Also tests with multiple messages and a freshly generated key.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
TOOL="$BUILD_DIR/ecdsa_tool"
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

printf "Building ecdsa_tool...\n"
cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug >/dev/null 2>&1
cmake --build "$BUILD_DIR" --target ecdsa_tool >/dev/null 2>&1
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
printf "\n=== Results ===\n"
# =========================================================================

total=$((pass + fail))
printf "%d / %d passed\n" "$pass" "$total"
if [ "$fail" -ne 0 ]; then
    printf "FAILED\n"
    exit 1
fi
printf "ALL PASSED\n"
