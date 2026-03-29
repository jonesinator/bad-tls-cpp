#include <crypto/ecdsa.hpp>
#include <crypto/sha2.hpp>
#include <asn1/pem.hpp>
#include <asn1/parser.hpp>
#include <asn1/der/codegen.hpp>
#include <cassert>
#include <cstdint>
#include <span>
#include <string_view>

using namespace asn1;
using namespace asn1::der;

// Parse ASN.1 definitions at compile time
constexpr char ecc_asn1[] = {
    #embed "definitions/ecprivatekey.asn1"
};
constexpr auto Mod = parse_module(std::string_view{ecc_asn1, sizeof(ecc_asn1)});

// Number and curve types for P-256
using uint512 = number<std::uint32_t, 16>;
using p256_curve = p256<uint512>;
using p256_fe = field_element<p256_curve>;
using p256_point = point<p256_curve>;

// Number and curve types for P-384
using uint768 = number<std::uint32_t, 24>;
using p384_curve = p384<uint768>;
using p384_fe = field_element<p384_curve>;
using p384_point = point<p384_curve>;

// The real OpenSSL-generated P-256 key from the other tests
constexpr std::string_view test_pem =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEILqCeQe9YS7mdX3IseutWyDcygJWrKtkpQul8wWxsKNMoAoGCCqGSM49\n"
    "AwEHoUQDQgAE2wIVduUCSe5a9JoCg7cE5lmkK1GAlNnYpqTz5ZB9339rsLkmHZIi\n"
    "jMWwbEFkrrjsCG4+H2avHOsSky5iNHfRvA==\n"
    "-----END EC PRIVATE KEY-----\n";

// --- SHA-256 tests ---

void test_sha256_empty() {
    std::array<uint8_t, 0> empty{};
    auto hash = sha256(std::span<const uint8_t>(empty.data(), 0));
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert(hash[0] == 0xE3 && hash[1] == 0xB0 && hash[2] == 0xC4 && hash[3] == 0x42);
    assert(hash[28] == 0x78 && hash[29] == 0x52 && hash[30] == 0xB8 && hash[31] == 0x55);
}

void test_sha256_abc() {
    const uint8_t msg[] = {'a', 'b', 'c'};
    auto hash = sha256(std::span<const uint8_t>(msg, 3));
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    assert(hash[0] == 0xBA && hash[1] == 0x78 && hash[2] == 0x16 && hash[3] == 0xBF);
    assert(hash[28] == 0xF2 && hash[29] == 0x00 && hash[30] == 0x15 && hash[31] == 0xAD);
}

void test_sha256_two_blocks() {
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (56 bytes, forces 2 blocks)
    const char* msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    auto hash = sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg), 56));
    // SHA-256 = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
    assert(hash[0] == 0x24 && hash[1] == 0x8D && hash[2] == 0x6A && hash[3] == 0x61);
    assert(hash[28] == 0x19 && hash[29] == 0xDB && hash[30] == 0x06 && hash[31] == 0xC1);
}

void test_sha256_test_message() {
    const char* msg = "test message";
    auto hash = sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg), 12));
    // SHA-256("test message") = 3f0a377ba0a4a460ecb616f6507ce0d8cfa3e704025d4fda3ed0c5ca05468728
    assert(hash[0] == 0x3F && hash[1] == 0x0A && hash[2] == 0x37 && hash[3] == 0x7B);
    assert(hash[28] == 0x05 && hash[29] == 0x46 && hash[30] == 0x87 && hash[31] == 0x28);
}

// --- HMAC-SHA-256 tests ---

void test_hmac_sha256_rfc4231_case2() {
    // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
    const char* key = "Jefe";
    const char* data = "what do ya want for nothing?";
    auto mac = hmac<sha256_state>(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(key), 4),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(data), 28));
    // Expected: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    assert(mac[0] == 0x5B && mac[1] == 0xDC && mac[2] == 0xC1 && mac[3] == 0x46);
    assert(mac[28] == 0x64 && mac[29] == 0xEC && mac[30] == 0x38 && mac[31] == 0x43);
}

// --- Helper to extract private key and public key point from PEM ---

struct test_key {
    uint512 d;
    p256_point Q;
};

test_key load_test_key() {
    auto key = asn1::pem::decode_to<Mod, Mod.find_type("ECPrivateKey")>(test_pem);

    auto d = uint512::from_bytes(key.get<"privateKey">().bytes);

    auto& pub_bytes = key.get<"publicKey">()->bytes;
    auto pub_span = std::span<const uint8_t>(pub_bytes);
    auto x = uint512::from_bytes(pub_span.subspan(1, 32));
    auto y = uint512::from_bytes(pub_span.subspan(33, 32));
    p256_point Q{p256_fe{x}, p256_fe{y}};

    return {d, Q};
}

// --- ECDSA sign/verify tests ---

void test_sign_verify_roundtrip() {
    auto [d, Q] = load_test_key();

    const char* msg = "test message";
    auto hash = sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg), 12));

    auto sig = ecdsa_sign<p256_curve, sha256_state>(d, hash);

    // r and s should be non-zero
    assert(sig.r != uint512(0U));
    assert(sig.s != uint512(0U));

    // Low-S check: s <= n/2
    uint512 half_n = p256_curve::n() / uint512(2U);
    assert(sig.s <= half_n);

    // Should verify
    assert((ecdsa_verify<p256_curve, sha256_state>(Q, hash, sig)));
}

void test_verify_rejects_wrong_message() {
    auto [d, Q] = load_test_key();

    const char* msg = "test message";
    auto hash = sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg), 12));

    auto sig = ecdsa_sign<p256_curve, sha256_state>(d, hash);

    // Different message should fail
    const char* wrong = "wrong message";
    auto wrong_hash = sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(wrong), 13));
    assert((!ecdsa_verify<p256_curve, sha256_state>(Q, wrong_hash, sig)));
}

void test_verify_rejects_corrupted_signature() {
    auto [d, Q] = load_test_key();

    const char* msg = "test message";
    auto hash = sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg), 12));

    auto sig = ecdsa_sign<p256_curve, sha256_state>(d, hash);

    // Corrupt r
    ecdsa_signature<p256_curve> bad_sig = {sig.r + uint512(1U), sig.s};
    assert((!ecdsa_verify<p256_curve, sha256_state>(Q, hash, bad_sig)));

    // Corrupt s
    bad_sig = {sig.r, sig.s + uint512(1U)};
    assert((!ecdsa_verify<p256_curve, sha256_state>(Q, hash, bad_sig)));
}

void test_verify_rejects_zero_r_s() {
    auto [d, Q] = load_test_key();

    const char* msg = "test message";
    auto hash = sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg), 12));

    ecdsa_signature<p256_curve> zero_r = {uint512(0U), uint512(1U)};
    assert((!ecdsa_verify<p256_curve, sha256_state>(Q, hash, zero_r)));

    ecdsa_signature<p256_curve> zero_s = {uint512(1U), uint512(0U)};
    assert((!ecdsa_verify<p256_curve, sha256_state>(Q, hash, zero_s)));
}

void test_sign_is_deterministic() {
    auto [d, Q] = load_test_key();

    const char* msg = "test message";
    auto hash = sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg), 12));

    auto sig1 = ecdsa_sign<p256_curve, sha256_state>(d, hash);
    auto sig2 = ecdsa_sign<p256_curve, sha256_state>(d, hash);
    assert(sig1.r == sig2.r);
    assert(sig1.s == sig2.s);
}

void test_verify_openssl_signature() {
    auto [d, Q] = load_test_key();

    // Signature generated by OpenSSL: echo -n "test message" | openssl dgst -sha256 -sign key.pem
    // ECDSA-Sig-Value DER encoding:
    const uint8_t openssl_sig_der[] = {
        0x30, 0x44, 0x02, 0x20, 0x35, 0x8f, 0x75, 0x28, 0x70, 0xcd, 0x70, 0x98,
        0x72, 0x45, 0x69, 0x3b, 0x0e, 0xbe, 0x6f, 0x5b, 0x51, 0x27, 0xba, 0x61,
        0xbd, 0xfb, 0x16, 0xed, 0x2b, 0xc7, 0x74, 0xac, 0x9e, 0x1c, 0x32, 0x75,
        0x02, 0x20, 0x27, 0x49, 0x2d, 0x0a, 0x50, 0x89, 0xb1, 0x4d, 0x06, 0x63,
        0x5a, 0x93, 0xea, 0x1b, 0x50, 0x1c, 0xae, 0x8b, 0xaa, 0x99, 0x10, 0xba,
        0xd7, 0x4f, 0xc2, 0xb1, 0x7d, 0x59, 0x4d, 0xa8, 0x9b, 0x4a
    };

    // Decode with existing ECDSA-Sig-Value codegen
    std::vector<uint8_t> der_vec(std::begin(openssl_sig_der), std::end(openssl_sig_der));
    Reader r{der_vec};
    auto der_sig = decode<Mod, Mod.find_type("ECDSA-Sig-Value")>(r);

    // Convert DER Integer to uint512
    auto r_val = uint512::from_bytes(der_sig.get<"r">().bytes);
    auto s_val = uint512::from_bytes(der_sig.get<"s">().bytes);

    ecdsa_signature<p256_curve> sig{r_val, s_val};

    // Verify against SHA-256("test message")
    const char* msg = "test message";
    auto hash = sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg), 12));

    assert((ecdsa_verify<p256_curve, sha256_state>(Q, hash, sig)));
}

void test_sign_message_convenience() {
    auto [d, Q] = load_test_key();

    const char* msg = "hello world";
    auto msg_span = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg), 11);

    auto sig = ecdsa_sign_message<p256_curve, sha256_state>(d, msg_span);
    assert((ecdsa_verify_message<p256_curve, sha256_state>(Q, msg_span, sig)));
}

void test_der_roundtrip() {
    auto [d, Q] = load_test_key();

    const char* msg = "test message";
    auto hash = sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg), 12));

    auto sig = ecdsa_sign<p256_curve, sha256_state>(d, hash);

    // Convert number_type r,s to DER Integer (big-endian, minimal, unsigned -> sign-padded)
    auto num_to_integer = [](const uint512& n) -> Integer {
        auto bytes = n.to_bytes(std::endian::big);
        // Strip leading zeros
        size_t start = 0;
        while (start < bytes.size() - 1 && bytes[start] == 0) ++start;
        Integer result;
        if (bytes[start] & 0x80) result.bytes.push_back(0x00); // sign bit padding
        result.bytes.insert(result.bytes.end(), bytes.begin() + start, bytes.end());
        return result;
    };

    // Encode signature to DER
    Type<Mod, "ECDSA-Sig-Value"> der_sig;
    der_sig.get<"r">() = num_to_integer(sig.r);
    der_sig.get<"s">() = num_to_integer(sig.s);

    Writer w;
    encode<Mod, Mod.find_type("ECDSA-Sig-Value")>(w, der_sig);
    auto der_bytes = std::move(w).finish();

    // Decode back
    Reader r{der_bytes};
    auto decoded = decode<Mod, Mod.find_type("ECDSA-Sig-Value")>(r);

    auto r_decoded = uint512::from_bytes(decoded.get<"r">().bytes);
    auto s_decoded = uint512::from_bytes(decoded.get<"s">().bytes);

    assert(r_decoded == sig.r);
    assert(s_decoded == sig.s);

    // Verify the decoded signature
    ecdsa_signature<p256_curve> sig2{r_decoded, s_decoded};
    assert((ecdsa_verify<p256_curve, sha256_state>(Q, hash, sig2)));
}

// --- SHA-384 tests ---

void test_sha384_abc() {
    const uint8_t msg[] = {'a', 'b', 'c'};
    sha384_state s;
    s.init();
    s.update(std::span<const uint8_t>(msg, 3));
    auto hash = s.finalize();
    // SHA-384("abc") = cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed
    //                   8086072ba1e7cc2358baeca134c825a7
    assert(hash[0] == 0xCB && hash[1] == 0x00 && hash[2] == 0x75 && hash[3] == 0x3F);
    assert(hash[44] == 0x34 && hash[45] == 0xC8 && hash[46] == 0x25 && hash[47] == 0xA7);
}

// --- HMAC-SHA-384 tests ---

void test_hmac_sha384_rfc4231_case2() {
    // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
    const char* key = "Jefe";
    const char* data = "what do ya want for nothing?";
    auto mac = hmac<sha384_state>(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(key), 4),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(data), 28));
    // Expected: af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e
    //           8e2240ca5e69e2c78b3239ecfab21649
    assert(mac[0] == 0xAF && mac[1] == 0x45 && mac[2] == 0xD2 && mac[3] == 0xE3);
    assert(mac[44] == 0xFA && mac[45] == 0xB2 && mac[46] == 0x16 && mac[47] == 0x49);
}

// --- P-384 ECDSA tests ---

void test_p384_sign_verify_roundtrip() {
    // RFC 6979 A.2.6 private key
    auto d = *uint768::from_string(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8"
        "96D5724E4C70A825F872C9EA60D2EDF5",
        string_base::hexadecimal);

    // Compute public key Q = d * G
    p384_point G{p384_fe{p384_curve::gx()}, p384_fe{p384_curve::gy()}};
    p384_point Q = G.scalar_mul(d);
    assert(Q.on_curve());

    // Hash a test message with SHA-384
    const char* msg = "test message";
    sha384_state hs;
    hs.init();
    hs.update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg), 12));
    auto hash = hs.finalize();

    // Sign and verify
    auto sig = ecdsa_sign<p384_curve, sha384_state>(d, hash);
    assert(sig.r != uint768(0U));
    assert(sig.s != uint768(0U));

    // Low-S check
    uint768 half_n = p384_curve::n() / uint768(2U);
    assert(sig.s <= half_n);

    assert((ecdsa_verify<p384_curve, sha384_state>(Q, hash, sig)));

    // Deterministic: signing again should produce the same signature
    auto sig2 = ecdsa_sign<p384_curve, sha384_state>(d, hash);
    assert(sig.r == sig2.r);
    assert(sig.s == sig2.s);

    // Wrong hash should fail
    const char* wrong = "wrong message";
    sha384_state hs2;
    hs2.init();
    hs2.update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(wrong), 13));
    auto wrong_hash = hs2.finalize();
    assert((!ecdsa_verify<p384_curve, sha384_state>(Q, wrong_hash, sig)));
}

int main() {
    // SHA-256
    test_sha256_empty();
    test_sha256_abc();
    test_sha256_two_blocks();
    test_sha256_test_message();

    // HMAC-SHA-256
    test_hmac_sha256_rfc4231_case2();

    // ECDSA
    test_sign_verify_roundtrip();
    test_verify_rejects_wrong_message();
    test_verify_rejects_corrupted_signature();
    test_verify_rejects_zero_r_s();
    test_sign_is_deterministic();
    test_verify_openssl_signature();
    test_sign_message_convenience();
    test_der_roundtrip();

    // SHA-384
    test_sha384_abc();

    // HMAC-SHA-384
    test_hmac_sha384_rfc4231_case2();

    // ECDSA P-384/SHA-384
    test_p384_sign_verify_roundtrip();

    return 0;
}
