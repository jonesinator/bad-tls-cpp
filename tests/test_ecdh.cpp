#include <crypto/ecdh.hpp>
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

// Number and curve types for secp256k1
using k256_curve = secp256k1<uint512>;
using k256_fe = field_element<k256_curve>;
using k256_point = point<k256_curve>;

// The real OpenSSL-generated P-256 key from the other tests
constexpr std::string_view test_pem =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEILqCeQe9YS7mdX3IseutWyDcygJWrKtkpQul8wWxsKNMoAoGCCqGSM49\n"
    "AwEHoUQDQgAE2wIVduUCSe5a9JoCg7cE5lmkK1GAlNnYpqTz5ZB9339rsLkmHZIi\n"
    "jMWwbEFkrrjsCG4+H2avHOsSky5iNHfRvA==\n"
    "-----END EC PRIVATE KEY-----\n";

// --- HKDF tests ---

void test_hkdf_rfc5869_case1() {
    // RFC 5869 Appendix A, Test Case 1 (SHA-256)
    // IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
    // salt = 0x000102030405060708090a0b0c (13 bytes)
    // info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
    // L    = 42

    std::array<uint8_t, 22> ikm{};
    for (auto& b : ikm) b = 0x0b;

    std::array<uint8_t, 13> salt{};
    for (uint8_t i = 0; i < 13; ++i) salt[i] = i;

    std::array<uint8_t, 10> info{};
    for (uint8_t i = 0; i < 10; ++i) info[i] = 0xf0 + i;

    auto okm = hkdf<sha256_state, 42>(salt, ikm, info);

    // Expected PRK = 0x077709362c2e32df0ddc3f0dc47bba63
    //               90b6c73bb50f9c3122ec844ad7c2b3e5
    // Expected OKM = 3cb25f25faacd57a90434f64d0362f2a
    //               2d2d0a90cf1a5a4c5db02d56ecc4c5bf
    //               34007208d5b887185865
    assert(okm[0]  == 0x3c && okm[1]  == 0xb2 && okm[2]  == 0x5f && okm[3]  == 0x25);
    assert(okm[4]  == 0xfa && okm[5]  == 0xac && okm[6]  == 0xd5 && okm[7]  == 0x7a);
    assert(okm[40] == 0x58 && okm[41] == 0x65);
}

void test_hkdf_rfc5869_case2() {
    // RFC 5869 Appendix A, Test Case 2 (SHA-256) — longer inputs
    // IKM  = 0x000102...4f (80 bytes)
    // salt = 0x606162...af (80 bytes)
    // info = 0xb0b1b2...ff (80 bytes)
    // L    = 82

    std::array<uint8_t, 80> ikm{};
    for (uint8_t i = 0; i < 80; ++i) ikm[i] = i;

    std::array<uint8_t, 80> salt{};
    for (uint8_t i = 0; i < 80; ++i) salt[i] = 0x60 + i;

    std::array<uint8_t, 80> info{};
    for (uint8_t i = 0; i < 80; ++i) info[i] = 0xb0 + i;

    auto okm = hkdf<sha256_state, 82>(salt, ikm, info);

    // Expected OKM = b11e398dc80327a1c8e7f78c596a4934
    //               4f012eda2d4efad8a050cc4c19afa97c
    //               59045a99cac7827271cb41c65e590e09
    //               da3275600c2f09b8367793a9aca3db71
    //               cc30c58179ec3e87c14c01d5c1f3434f
    //               1d87
    assert(okm[0]  == 0xb1 && okm[1]  == 0x1e && okm[2]  == 0x39 && okm[3]  == 0x8d);
    assert(okm[80] == 0x1d && okm[81] == 0x87);
}

void test_hkdf_rfc5869_case3() {
    // RFC 5869 Appendix A, Test Case 3 (SHA-256) — zero-length salt and info
    // IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
    // salt = "" (empty)
    // info = "" (empty)
    // L    = 42

    std::array<uint8_t, 22> ikm{};
    for (auto& b : ikm) b = 0x0b;

    std::span<const uint8_t> empty_salt{};
    std::span<const uint8_t> empty_info{};

    auto okm = hkdf<sha256_state, 42>(empty_salt, ikm, empty_info);

    // Expected OKM = 8da4e775a563c18f715f802a063c5a31
    //               b8a11f5c5ee1879ec3454e5f3c738d2d
    //               9d201395faa4b61a96c8
    assert(okm[0]  == 0x8d && okm[1]  == 0xa4 && okm[2]  == 0xe7 && okm[3]  == 0x75);
    assert(okm[40] == 0x96 && okm[41] == 0xc8);
}

// --- ECDH keypair tests ---

void test_keypair_from_private_matches_pem() {
    auto key = asn1::pem::decode_to<Mod, Mod.find_type("ECPrivateKey")>(test_pem);

    auto d = uint512::from_bytes(key.get<"privateKey">().bytes);

    auto& pub_bytes = key.get<"publicKey">()->bytes;
    auto pub_span = std::span<const uint8_t>(pub_bytes);
    auto x = uint512::from_bytes(pub_span.subspan(1, 32));
    auto y = uint512::from_bytes(pub_span.subspan(33, 32));
    p256_point Q{p256_fe{x}, p256_fe{y}};

    auto kp = ecdh_keypair_from_private<p256_curve>(d);
    assert(kp.public_key == Q);
    assert(kp.private_key == d);
}

// --- ECDH validation tests ---

void test_validate_public_key_valid() {
    // Generator point should be valid
    p256_point G{p256_fe{p256_curve::gx()}, p256_fe{p256_curve::gy()}};
    assert(ecdh_validate_public_key(G));

    // Derived public key should be valid
    auto d = *uint512::from_string(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        string_base::hexadecimal);
    auto kp = ecdh_keypair_from_private<p256_curve>(d);
    assert(ecdh_validate_public_key(kp.public_key));
}

void test_validate_public_key_infinity() {
    p256_point inf{};
    assert(!ecdh_validate_public_key(inf));
}

void test_validate_public_key_off_curve() {
    // A point that's not on the curve
    p256_point bad{p256_fe{uint512(1U)}, p256_fe{uint512(2U)}};
    assert(!ecdh_validate_public_key(bad));
}

// --- ECDH shared secret tests ---

void test_roundtrip_p256() {
    // Two known private keys
    auto d_a = *uint512::from_string(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        string_base::hexadecimal);
    auto d_b = *uint512::from_string(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8",
        string_base::hexadecimal);

    auto kp_a = ecdh_keypair_from_private<p256_curve>(d_a);
    auto kp_b = ecdh_keypair_from_private<p256_curve>(d_b);

    // Both sides should derive the same shared secret
    auto secret_a = ecdh_raw_shared_secret<p256_curve>(d_a, kp_b.public_key);
    auto secret_b = ecdh_raw_shared_secret<p256_curve>(d_b, kp_a.public_key);

    assert(secret_a.has_value());
    assert(secret_b.has_value());
    assert(*secret_a == *secret_b);
    assert(*secret_a != uint512(0U));
}

void test_roundtrip_secp256k1() {
    auto d_a = *uint512::from_string(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        string_base::hexadecimal);
    auto d_b = *uint512::from_string(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8",
        string_base::hexadecimal);

    auto kp_a = ecdh_keypair_from_private<k256_curve>(d_a);
    auto kp_b = ecdh_keypair_from_private<k256_curve>(d_b);

    auto secret_a = ecdh_raw_shared_secret<k256_curve>(d_a, kp_b.public_key);
    auto secret_b = ecdh_raw_shared_secret<k256_curve>(d_b, kp_a.public_key);

    assert(secret_a.has_value());
    assert(secret_b.has_value());
    assert(*secret_a == *secret_b);
    assert(*secret_a != uint512(0U));
}

void test_raw_shared_secret_infinity_returns_nullopt() {
    // Passing point at infinity should return nullopt
    p256_point inf{};
    auto d = *uint512::from_string(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        string_base::hexadecimal);
    auto result = ecdh_raw_shared_secret<p256_curve>(d, inf);
    assert(!result.has_value());
}

// --- Full ECDHE + HKDF derivation ---

void test_ecdh_derive_with_hkdf() {
    auto d_a = *uint512::from_string(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        string_base::hexadecimal);
    auto d_b = *uint512::from_string(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8",
        string_base::hexadecimal);

    auto kp_a = ecdh_keypair_from_private<p256_curve>(d_a);
    auto kp_b = ecdh_keypair_from_private<p256_curve>(d_b);

    const uint8_t info_bytes[] = {'E', 'C', 'D', 'H', ' ', 't', 'e', 's', 't'};
    std::span<const uint8_t> info{info_bytes};

    auto key_a = ecdh_derive<p256_curve, sha256_state, 32>(d_a, kp_b.public_key, {}, info);
    auto key_b = ecdh_derive<p256_curve, sha256_state, 32>(d_b, kp_a.public_key, {}, info);

    assert(key_a.has_value());
    assert(key_b.has_value());
    assert(*key_a == *key_b);

    // Derived key should not be all zeros
    bool all_zero = true;
    for (auto b : *key_a) if (b != 0) { all_zero = false; break; }
    assert(!all_zero);
}

int main() {
    // HKDF
    test_hkdf_rfc5869_case1();
    test_hkdf_rfc5869_case2();
    test_hkdf_rfc5869_case3();

    // ECDH keypair
    test_keypair_from_private_matches_pem();

    // Validation
    test_validate_public_key_valid();
    test_validate_public_key_infinity();
    test_validate_public_key_off_curve();

    // Shared secret
    test_roundtrip_p256();
    test_roundtrip_secp256k1();
    test_raw_shared_secret_infinity_returns_nullopt();

    // Full derivation
    test_ecdh_derive_with_hkdf();

    return 0;
}
